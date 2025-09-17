# Speed Limiter

基于 eBPF cgroup egress 钩子实现的令牌桶网络限速工具。

## 功能特性

- **令牌桶限速**：基于 eBPF 在 cgroup egress 钩子上实现字节级限速
- **按 cgroup 分组**：支持对不同进程组设置不同的限速规则
- **CO-RE 支持**：安装时自动生成 `vmlinux.h` 并编译 BPF 对象，提升跨内核可移植性
- **便捷管理**：自动创建和管理 cgroup，支持进程迁移和规则管理
- **实时监控**：提供调试工具追踪 BPF 程序执行和 cgroup 状态

## 工作原理

### 令牌桶算法
- **桶 (Bucket)**：存放令牌的容器
- **令牌 (Token)**：每个令牌代表允许发送 1 字节数据的权限
- **速率 (Rate)**：令牌以固定速率加入桶中，如 1MB/s = 1,048,576 tokens/s
- **桶容量 (Bucket Size)**：桶的最大容量，决定允许的最大突发流量

### 内核数据包处理流程

当应用程序调用 `send()` 或 `write()` 发送数据时，数据包在内核中的处理流程如下：

```
应用程序 send()/write()
    ↓
内核系统调用 sys_sendto/sys_write
    ↓
Socket 层: sock_sendmsg() → inet_sendmsg()
    ↓
传输层: udp_sendmsg() / tcp_sendmsg()
    ↓
网络层: ip_send_skb() → ip_local_out() → __ip_local_out()
    ↓
【关键钩子点】ip_finish_output() ← 我们的 eBPF 程序在这里拦截
    ↓
BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb)
    ↓
__cgroup_bpf_run_filter_skb(sk, skb, CGROUP_INET_EGRESS)
    ↓
limit_egress() ← 我们的 eBPF 程序执行令牌桶检查
    ↓
ip_finish_output2() → 邻居子系统 → 网卡驱动 → 物理网卡
```

### eBPF 程序执行机制

#### 1. 程序触发条件
eBPF 程序只在以下条件同时满足时才会执行：
- `cgroup_bpf_enabled(CGROUP_INET_EGRESS)` 为 true
- socket 存在且有效
- socket 的 cgroup 及其祖先节点中有有效的 BPF 程序

#### 2. cgroup 关联机制
```c
// 内核检查 socket 的 cgroup 是否有有效的 BPF 程序
static inline bool cgroup_bpf_sock_enabled(struct sock *sk, enum cgroup_bpf_attach_type type)
{
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    struct bpf_prog_array *array;
    
    array = rcu_access_pointer(cgrp->bpf.effective[type]);
    return array != &bpf_empty_prog_array.hdr;
}
```

#### 3. 程序执行流程
```c
// 内核执行 BPF 程序的入口
int __cgroup_bpf_run_filter_skb(struct sock *sk, struct sk_buff *skb, 
                                enum cgroup_bpf_attach_type atype)
{
    // 获取 socket 关联的 cgroup
    struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
    
    // 设置 skb 的 socket 指针
    skb->sk = sk;
    
    // 执行 cgroup 上的有效 BPF 程序数组
    ret = bpf_prog_run_array_cg(&cgrp->bpf, atype, skb, __bpf_prog_run_save_cb, 0, &flags);
    
    return ret;
}
```

### eBPF 程序实现细节

#### 1. 程序结构
```c
SEC("cgroup_skb/egress")
int limit_egress(struct __sk_buff *skb)
{
    // 获取当前时间戳和数据包长度
    __u64 now = bpf_ktime_get_ns();
    __u64 packet_len = skb->len;
    
    // 获取当前进程的 cgroup ID
    __u64 cgid = bpf_get_current_cgroup_id();
    
    // 查找该 cgroup 的限速配置
    struct rate_limit_config *conf = bpf_map_lookup_elem(&rate_limit_config_map, &cgid);
    struct rate_limit_state *st = bpf_map_lookup_elem(&rate_limit_state_map, &cgid);
    
    // 令牌桶算法处理...
}
```

#### 2. 双 Map 设计
- **`rate_limit_config_map`**：存储限速配置
  - Key: `cgroup_id` (64位)
  - Value: `struct rate_limit_config` (rate_bps, bucket_size)
- **`rate_limit_state_map`**：存储运行时状态
  - Key: `cgroup_id` (64位)
  - Value: `struct rate_limit_state` (tokens, last_update_ns, lock)


### 重要限制和注意事项

#### 1. Socket 创建时机
- **关键限制**：socket 的 cgroup 关联在创建时确定，后续进程迁移不会更新已存在 socket 的 cgroup 关联
- **影响**：将进程移动到新的 cgroup 后，该进程的现有 socket 仍使用原 cgroup 的限速规则
- **解决方案**：新创建的子进程会继承新的 cgroup，其 socket 将使用新的限速规则

#### 2. cgroup 层次结构
```
根 cgroup (A)
├── 子 cgroup (B)
│   ├── 孙 cgroup (D)
│   └── 孙 cgroup (E)
└── 子 cgroup (C)
    └── 孙 cgroup (F)
```

- **有效程序计算**：子 cgroup 会继承父 cgroup 的所有 BPF 程序
- **程序执行**：当数据包通过时，会执行该 cgroup 及其所有祖先 cgroup 上的 BPF 程序
- **推荐做法**：在根 cgroup 附加 BPF 程序，在程序内部根据 `cgroup_id` 区分不同的限速策略

#### 3. 性能考虑
- **零拷贝**：eBPF 程序直接在内核网络栈中执行，无需数据拷贝
- **高效查找**：使用 HASH map 实现 O(1) 时间复杂度的配置查找
- **原子操作**：使用 BPF 自旋锁保护并发访问的状态更新

## 系统要求

### 运行时依赖
- Linux 内核 >= 5.8（支持 cgroup_skb/egress）
- libbpf >= 1.4.0
- cgroup v2 支持

### 构建依赖
- clang/llvm
- libbpf-dev
- libelf-dev
- zlib1g-dev
- bpftool（用于生成 vmlinux.h）

## 安装

### 从源码构建
```bash
# 安装依赖
sudo apt install clang llvm-20 libbpf-dev libelf-dev zlib1g-dev bpftool

# 配置 llvm-strip
sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-20 100

# 构建
make
```

### 从 Debian 包安装
```bash
# 构建 Debian 包
dpkg-buildpackage -us -uc -tc -b

# 安装
sudo dpkg -i speed-limiter_0.1.0_amd64.deb
```

安装时会自动：
- 生成 `/usr/share/speed_limiter/src/vmlinux.h`
- 编译 `/usr/lib/speed_limiter/limiter.bpf.o`

## 使用方法

### 基本命令

```bash
# 设置进程限速
sudo limiter set --pid <pid> --rate <rate> [--bucket <bucket>]

# 迁移进程到指定规则
sudo limiter move --pid <pid> [--cgroup-path <path> | --cgid <id> | --last]

# 全局重载程序
sudo limiter reload [-o /path/of/limiter.bpf.o ] [--cgroup-path <path>]

# 取消进程限速
sudo limiter unset --pid <pid>

# 列出所有规则
sudo limiter list [--pid | --bpf]

# 清理所有规则
sudo limiter purge

# 显示帮助
limiter --help
```

### 参数说明

- `--pid/-p`：目标进程 ID
- `--rate/-r`：限速值，支持单位：k/K=1024, m/M=1024²（如：1m, 512k）
- `--bucket/-b`：令牌桶大小，默认等于 rate
- `--bpf-obj/-o`：BPF 对象路径（默认 /usr/lib/speed_limiter/limiter.bpf.o）
- `--cgroup-path`：目标 cgroup v2 路径
- `--cgid`：目标 cgroup ID
- `--last`：使用最近设置的规则

### 使用示例

```bash
# 1. 为进程 1234 设置 1MB/s 限速
sudo limiter set --pid 1234 --rate 1m

# 2. 为进程 5678 设置 512KB/s 限速，桶大小 1MB
sudo limiter set --pid 5678 --rate 512k --bucket 1m

# 3. 查看所有限速规则
sudo limiter list

# 4. 将进程迁移到最近设置的规则
sudo limiter move --pid 9999 --last

# 5. 取消进程 1234 的限速
sudo limiter unset --pid 1234

# 6. 清理所有限速规则
sudo limiter purge
```

## 调试工具

### 追踪 cgroup BPF 程序执行
```bash
# 构建调试工具
make -C src/tool

# 运行追踪程序
sudo ./bin/debug_cgroup_pbf
```

输出示例：
```
SESSION: direction=out cgroup_id=12345 ctx=0xffff8f2ff73b4400 atype=1
  PROG: id=1497 name=limit_egress
```

### 输出日志追踪分析

查看输出：
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# 或
sudo bpftool prog tracelog
```

### 查看 BPF 程序状态
```bash
# 查看所有 BPF 程序
sudo bpftool prog list

# 查看特定程序的详细信息
sudo bpftool prog show id <program_id>

# 查看 cgroup 信息
sudo bpftool cgroup show /sys/fs/cgroup/speed_limiter/

# 查看 map 内容
sudo bpftool map dump pinned /sys/fs/bpf/speed_limiter/rate_limit_config_map
sudo bpftool map dump pinned /sys/fs/bpf/speed_limiter/rate_limit_state_map

# 查看 map 统计信息
sudo bpftool map show pinned /sys/fs/bpf/speed_limiter/rate_limit_config_map
```


### 故障排除指南

#### 1. BPF 程序未执行
检查项目：
- cgroup 是否正确创建
- BPF 程序是否正确附加到 cgroup
- socket 的 cgroup 关联是否正确

```bash
# 检查 cgroup 层次结构
sudo bpftool cgroup tree

# 检查有效程序
sudo bpftool cgroup show /sys/fs/cgroup/speed_limiter/
```

#### 2. 限速不生效
可能原因：
- socket 创建时不在目标 cgroup 中
- 进程迁移后 socket 未更新 cgroup 关联
- map 中缺少对应 cgroup_id 的配置

```bash
# 检查当前进程的 cgroup
cat /proc/self/cgroup

# 检查 map 中的配置
sudo bpftool map dump pinned /sys/fs/bpf/speed_limiter/rate_limit_config_map
```

#### 3. 程序加载失败
```bash
# 检查内核版本和 BPF 支持
uname -r
cat /proc/config.gz | gunzip | grep -i bpf

# 检查 BTF 支持
ls /sys/kernel/btf/vmlinux

# 检查 libbpf 版本
pkg-config --modversion libbpf
```

## 目录结构

```
speed_limiter/
├── src/
│   ├── limiter/          # 主程序源码
│   │   ├── main.c        # 程序入口
│   │   ├── cli.c         # 命令行接口
│   │   ├── managed.c     # cgroup 管理
│   │   ├── bpf.c         # BPF 程序加载
│   │   └── ...
│   ├── bpf/
│   │   └── limiter.bpf.c # eBPF 程序源码
│   ├── include/
│   │   └── limiter.h     # 公共头文件
│   └── tool/             # 调试工具
│       ├── debug_cgroup_pbf.c
│       └── trace_cgroup_progs.bpf.c
├── debian/               # Debian 打包配置
└── Makefile             # 构建配置
```

## 许可证

GPL-2.0

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。
