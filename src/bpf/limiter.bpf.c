// SPDX-License-Identifier: GPL-2.0
/*
 * 文件用途
 * - 该 eBPF 程序挂载在 cgroup egress 路径 (cgroup_skb/egress)，
 *   对每个发往网络栈的 skb 进行令牌桶限速。
 *
 * 实现原理
 * - 以 cgroup_id 作为键，使用两个 HASH map 分别存储配置与状态：
 *   config(rate_bps/bucket_size) 与 state(tokens/last_update_ns)。
 * - 每次有 skb 到达时，按与上次更新时间的纳秒差补充令牌，封顶到 bucket_size，
 *   然后判断 tokens 是否足够支付本次包长 (skb->len)，足够则扣减并放行，否则丢弃。
 * - eBPF 返回值：1 放行 (allow)，0 丢弃 (deny)。
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "../include/limiter.h"

/* 从skb获取cgroup_id的辅助函数 */
static __always_inline __u64 get_cgroup_id_from_skb(struct __sk_buff *skb)
{
	struct sock *sk;
	struct cgroup *cgrp;
	
	/* 获取socket指针 */
	sk = (struct sock *)BPF_CORE_READ(skb, sk);
	if (!sk)
		return 0;
	
	/* 获取cgroup指针 */
	cgrp = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
	if (!cgrp)
		return 0;
	
	/* 获取cgroup ID */
	return BPF_CORE_READ(cgrp, kn, id);
}

/* 配置与状态分离的双 map 设计（BTF-defined maps） */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct rate_limit_config);
} rate_limit_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct rate_limit_state);
} rate_limit_state_map SEC(".maps");


/*
应用程序 (Userspace)
         |
         v (系统调用: sendto, write, etc.)
Socket 缓冲区 (Kernel)
         |
         v
--- 【cgroup_skb/egress HOOK 点】--- <-- 我们在这里做决策
         |
         v
TCP/UDP 协议处理 -> IP 路由 -> 邻居表 -> 网卡队列驱动 -> 网卡
         ^
         |
     TCP 重传计时器
	
*/

SEC("cgroup_skb/egress")
int limit_egress(struct __sk_buff *skb)
{
	/* 当前时间 (ns) 与该包长度 */
	__u64 now = bpf_ktime_get_ns();
	__u64 packet_len = skb->len;
	/* 以 cgroup_id 作为限速维度 */
	__u64 cgid = get_cgroup_id_from_skb(skb);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)(pid_tgid >> 32);  // 修正：获取线程组ID (tgid)
	u32 tid = (u32)(pid_tgid);        // 获取线程ID (pid)
	struct rate_limit_config *conf;
	struct rate_limit_state *st;

    bpf_printk("cgid=%llu tgid=%u tid=%u len=%u\n", cgid, pid, tid, skb->len);
	conf = bpf_map_lookup_elem(&rate_limit_config_map, &cgid);
	st = bpf_map_lookup_elem(&rate_limit_state_map, &cgid);
	if (!conf) {
		/* 未配置限速则放行 */
		bpf_printk("no conf found,pass\n");
		return 1;
	}
	if (!st) {
		/* 首次状态初始化：放行当前包 */
		struct rate_limit_state init = {};
		init.tokens = conf->bucket_size; /* 或 0，视业务取舍 */
		init.last_update_ns = now;
		bpf_map_update_elem(&rate_limit_state_map, &cgid, &init, 0);
		bpf_printk("no state found,pass\n");
		return 1;
	}

	/* 进入临界区：保护 tokens/last_update_ns 更新 */
	bpf_spin_lock(&st->lock);

	__u64 time_delta_ns = now - st->last_update_ns;
	__u64 tokens_to_add = (time_delta_ns * conf->rate_bps) / 1000000000ULL;

	/* 将新令牌加入桶中，并且不能超过桶的最大容量（来自 config） */
	st->tokens += tokens_to_add;
	if (st->tokens > conf->bucket_size) {
		st->tokens = conf->bucket_size;
	}
	st->last_update_ns = now;

	/* 判断是否可放行并扣减 */
	if (st->tokens >= packet_len) {
		st->tokens -= packet_len;//消耗令牌

		bpf_spin_unlock(&st->lock);
		bpf_printk("cgid=%llu  tokens=%llu len=%u \n", cgid,st->tokens, skb->len );
		return 1;
	}
	bpf_spin_unlock(&st->lock);
	return 0;
}

char _license[] SEC("license") = "GPL";
