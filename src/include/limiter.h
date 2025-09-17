#ifndef LIMITER_H
#define LIMITER_H

/* 通用别名，避免依赖标准/内核头 */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
/*
令牌桶原理：
桶 (Bucket)：一个容器，用于存放“令牌”。
令牌 (Token)：permission slip。每个令牌代表允许发送1字节数据的权限（有时也可以是1个数据包）。
速率 (Rate)：令牌以固定的速率被加入到桶中。例如，速率 rate_bps = 1,048,576 表示每秒会向桶中加入 1,048,576 个令牌（即 1 MB/s）。
桶容量 (Bucket Size)：桶的最大容量。这决定了允许的最大突发流量。例如，bucket_size = 2,097,152（2 MB）。速率和桶大小一致会怎么样？

工作流程：
数据包到达：当一个数据包到达时，系统会检查桶中是否有大于等于该数据包大小的令牌。
足够令牌：如果有，则从桶中扣除相应数量的令牌，数据包被立即发送。这允许突发传输。
不足令牌：如果没有，数据包会被延迟或丢弃，直到有足够的令牌被加入桶中。这起到了限速的作用。
*/

struct rate_limit_config {
	__u64 rate_bps;      // 限速字节/秒
	__u64 bucket_size;   // 令牌桶大小
};

/* BPF 自旋锁类型 */
/* 用户态：由 libbpf.h 提供定义 */
/* BPF 端：由 vmlinux.h 提供定义 */

struct rate_limit_state {
	struct bpf_spin_lock lock; // 并发保护（BPF端）
	__u64 tokens;              // 当前桶内令牌数
	__u64 last_update_ns;      // 上次更新令牌的时间戳
};

struct rate_limit_full_info {
	struct rate_limit_config config;
	struct rate_limit_state state;
};

#endif /* LIMITER_H */
