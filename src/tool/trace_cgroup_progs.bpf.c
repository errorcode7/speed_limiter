// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct prog_event {
    __u32 type;        // 0=session start, 1=prog item
    __u32 pid_tgid_low;
    __u32 atype;       // cgroup_bpf_attach_type
    __u32 prog_id;     // bpf_prog_aux->id
    __u64 ctx;         // skb pointer (context)
    __u64 cgroup_id;   // cgroup ID
    char name[16];     // program name
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void emit_session_start(__u64 ctx_ptr, __u32 atype, __u64 cgroup_id)
{
    struct prog_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    e->type = 0;
    e->pid_tgid_low = (__u32)bpf_get_current_pid_tgid();
    e->atype = atype;
    e->prog_id = 0;
    e->ctx = ctx_ptr;
    e->cgroup_id = cgroup_id;
    __builtin_memset(e->name, 0, sizeof(e->name));
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_prog_item(__u64 ctx_ptr, __u32 atype,
                                           __u32 prog_id, const struct bpf_prog_aux *aux, __u64 cgroup_id)
{
    struct prog_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    e->type = 1;
    e->pid_tgid_low = (__u32)bpf_get_current_pid_tgid();//当前进程的pid
    e->atype = atype;
    e->prog_id = prog_id;
    e->ctx = ctx_ptr;
    e->cgroup_id = cgroup_id;
    __builtin_memset(e->name, 0, sizeof(e->name));
    if (aux)
        BPF_CORE_READ_INTO(&e->name, aux, name);
    bpf_ringbuf_submit(e, 0);
}

// helper：安全获取 sock_cgroup 指针，兼容 sock_cgroup_ptr(&sk->sk_cgrp_data)
static __always_inline const struct cgroup *get_cgrp_from_sk(const struct sock *sk)
{
    // sock_cgroup_data 的低位包含位标志，需要清掩；编码在不同版本有差异。
    // 这里用 BTF 读取 sk->sk_cgrp_data.cgroup，CO-RE 自动解析布局。
    struct sock_cgroup_data data = {};
    if (!sk)
        return 0;
    BPF_CORE_READ_INTO(&data, sk, sk_cgrp_data);
    return (const struct cgroup *)data.cgroup;
}
/*
想知道数据包经过哪些cgroup的bpf程序
__cgroup_bpf_run_filter_skb负责执行具体的程序
基本原理是进程遍历cgroup，获取cgroup挂载的bpf程序
期望获取cgroup挂载的bpf程序

atype，可知道是入栈还是出栈


*/
SEC("fentry/__cgroup_bpf_run_filter_skb")
int BPF_PROG(on_enter_cgrp_skb, struct sock *sk, struct sk_buff *skb, int atype)
{
    const struct cgroup *cgrp;
    const struct bpf_prog_array *array;
    const struct bpf_prog_array_item *item;
    const struct bpf_prog *prog;
    const struct bpf_prog_aux *aux;
    __u64 ctx_ptr = (unsigned long)skb;
    __u32 uatype = (__u32)atype;
    __u64 cgroup_id = 0;

    // 从 sk 反推出 cgroup
    cgrp = get_cgrp_from_sk(sk);
    if (!cgrp)
        return 0;

    // 获取 cgroup ID
    cgroup_id = BPF_CORE_READ(cgrp, kn, id);

    // 先发一条会话开始事件
    emit_session_start(ctx_ptr, uatype, cgroup_id);

    // 直接读取 cgrp->bpf.effective[atype]（RCU 指针）
    array = BPF_CORE_READ(cgrp, bpf.effective[uatype]);
    if (!array)
        return 0;

    // 遍历 items，直到遇到 NULL prog
    // 注意：bpf_prog_array_item 没有显式长度，以 NULL 终止
    // 这里保守遍历上限，防御性避免越界
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        // 读取第 i 个 prog 指针
        prog = BPF_CORE_READ(array, items[i].prog);
        if (!prog)
            break;
        aux = BPF_CORE_READ(prog, aux);
        if (!aux)
            continue;
        __u32 id = BPF_CORE_READ(aux, id);
        emit_prog_item(ctx_ptr, uatype, id, aux, cgroup_id);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

