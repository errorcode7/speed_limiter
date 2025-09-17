// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct prog_event {
    __u32 type;        // 0=session start, 1=prog item
    __u32 pid_tgid_low;
    __u32 atype;       // cgroup_bpf_attach_type
    __u32 prog_id;     // bpf_prog_aux->id
    __u64 ctx;         // skb pointer
    __u64 cgroup_id;   // cgroup ID
    char name[16];     // program name
};

static volatile sig_atomic_t exiting = 0;

static void on_sigint(int sig) { (void)sig; exiting = 1; }

static int on_event(void *ctx, void *data, size_t len)
{
    const struct prog_event *e = data;
    const char *direction;

    // 根据 atype 确定方向
    switch (e->atype) {
        case 0: direction = "ingress"; break;  // BPF_CGROUP_INET_INGRESS
        case 1: direction = "egress"; break;   // BPF_CGROUP_INET_EGRESS
        case 2: direction = "sock_create"; break; // BPF_CGROUP_INET_SOCK_CREATE
        case 3: direction = "sock_ops"; break;    // BPF_CGROUP_SOCK_OPS
        case 4: direction = "device"; break;      // BPF_CGROUP_DEVICE
        case 5: direction = "bind4"; break;       // BPF_CGROUP_INET4_BIND
        case 6: direction = "bind6"; break;       // BPF_CGROUP_INET6_BIND
        case 7: direction = "connect4"; break;    // BPF_CGROUP_INET4_CONNECT
        case 8: direction = "connect6"; break;    // BPF_CGROUP_INET6_CONNECT
        case 9: direction = "sendmsg4"; break;    // BPF_CGROUP_UDP4_SENDMSG
        case 10: direction = "sendmsg6"; break;   // BPF_CGROUP_UDP6_SENDMSG
        case 11: direction = "recvmsg4"; break;   // BPF_CGROUP_UDP4_RECVMSG
        case 12: direction = "recvmsg6"; break;   // BPF_CGROUP_UDP6_RECVMSG
        default: direction = "unknown"; break;
    }

    if (e->type == 0) {
        printf("SESSION: direction=%s cgroup_id=%llu ctx=0x%lx atype=%u\n",
               direction, e->cgroup_id, (unsigned long)e->ctx, e->atype);
    } else if (e->type == 1) {
        printf("  PROG: id=%u name=%.*s\n", e->prog_id, (int)sizeof(e->name), e->name);
    }
    fflush(stdout);
    return 0;
}

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int map_fd, err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* 通过可执行文件所在目录定位 bin/ 下的 BPF 对象 */
    char exe_path[PATH_MAX];
    char exe_dir[PATH_MAX];
    char bpf_obj_path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n < 0 || (size_t)n >= sizeof(exe_path)) {
        fprintf(stderr, "resolve /proc/self/exe failed\n");
        return 1;
    }
    exe_path[n] = '\0';
    strncpy(exe_dir, exe_path, sizeof(exe_dir));

    exe_dir[sizeof(exe_dir) - 1] = '\0';
    char *dir = dirname(exe_dir);
    if (!dir) {
        fprintf(stderr, "dirname failed\n");
        return 1;
    }
    int l = snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/%s", dir, "trace_cgroup_progs.bpf.o");
    if (l < 0 || (size_t)l >= sizeof(bpf_obj_path)) {
        fprintf(stderr, "bpf obj path too long\n");
        return 1;
    }

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) { fprintf(stderr, "open bpf obj failed\n"); return 1; }
    if ((err = bpf_object__load(obj))) { fprintf(stderr, "load failed: %d\n", err); return 1; }

    prog = bpf_object__find_program_by_name(obj, "on_enter_cgrp_skb");
    if (!prog) { fprintf(stderr, "find program failed\n"); return 1; }
    link = bpf_program__attach(prog);
    if (!link) { fprintf(stderr, "attach failed\n"); return 1; }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) { fprintf(stderr, "find map failed\n"); return 1; }
    rb = ring_buffer__new(map_fd, on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "create ringbuf failed\n"); return 1; }

    signal(SIGINT, on_sigint);
    printf("list-only running... Ctrl-C to exit\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 200);
        if (err < 0) { fprintf(stderr, "poll failed: %d\n", err); break; }
    }

    ring_buffer__free(rb);
    if (link) bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}


