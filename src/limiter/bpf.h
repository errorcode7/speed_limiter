#ifndef BPF_H
#define BPF_H

#include <linux/types.h>

/* 附加模式枚举 */
typedef enum {
    ATTACH_MODE_PROG_ATTACH = 0,  /* 使用 bpf_prog_attach，支持 MULTI 但不持久化 */
    ATTACH_MODE_LINK = 1,         /* 使用 bpf_link，支持持久化但不支持 MULTI */
} AttachMode;

/* 载入/附加程序的选项 */
typedef struct LoadOptions {
    const char *bpf_obj_path;   /* BPF 对象文件路径 */
    const char *cgroup_path;    /* 目标 cgroup 路径（可选） */
    unsigned int attach_flags;  /* 传递给 bpf_prog_attach 的 flags，如 BPF_F_ALLOW_MULTI */
    AttachMode attach_mode;     /* 附加模式：prog_attach 或 link */
} LoadOptions;


typedef struct LimiterConfig {
    unsigned long long cgid;    /* 目标 cgroup id，可为 0 表示不写配置 */
    unsigned long long rate_bps;   /* 速率（bytes/s） */
    unsigned long long bucket_size;/* 桶大小（bytes）*/
} LimiterConfig;

/* 加载 eBPF 程序并设置限速规则 */
int do_load(const LimiterConfig *cfg, const LoadOptions *opts, int reload_flag);

/* 卸载 eBPF 程序 */
int do_unload(unsigned long long cgid);

/* 仅卸载附加在指定 cgroup 的名为 "limit_egress" 的程序 */
int detach_limit_egress(const char *cgroup_path);

/* Link 相关函数 */
int bpf_attach_cgroup_with_link(int prog_fd, const char *cgroup_path);
int bpf_detach_link(const char *cgroup_path);
int bpf_is_link_attached(const char *cgroup_path);

/* 清理 pinned link 与 maps */
int bpf_purge_links(void);
int bpf_purge_maps(void);
/* 批量 detach MANAGED_ROOT 及子目录的 limit_egress */
int bpf_detach_limit_egress_all(void);

/* 获取当前的附加模式 */
AttachMode get_current_attach_mode(void);

/* 获取程序的附加模式信息 */
const char* get_prog_attach_mode(__u32 prog_id);

#endif /* BPF_H */
