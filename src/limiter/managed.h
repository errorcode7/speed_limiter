#ifndef MANAGED_H
#define MANAGED_H

#include <sys/types.h>

/* 托管 cgroup 根目录 */
#define MANAGED_CGROUP_ROOT "/sys/fs/cgroup/speed_limiter"

/* 便捷子命令：set - 设置进程限速 */
int do_set(pid_t pid, const char *rate_str, const char *bucket_str, const char *bpf_obj_path);

/* 便捷子命令：unset - 取消进程限速 */
int do_unset(pid_t pid);

/* 便捷子命令：list - 列出所有限速规则 */
int do_list_managed(void);

/* 便捷子命令：purge - 清理所有限速规则 */
int do_purge(void);

/* 便捷子命令：list --pid - 列出cgroup_id和进程ID */
int do_list_cgroup_pids(void);

/* 便捷子命令：list --bpf - 列出cgroup_id、BPF程序名和加载时间 */
int do_list_cgroup_bpf(void);

#endif /* MANAGED_H */
