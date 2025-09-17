#ifndef CGROUP_H
#define CGROUP_H

#include <sys/types.h>
#include <stddef.h>

/* 获取 cgroup ID */
unsigned long long get_cgroup_id(const char *cgroup_path);

/* 生成规则目录名：bucket_<bytes>_rate_<bps> */
int make_rule_dirname(char *buf, size_t bufsize, unsigned long long bucket, unsigned long long rate);

/* 检查 cgroup 是否为空 */
int is_cgroup_empty(const char *cgroup_path);

/* 将进程移入指定 cgroup */
int do_move_pid(pid_t pid, const char *cgroup_path);

/* 创建 cgroup 目录 */
int do_cg_create(const char *cgroup_path);

/* 删除 cgroup 目录 */
int do_cg_delete(const char *cgroup_path);

#endif /* CGROUP_H */
