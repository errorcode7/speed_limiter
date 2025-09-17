#ifndef UTILS_H
#define UTILS_H

#include <sys/stat.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdarg.h>

/* 单位解析：支持 k/K=1024, m/M=1024*1024 */
unsigned long long parse_size(const char *str);

/* 安全路径拼接：自动处理斜杠，返回0成功 */
int safe_path_join(char *dest, size_t dest_size, ...);

/* 便捷宏：自动计算 dest 大小 */
#define SAFE_PATH_JOIN(dest, ...) \
    safe_path_join(dest, sizeof(dest), __VA_ARGS__, NULL)

/* 安全路径追加：将新组件追加到现有路径 */
int safe_path_append(char *dest, size_t dest_size, ...);

// 支持a="b"+a
#define SAFE_PATH_APPEND(dest, ...) \
    safe_path_append(dest, sizeof(dest), __VA_ARGS__, NULL)

/* 确保目录存在，不存在则创建 */
int ensure_dir(const char *path, mode_t mode);

/* 打开 cgroup 文件描述符 */
int open_cgroup_fd(const char *path);

/* 运行时状态目录 */
#define RUNTIME_DIR "/run/speed_limiter"

/* 记录/读取最近一次创建的规则 */
int write_last_rule(const char *cgroup_path, unsigned long long cgid);
int read_last_rule(char *cgroup_path_out, size_t path_bufsz, unsigned long long *cgid_out);

/* 读取进程当前 cgroup v2 路径（形如 /xxx），返回0成功 */
int read_proc_cgroup_v2_path(pid_t pid, char *buf, size_t bufsz);

/* 读取进程 starttime（/proc/<pid>/stat 第22项，单位为时钟ticks），返回0成功 */
int read_proc_starttime(pid_t pid, unsigned long long *starttime_out);

/* 原始 cgroup 记录：保存/加载/删除（保存在 RUNTIME_DIR "/orig_cgrp/<pid>"） */
int save_pid_original_cgroup(pid_t pid, const char *cgroup_path, unsigned long long starttime);
int load_pid_original_cgroup(pid_t pid, char *path_out, size_t path_bufsz, unsigned long long *starttime_out);
int delete_pid_original_cgroup(pid_t pid);

/* 将进程移动到指定 cgroup：写入 cgroup.procs 文件，返回0成功 */
int move_pid_to_cgroup(pid_t pid, const char *cgroup_path);

#endif /* UTILS_H */
