#ifndef UTILS_H
#define UTILS_H

#include <sys/stat.h>
#include <stddef.h>

/* 单位解析：支持 k/K=1024, m/M=1024*1024 */
unsigned long long parse_size(const char *str);

/* 确保目录存在，不存在则创建 */
int ensure_dir(const char *path, mode_t mode);

/* 打开 cgroup 文件描述符 */
int open_cgroup_fd(const char *path);

/* 运行时状态目录 */
#define RUNTIME_DIR "/run/speed_limiter"

/* 记录/读取最近一次创建的规则 */
int write_last_rule(const char *cgroup_path, unsigned long long cgid);
int read_last_rule(char *cgroup_path_out, size_t path_bufsz, unsigned long long *cgid_out);

#endif /* UTILS_H */
