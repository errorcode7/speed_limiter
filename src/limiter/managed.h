#ifndef MANAGED_H
#define MANAGED_H

#include <sys/types.h>
#include "bpf.h"

/* 重载标志定义 */
#define UPDATE_CONFIG_ONLY 1
#define RELOAD_PROGRAM 2

/* 简洁安全的 snprintf 宏：仅适用于栈上/固定大小数组 dest */
#define SAFE_SNPRINTF(dest, fmt, ...) do { \
	int _written = snprintf((dest), sizeof(dest), (fmt), ##__VA_ARGS__); \
	if (_written < 0 || (size_t)_written >= sizeof(dest)) { \
		fprintf(stderr, "Path too long: " fmt "\n", ##__VA_ARGS__); \
		return -1; \
	} \
} while (0)

/* cgroup v2 根（不带尾斜杠） */
#define CGROUPFS_ROOT "/sys/fs/cgroup"
#define MANAGED_ROOT "/sys/fs/cgroup/speed_limiter"

//附加程序到到根，可以管所有进程。
#define ATTACH_POINT "/sys/fs/cgroup"

/* BPF FS 根与项目 pin 目录（不带尾斜杠） */
#define BPFFS_ROOT "/sys/fs/bpf"
#define BPFFS_DIR "/sys/fs/bpf/speed_limiter"

/* 链接与 map 的固定路径（在项目 pin 目录下） */
#define PIN_LINK_PERSISTENT  "/sys/fs/bpf/speed_limiter/link"
#define PIN_MAP_CFG          "/sys/fs/bpf/speed_limiter/rate_limit_config_map"
#define PIN_MAP_STATE        "/sys/fs/bpf/speed_limiter/rate_limit_state_map"

/* 默认的 bpf 对象安装路径 */
#define DEFAULT_BPF_OBJ "/usr/lib/speed_limiter/limiter.bpf.o"



/* 若未由其他头定义运行时目录，则给出默认值（与 utils.h 保持一致） */
#ifndef RUNTIME_DIR
#define RUNTIME_DIR "/run/speed_limiter"
#endif

/* 便捷子命令：set - 设置进程限速 */
int do_set(pid_t pid, const struct LimiterConfig cfg, const struct LoadOptions opts);

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
