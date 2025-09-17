#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <linux/limits.h>

#ifndef RUNTIME_DIR
#define RUNTIME_DIR "/run/speed_limiter"
#endif

int write_last_rule(const char *cgroup_path, unsigned long long cgid)
{
	if (ensure_dir(RUNTIME_DIR, 0755) != 0) return -1;
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/last_rule", RUNTIME_DIR);
	FILE *f = fopen(path, "w");
	if (!f) return -1;
	fprintf(f, "%s\n%llu\n", cgroup_path, (unsigned long long)cgid);
	fclose(f);
	return 0;
}

int read_last_rule(char *cgroup_path_out, size_t path_bufsz, unsigned long long *cgid_out)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/last_rule", RUNTIME_DIR);
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[PATH_MAX];
	if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
	/* 去掉换行 */
	char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
	if (cgroup_path_out && path_bufsz > 0) {
		strncpy(cgroup_path_out, line, path_bufsz-1);
		cgroup_path_out[path_bufsz-1] = '\0';
	}
	if (fgets(line, sizeof(line), f)) {
		*cgid_out = strtoull(line, NULL, 10);
	}
	fclose(f);
	return 0;
}

/* 单位解析：支持 k/K=1024, m/M=1024*1024 */
unsigned long long parse_size(const char *str)
{
	char *endptr;
	unsigned long long val = strtoull(str, &endptr, 10);
	
	if (endptr == str) {
		fprintf(stderr, "无效数值: %s\n", str);
		return 0;
	}
	
	if (*endptr == '\0') {
		return val; /* 无单位，直接返回 */
	}
	
	if (strcasecmp(endptr, "k") == 0) {
		return val * 1024;
	} else if (strcasecmp(endptr, "m") == 0) {
		return val * 1024 * 1024;
	} else {
		fprintf(stderr, "不支持的单位: %s (支持 k/K, m/M)\n", endptr);
		return 0;
	}
}

/* 确保目录存在，不存在则创建 */
int ensure_dir(const char *path, mode_t mode)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) return 0;
		fprintf(stderr, "路径存在但不是目录: %s\n", path);
		return -1;
	}
	if (mkdir(path, mode) == 0) {
		fprintf(stderr, "创建目录: %s\n", path);
		return 0;
	}
	if (errno == EEXIST) return 0;
	fprintf(stderr, "创建目录失败: %s: %s\n", path, strerror(errno));
	return -1;
}

/* 打开 cgroup 文件描述符 */
int open_cgroup_fd(const char *path)
{
	int fd = open(path, O_RDONLY);
	return fd;
}
