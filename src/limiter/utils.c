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
#include <dirent.h>

#ifndef RUNTIME_DIR
#define RUNTIME_DIR "/run/speed_limiter"
#endif

int path_join(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *component;
    char temp[dest_size]; // 临时缓冲区
    size_t pos = 0;
    int is_first_component = 1;

    if (dest_size == 0) return -1;

    // 先保存原始内容到临时缓冲区
    strcpy(temp, dest);
    pos = strlen(temp);

    va_start(args, dest_size);

    while ((component = va_arg(args, const char *)) != NULL) {
        if (component[0] == '\0') continue; // 跳过空组件

        size_t comp_len = strlen(component);
        const char *comp_start = component;

        // 对于第一个组件，如果是绝对路径，保留开头的斜杠
        if (is_first_component) {
            if (comp_len > 0 && comp_start[0] == '/') {
                if (pos + 1 >= dest_size) {
                    va_end(args);
                    return -1;
                }
                temp[pos++] = '/';
                temp[pos] = '\0';
                comp_start++; // 跳过这个斜杠，避免后面重复处理
                comp_len--;
            }
            is_first_component = 0;
        } else {
            // 非第一个组件：移除开头多余的斜杠
            while (comp_len > 0 && comp_start[0] == '/') {
                comp_start++;
                comp_len--;
            }
        }

        // 移除所有组件结尾多余的斜杠
        while (comp_len > 0 && comp_start[comp_len - 1] == '/') {
            comp_len--;
        }

        if (comp_len == 0) continue; // 跳过只剩斜杠的组件

        // 是否需要添加分隔斜杠（当前不是以斜杠结尾且组件不为空）
        if (pos > 0 && temp[pos - 1] != '/') {
            if (pos + 1 >= dest_size) {
                va_end(args);
                return -1;
            }
            temp[pos++] = '/';
            temp[pos] = '\0';
        }

        // 检查是否有足够空间
        if (pos + comp_len >= dest_size) {
            va_end(args);
            return -1;
        }

        // 复制组件
        memcpy(temp + pos, comp_start, comp_len);
        pos += comp_len;
        temp[pos] = '\0';
    }

    va_end(args);

    // 将结果复制回目标缓冲区
    strcpy(dest, temp);
    return 0;
}

int safe_path_join(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *component;
    size_t pos = 0;
    int is_first_component = 1;
    
    if (dest_size == 0) return -1;
    dest[0] = '\0';
    
    va_start(args, dest_size);
    
    while ((component = va_arg(args, const char *)) != NULL) {
        if (component[0] == '\0') continue; // 跳过空组件
        
        size_t comp_len = strlen(component);
        const char *comp_start = component;
        
        // 对于第一个组件，如果是绝对路径，保留开头的斜杠
        if (is_first_component) {
            if (comp_len > 0 && comp_start[0] == '/') {
                if (pos + 1 >= dest_size) return -1;
                dest[pos++] = '/';
                dest[pos] = '\0';
                comp_start++; // 跳过这个斜杠，避免后面重复处理
                comp_len--;
            }
            is_first_component = 0;
        } else {
            // 非第一个组件：移除开头多余的斜杠
            while (comp_len > 0 && comp_start[0] == '/') {
                comp_start++;
                comp_len--;
            }
        }
        
        // 移除所有组件结尾多余的斜杠
        while (comp_len > 0 && comp_start[comp_len - 1] == '/') {
            comp_len--;
        }
        
        if (comp_len == 0) continue; // 跳过只剩斜杠的组件
        
        // 是否需要添加分隔斜杠（当前不是以斜杠结尾且组件不为空）
        if (pos > 0 && dest[pos - 1] != '/') {
            if (pos + 1 >= dest_size) return -1;
            dest[pos++] = '/';
            dest[pos] = '\0';
        }
        
        // 检查是否有足够空间
        if (pos + comp_len >= dest_size) return -1;
        
        // 复制组件
        memcpy(dest + pos, comp_start, comp_len);
        pos += comp_len;
        dest[pos] = '\0';
    }
    
    va_end(args);
    return 0;
}

int safe_path_append(char *dest, size_t dest_size, ...) {
    if (!dest || dest_size == 0) return -1;

    char temp[dest_size];
    strcpy(temp, dest);
	size_t current_len = strlen(dest);

    va_list args;
    va_start(args, dest_size);

    const char *arg;
    while ((arg = va_arg(args, const char *)) != NULL) {
        // 添加斜杠（如果需要）
        if (current_len > 0 && temp[current_len - 1] != '/') {
            if (current_len + 1 >= dest_size) {
                va_end(args);
                return -1;
            }
            temp[current_len++] = '/';
            temp[current_len] = '\0';
        }

        // 跳过参数开头的斜杠
        const char *clean_arg = arg;
        while (*clean_arg == '/') clean_arg++;

        // 计算要添加的字符串长度
        size_t arg_len = strlen(clean_arg);
        if (arg_len == 0) continue;

        // 检查剩余空间
        if (current_len + arg_len >= dest_size) {
            va_end(args);
            return -1;
        }

        // 直接复制（比strcat更快）
        memcpy(temp + current_len, clean_arg, arg_len);
        current_len += arg_len;
        temp[current_len] = '\0';
    }

    va_end(args);

    // 移除尾部多余斜杠
    while (current_len > 1 && temp[current_len - 1] == '/') {
        temp[--current_len] = '\0';
    }

    strcpy(dest, temp);
    return 0;
}


int write_last_rule(const char *cgroup_path, unsigned long long cgid)
{
	if (ensure_dir(RUNTIME_DIR, 0755) != 0) return -1;
	char path[PATH_MAX];
	SAFE_PATH_JOIN(path, RUNTIME_DIR, "last_rule");
	FILE *f = fopen(path, "w");
	if (!f) return -1;
	fprintf(f, "%s\n%llu\n", cgroup_path, (unsigned long long)cgid);
	fclose(f);
	return 0;
}

int read_last_rule(char *cgroup_path_out, size_t path_bufsz, unsigned long long *cgid_out)
{
	char path[PATH_MAX];
	SAFE_PATH_JOIN(path, RUNTIME_DIR, "last_rule");
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

int read_proc_cgroup_v2_path(pid_t pid, char *buf, size_t bufsz)
{
	char proc_cg[PATH_MAX];
	char pid_str[32];
	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	SAFE_PATH_JOIN(proc_cg, "/proc", pid_str, "cgroup");
	FILE *f = fopen(proc_cg, "r");
	if (!f) return -1;
	char line[PATH_MAX];
	int ok = -1;
	while (fgets(line, sizeof(line), f)) {
		/* cgroup v2 格式：0::<path> */
		if (strncmp(line, "0::", 3) == 0) {
			char *p = strchr(line, ':');
			if (!p) break;
			p = strchr(p + 1, ':');
			if (!p) break;
			p++;
			char *nl = strchr(p, '\n'); if (nl) *nl = '\0';
			/* 若为空表示根 "/" */
			if (*p == '\0') {
				if (buf && bufsz > 0) { buf[0] = '/'; buf[1] = '\0'; }
				ok = 0; break;
			}
			if (buf && bufsz > 0) {
				strncpy(buf, p, bufsz - 1);
				buf[bufsz - 1] = '\0';
			}
			ok = 0; break;
		}
	}
	fclose(f);
	return ok;
}

int read_proc_starttime(pid_t pid, unsigned long long *starttime_out)
{
	if (!starttime_out) return -1;
	char proc_stat[PATH_MAX];
	char pid_str[32];
	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	SAFE_PATH_JOIN(proc_stat, "/proc", pid_str, "stat");
	FILE *f = fopen(proc_stat, "r");
	if (!f) return -1;
	/* /proc/<pid>/stat 字段多，取第22个字段 */
	/* 简单读取整行后用 sscanf 跳过前面字段较繁琐，这里逐词读取 */
	unsigned long long starttime = 0ULL;
	char buf[8192];
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
	fclose(f);
	/* 进程名可能含空格且包在括号内，定位到右括号后再分词 */
	char *rp = strrchr(buf, ')');
	if (!rp) return -1;
	char *p = rp + 2; /* 跳过空格，定位到 state 字段 */
	/* 从 state 起计数，starttime 是从头数第22个，这里粗略实现：
	   1:pid 2:comm 3:state 4:ppid ... 22:starttime */
	int field = 3; /* state */
	while (*p && field < 22) {
		if (*p == ' ') { while (*p == ' ') p++; field++; }
		else p++;
	}
	if (field != 22) return -1;
	if (sscanf(p, "%llu", &starttime) != 1) return -1;
	*starttime_out = starttime;
	return 0;
}

static int ensure_runtime_subdir(const char *sub)
{
	if (ensure_dir(RUNTIME_DIR, 0755) != 0) return -1;
	char d[PATH_MAX];
	SAFE_PATH_JOIN(d, RUNTIME_DIR, sub);
	return ensure_dir(d, 0755);
}

/* 构建进程原始 cgroup 记录文件路径 */
static int build_pid_cgroup_path(pid_t pid, char *path, size_t path_size) {
	char pid_str[32];
	if (snprintf(pid_str, sizeof(pid_str), "%d", pid) >= (int)sizeof(pid_str)) {
		return -1;
	}
	return safe_path_join(path, path_size, RUNTIME_DIR, "orig_cgrp", pid_str, NULL);
}

int save_pid_original_cgroup(pid_t pid, const char *cgroup_path, unsigned long long starttime)
{
	if (ensure_runtime_subdir("orig_cgrp") != 0) {
		fprintf(stderr, "无法创建运行时子目录 orig_cgrp\n");
		return -1;
	}

	char path[PATH_MAX];
	if (build_pid_cgroup_path(pid, path, sizeof(path)) != 0) {
		fprintf(stderr, "无法构建进程 %d 的记录文件路径\n", pid);
		return -1;
	}

	/* 若已存在，忽略重复操作，直接返回成功 */
	if (access(path, F_OK) == 0) {
		return 0;
	}

	FILE *f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "无法创建进程 %d 的原始 cgroup 记录: %s (%s)\n",
		        pid, path, strerror(errno));
		return -1;
	}

	if (fprintf(f, "%s\n%llu\n", cgroup_path ? cgroup_path : "/",
	            (unsigned long long)starttime) < 0) {
		fprintf(stderr, "无法写入进程 %d 的原始 cgroup 记录\n", pid);
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}

int load_pid_original_cgroup(pid_t pid, char *path_out, size_t path_bufsz, unsigned long long *starttime_out)
{
	char path[PATH_MAX];
	if (build_pid_cgroup_path(pid, path, sizeof(path)) != 0) return -1;

	FILE *f = fopen(path, "r");
	if (!f) return -1;

	char line[PATH_MAX];
	unsigned long long st = 0ULL;

	// 读取 cgroup 路径
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}

	// 移除换行符
	char *nl = strchr(line, '\n');
	if (nl) *nl = '\0';

	// 复制到输出缓冲区
	if (path_out && path_bufsz > 0) {
		strncpy(path_out, line, path_bufsz - 1);
		path_out[path_bufsz - 1] = '\0';
	}

	// 读取 starttime
	if (fgets(line, sizeof(line), f)) {
		st = strtoull(line, NULL, 10);
	}

	if (starttime_out) *starttime_out = st;
	fclose(f);
	return 0;
}

int delete_pid_original_cgroup(pid_t pid)
{
	char path[PATH_MAX];
	if (build_pid_cgroup_path(pid, path, sizeof(path)) != 0) return -1;

	int ret = unlink(path);
	if (ret != 0 && errno != ENOENT) {
		fprintf(stderr, "无法删除进程 %d 的原始 cgroup 记录: %s (%s)\n",
		        pid, path, strerror(errno));
	}
	return ret;
}

/* 将进程移动到指定 cgroup：写入 cgroup.procs 文件，返回0成功 */
int move_pid_to_cgroup(pid_t pid, const char *cgroup_path)
{
	char procs_path[PATH_MAX];
	SAFE_PATH_JOIN(procs_path, cgroup_path, "cgroup.procs");

	FILE *f = fopen(procs_path, "w");
	if (!f) {
		fprintf(stderr, "无法打开 cgroup.procs 文件: %s (%s)\n", procs_path, strerror(errno));
		return -1;
	}

	if (fprintf(f, "%d", pid) < 0) {
		fprintf(stderr, "无法写入进程 %d 到 cgroup: %s (%s)\n", pid, cgroup_path, strerror(errno));
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}
