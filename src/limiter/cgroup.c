#include "cgroup.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>


unsigned long long get_cgroup_id(const char *cgroup_path) {
    int cgroup_fd = open(cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "打开 %s 失败: %s\n", cgroup_path, strerror(errno));
        return 0ULL;
    }

    struct stat st;
    if (fstat(cgroup_fd, &st) != 0) {
        fprintf(stderr, "fstat 失败: %s\n", strerror(errno));
        close(cgroup_fd);
        return 0ULL;
    }
    close(cgroup_fd);
    /* 使用 inode 作为标识（注意：这不是内核 cgroup_id，仅作当前实现的键值）*/
    return (unsigned long long)st.st_ino;
}

/* 生成规则目录名：bucket_<bytes>_rate_<bps> */
int make_rule_dirname(char *buf, size_t bufsize, unsigned long long bucket, unsigned long long rate)
{
	return snprintf(buf, bufsize, "bucket_%llu_rate_%llu", bucket, rate);
}

/* 检查 cgroup 是否为空 */
int is_cgroup_empty(const char *cgroup_path)
{
	char procs_path[PATH_MAX];
	snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
	FILE *f = fopen(procs_path, "readdir");
	/* 简化：通过读取第一行判断是否为空 */
	if (!f) return -1;
	char buf[64];
	int empty = (fgets(buf, sizeof(buf), f) == NULL);
	fclose(f);
	return empty;
}

/* 将进程移入指定 cgroup */
int do_move_pid(pid_t pid, const char *cgroup_path)
{
	if (!cgroup_path || pid <= 0) {
		fprintf(stderr, "--move-pid 需要 --pid 和 --cgroup-path\n");
		return 1;
	}
	char procs_path[PATH_MAX];
	snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
	FILE *f = fopen(procs_path, "w");
	if (!f) {
		fprintf(stderr, "打开 %s 失败: %s\n", procs_path, strerror(errno));
		return 1;
	}
	fprintf(f, "%d", pid);
	fclose(f);
	printf("已将 PID %d 移入 %s\n", pid, cgroup_path);
	return 0;
}

/* 创建 cgroup 目录 */
int do_cg_create(const char *cgroup_path)
{
	if (!cgroup_path) {
		fprintf(stderr, "--cg-create 需要 --cgroup-path\n");
		return 1;
	}
	if (ensure_dir(cgroup_path, 0755) != 0) return 1;
	printf("已创建 cgroup: %s\n", cgroup_path);
	return 0;
}

/* 删除 cgroup 目录 */
int do_cg_delete(const char *cgroup_path)
{
	if (!cgroup_path) {
		fprintf(stderr, "--cg-delete 需要 --cgroup-path\n");
		return 1;
	}
	int empty = is_cgroup_empty(cgroup_path);
	if (empty == 0) {
		fprintf(stderr, "cgroup 非空，请先迁出进程: %s\n", cgroup_path);
		return 1;
	}
	if (empty < 0) {
		fprintf(stderr, "无法检查 cgroup 是否为空: %s\n", cgroup_path);
		return 1;
	}
	if (rmdir(cgroup_path) != 0) {
		fprintf(stderr, "删除 cgroup 失败: %s: %s\n", cgroup_path, strerror(errno));
		return 1;
	}
	printf("已删除 cgroup: %s\n", cgroup_path);
	return 0;
}
