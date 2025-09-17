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

/* 检查 cgroup 是否为空 */
int is_cgroup_empty(const char *cgroup_path)
{
	char procs_path[PATH_MAX];
	SAFE_PATH_JOIN(procs_path, cgroup_path, "cgroup.procs");
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

	/* 在迁移前保存该 PID 的原始 cgroup（若尚未记录） */
	char orig_path[PATH_MAX];
	unsigned long long orig_st = 0ULL;
	if (load_pid_original_cgroup(pid, NULL, 0, NULL) != 0) {
		/* 无记录才尝试读取并保存 */
		if (read_proc_cgroup_v2_path(pid, orig_path, sizeof(orig_path)) == 0 &&
			read_proc_starttime(pid, &orig_st) == 0) {
			/* 记录：若记录已存在则忽略 */
			int save_ret = save_pid_original_cgroup(pid, orig_path, orig_st);
			if (save_ret != 0) {
				fprintf(stderr, "警告: 保存进程 %d 的原始 cgroup 记录失败 (路径=%s, 启动时间=%llu)\n",
				        pid, orig_path, (unsigned long long)orig_st);
			}
		} else {
			fprintf(stderr, "警告: 无法读取进程 %d 的 cgroup 信息或启动时间\n", pid);
		}
	}

	if (move_pid_to_cgroup(pid, cgroup_path) == 0) {
		printf("已将 PID %d 移入 %s\n", pid, cgroup_path);
		return 0;
	} else {
		return 1;
	}
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
