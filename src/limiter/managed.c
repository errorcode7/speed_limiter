#define _GNU_SOURCE
#include "managed.h"
#include "cgroup.h"
#include "bpf.h"
#include "utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

/* 便捷子命令：set - 设置进程限速 */
int do_set(pid_t pid, const struct LimiterConfig cfg_in, const struct LoadOptions opts_in)
{
    unsigned long long rate = cfg_in.rate_bps;
    unsigned long long bucket = cfg_in.bucket_size ? cfg_in.bucket_size : cfg_in.rate_bps;
    const char *bpf_obj_path = opts_in.bpf_obj_path;
    const char *default_cgroup_path = opts_in.cgroup_path ? opts_in.cgroup_path : MANAGED_ROOT;

    /* 验证参数有效性 */
    if (rate == 0ULL) return 1;
    if (bucket == 0ULL) return 1;

    /* 1. 确保托管根目录存在（默认 attach 到 MANAGED_ROOT） */
    if (ensure_dir(default_cgroup_path, 0755) != 0) {
        fprintf(stderr, "无法创建托管根目录: %s\n", default_cgroup_path);
        return 1;
    }

    /* 2. 生成规则目录名并创建 */
    char rule_str[PATH_MAX];
    char rule_path[PATH_MAX];

    /* 生成规则目录名：bucket_<bytes>_rate_<bps> */
    SAFE_SNPRINTF(rule_str, "bucket_%llu_rate_%llu", bucket, rate);

    if (SAFE_PATH_JOIN(rule_path, default_cgroup_path, rule_str) != 0) {
        fprintf(stderr, "规则路径过长\n");
        return 1;
    }

    if (ensure_dir(rule_path, 0755) != 0) {
        return 1;
    }

    /* 3. 获取 cgroup ID */
    unsigned long long cgid = get_cgroup_id(rule_path);
    if (cgid == 0) return 1;


    struct LimiterConfig cfg = { .cgid = cgid, .rate_bps = rate, .bucket_size = bucket };
	//ATTACH_POINT作为进程的附加路径，attach_flags作为附加选项
    struct LoadOptions opts = { 
        .bpf_obj_path = bpf_obj_path, 
        .cgroup_path = rule_path, 
        .attach_flags = (opts_in.attach_flags ? opts_in.attach_flags : BPF_F_ALLOW_MULTI),
        .attach_mode = opts_in.attach_mode
    };

	//cgroup_path作为进程的附加路径，attach_flags作为附加选项
	//可以是根cgroup,也可是default_cgroup_path下的具体cgroup路径(/speed_limiter/bucket_%s_rate_%s)，rule_path
	int ret = do_load(&cfg, &opts, 0);
    if (ret != 0) return ret;

    /* 记录最近规则，便于后续 move 使用 */
    write_last_rule(rule_path, cgid);

    /* 可选：将进程移入此 cgroup（仅当提供了 pid） */
    if (pid > 0) {
        ret = do_move_pid(pid, rule_path);
        if (ret != 0) {
            fprintf(stderr, "警告: 限速已设置但进程迁移失败\n");
        }
    }

    printf("已设置限速: rate=%llu bytes/s, bucket=%llu bytes, cgroup=%s, cgroup_id=%llu\n",
           rate, bucket, rule_path, (unsigned long long)cgid);
    if (pid <= 0) {
        printf("提示: 可使用 'limiter move --pid <PID> --last' 迁移进程进入该规则\n");
    }
    return 0;
}

/* 便捷子命令：unset - 取消进程限速 */
int do_unset(pid_t pid)
{
	/* 1. 查找进程当前所在的托管 cgroup */
	char proc_cgroup[PATH_MAX];
	char pid_str[32];
	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	SAFE_PATH_JOIN(proc_cgroup, "/proc", pid_str, "cgroup");

	FILE *f = fopen(proc_cgroup, "r");
	if (!f) {
		fprintf(stderr, "无法读取进程 %d 的 cgroup 信息\n", pid);
		return 1;
	}

	char cgroup_path[PATH_MAX];
	char *cgroup_path_ptr = NULL;//指向line的缓冲区
	while (fgets(cgroup_path, sizeof(cgroup_path), f)) {
		if (strstr(cgroup_path, "0::") == cgroup_path) { /* cgroup v2 */
			cgroup_path_ptr = strchr(cgroup_path, ':');
			if (cgroup_path_ptr) {
				cgroup_path_ptr = strchr(cgroup_path_ptr + 1, ':');
				if (cgroup_path_ptr) {
					cgroup_path_ptr++; /* 跳过 ':' */
					/* 移除换行符 */
					char *nl = strchr(cgroup_path_ptr, '\n');
					if (nl) *nl = '\0';
					break;
				}
			}
		}
	}
	fclose(f);

	if (!cgroup_path_ptr || strcmp(cgroup_path_ptr, "/") == 0) {
		printf("进程 %d 不在任何限速 cgroup 中\n", pid);
		return 0;
	}

	/* 2. 检查是否在托管目录下 */
	char rule_path[PATH_MAX];
	SAFE_PATH_JOIN(rule_path, CGROUPFS_ROOT, cgroup_path_ptr);
	if (access(rule_path, F_OK) != 0) {
		printf("进程 %d 的 cgroup 路径不存在: %s\n", pid, rule_path);
		return 0;
	}
	/* 3. 将进程恢复到原始 cgroup（若有记录且校验通过），否则移回根 cgroup */

	int restored = 0;
	{
		char saved_path[PATH_MAX];
		unsigned long long saved_st = 0ULL, cur_st = 0ULL;
		if (load_pid_original_cgroup(pid, saved_path, sizeof(saved_path), &saved_st) == 0 &&
			read_proc_starttime(pid, &cur_st) == 0 &&
			saved_st == cur_st) {
			char target_cgroup[PATH_MAX];
			SAFE_PATH_JOIN(target_cgroup, CGROUPFS_ROOT, saved_path);
			if (move_pid_to_cgroup(pid, target_cgroup) == 0) {
				printf("已将进程 %d 恢复到原始 cgroup: %s\n", pid, saved_path);
				restored = 1;
			} else {
				fprintf(stderr, "无法恢复到原始 cgroup，回退到根\n");
			}
		}
		/* 清理记录（无论是否恢复成功） */
		( void ) delete_pid_original_cgroup(pid);
	}

	if (!restored) {
		if (move_pid_to_cgroup(pid, CGROUPFS_ROOT) == 0) {
			printf("已将进程 %d 移回根 cgroup\n", pid);
		} else {
			fprintf(stderr, "无法将进程移回根 cgroup\n");
			return 1;
		}
	}

	/* 4. 检查规则目录是否为空，空则删除目录（但保留eBPF程序和配置） */

	printf("已取消进程 %d 的限速（cgroup和eBPF程序已保留）\n", pid);
	return 0;
}

/* 便捷子命令：list - 列出所有限速规则,其实应该从config map里获取 */
int do_list_managed(void)
{
	char *managed_dir = MANAGED_ROOT;
	DIR *dir = opendir(managed_dir);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s\n", managed_dir);
		return 1;
	}

	printf("限速规则列表:\n");
	printf("%-12s %-12s %-12s %-12s %s\n", "cgroup_id", "限速(bps)", "进程数", "状态", "规则路径");

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;

		char rule_path[PATH_MAX];
		SAFE_PATH_JOIN(rule_path, managed_dir, entry->d_name);
		/* 检查是否为目录 */
		struct stat st;
		if (stat(rule_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

		/* 解析规则目录名 */
		unsigned long long bucket = 0, rate = 0;
		if (sscanf(entry->d_name, "bucket_%llu_rate_%llu", &bucket, &rate) != 2) {
			continue; /* 跳过格式不匹配的目录 */
		}

		/* 统计进程数 */
		char procs_path[PATH_MAX];
		if (SAFE_PATH_JOIN(procs_path, rule_path, "cgroup.procs") != 0) {
			fprintf(stderr, "进程路径过长: %s\n", rule_path);
			continue;
		}
		FILE *f = fopen(procs_path, "r");
		int proc_count = 0;
		if (f) {
			char line[64];
			while (fgets(line, sizeof(line), f)) {
				if (strlen(line) > 0) proc_count++;
			}
			fclose(f);
		}

		/* 获取当前状态 */
		unsigned long long cgid = get_cgroup_id(rule_path);
		char status[32] = "未知";
		if (cgid != 0) {
			/* 检查是否有 eBPF 链接 */
			char pin_path[PATH_MAX]=PIN_LINK_PERSISTENT;
			//(pin_path, sizeof(pin_path), "/sys/fs/bpf/speed_limiter/cg_%llu_egress", cgid);
			int rc = access(pin_path, F_OK);
			if (rc == 0) {
				strcpy(status, "活跃");
			} else {
				int saved = errno;
				if (saved == EACCES || saved == EPERM) {
					fprintf(stderr, "无法访问 pin 路径: %s: %s\n", pin_path, strerror(saved));
					strcpy(status, "未知");
				} else {
					strcpy(status, "未附加");
				}
			}
		}

		printf("%-12llu %-12llu %-8d %-12s %s\n",
		       (unsigned long long)cgid, rate, proc_count, status, rule_path);
	}

	closedir(dir);
	return 0;
}


/* 清理空的 cgroup 目录 */
static int __attribute__((unused)) purge_empty_cgroups(void)
{
	DIR *dir = opendir(CGROUPFS_ROOT);
	if (!dir) {
		printf("无法打开托管目录: %s\n", CGROUPFS_ROOT);
		return 0;
	}

	int deleted_dirs = 0;
	int kept_dirs = 0;
	struct dirent *entry;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;

		char rule_path[PATH_MAX];
		SAFE_PATH_JOIN(rule_path, CGROUPFS_ROOT, entry->d_name);

		/* 检查目录是否为空（检查 cgroup.procs 文件） */
		char procs_path[PATH_MAX];
		if (SAFE_PATH_JOIN(procs_path, rule_path, "cgroup.procs") != 0) {
			fprintf(stderr, "路径过长: %s/cgroup.procs\n", rule_path);
			continue;
		}

		FILE *fp = fopen(procs_path, "r");
		if (fp) {
			int c = fgetc(fp);
			fclose(fp);

			/* 如果文件为空，删除目录 */
			if (c == EOF) {
				if (rmdir(rule_path) == 0) {
					printf("已删除空规则目录: %s\n", entry->d_name);
					deleted_dirs++;
				} else {
					fprintf(stderr, "无法删除目录 %s: %s\n", rule_path, strerror(errno));
				}
			} else {
				printf("保留非空规则目录: %s (包含进程)\n", entry->d_name);
				kept_dirs++;
			}
		}
	}

	closedir(dir);

	printf("已删除 %d 个空目录，保留 %d 个包含进程的目录\n", deleted_dirs, kept_dirs);
	return deleted_dirs;
}


/* 便捷子命令：purge - 清理所有限速规则 */
int do_purge(void)
{
	printf("开始清理限速规则...\n\n");
	/* 0. 先卸载所有已附加在托管目录的 limit_egress 程序 */
	//int detached = bpf_detach_limit_egress_all();
	int detached = detach_limit_egress(ATTACH_POINT);
	if (detached < 0) {
		return 1;
	}
	int bpf_unlinked = bpf_purge_maps();
	int bpf_maps_removed = bpf_purge_links();

	/* 3. 清理空的 cgroup 目录 */
	//int cgroup_cleaned = purge_empty_cgroups();

	printf("清理完成: 卸载程序=%d次, BPF链接=%d个, BPF maps=%d个\n",
	       detached, bpf_unlinked, bpf_maps_removed);

	return 0;
}

/* 便捷子命令：list --pid - 列出cgroup_id和进程ID */
int do_list_cgroup_pids(void)
{
	char *managed_root = MANAGED_ROOT;
	DIR *dir = opendir(managed_root);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s,请先用set创建规则\n", managed_root);
		return 1;
	}

	printf("cgroup_id  pid\n");
	//从MANAGED_ROOT目录下读取子目录下的cgroup.procs
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;

		char rule_path[PATH_MAX];
		SAFE_PATH_JOIN(rule_path, managed_root, entry->d_name);

		/* 过滤非目录项（避免把普通文件当作规则目录处理） */
		struct stat st;
		if (stat(rule_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
			continue;
		}

		/* 获取 cgroup ID */
		unsigned long long cgid = get_cgroup_id(rule_path);
		if (cgid == 0) continue;

		/* 读取进程列表 */
        char procs_path[PATH_MAX];
        if (SAFE_PATH_JOIN(procs_path, rule_path, "cgroup.procs") != 0) {
            /* 路径过长，跳过此规则 */
            continue;
        }
		FILE *f = fopen(procs_path, "r");
		if (!f) continue;

		char line[64];
		while (fgets(line, sizeof(line), f)) {
			/* 移除换行符 */
			char *nl = strchr(line, '\n');
			if (nl) *nl = '\0';

			if (strlen(line) > 0) {
				printf("%llu %s\n", (unsigned long long)cgid, line);
			}
		}
		fclose(f);
	}

	closedir(dir);
	return 0;
}

/* 格式化加载时间为可读字符串 */
static int format_load_time(__u64 load_time, char *time_str, size_t time_str_size)
{
	time_t current_time = time(NULL);
	struct timespec uptime;
	
	if (clock_gettime(CLOCK_MONOTONIC, &uptime) != 0) {
		return -1;
	}
	
	__u64 uptime_ns = uptime.tv_sec * 1000000000ULL + uptime.tv_nsec;
	time_t load_time_abs = current_time - (uptime_ns - load_time) / 1000000000ULL;
	
	struct tm *tm_info = localtime(&load_time_abs);
	if (!tm_info) {
		return -1;
	}
	
	strftime(time_str, time_str_size, "%Y-%m-%d %H:%M:%S", tm_info);
	return 0;
}

/* 打印程序信息 */
static void print_prog_info(__u32 prog_id, const struct bpf_prog_info *info, const char *cgroup_path)
{
	unsigned long long cgid = get_cgroup_id(cgroup_path);
	char time_str[64];
	const char *attach_mode = get_prog_attach_mode(prog_id);
	
	if (format_load_time(info->load_time, time_str, sizeof(time_str)) == 0) {
		printf("%llu %s %s %s %s\n", (unsigned long long)cgid, info->name, time_str, cgroup_path, attach_mode);
	}
}

/* 检查程序是否附加到指定的cgroup */
static int check_prog_attached_to_cgroup(__u32 prog_id, const char *cgroup_path)
{
	int cgroup_fd = open(cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		return 0;
	}
	
	LIBBPF_OPTS(bpf_prog_query_opts, p);
	__u32 prog_ids[1024] = {0};
	
	p.query_flags = 0;
	p.prog_cnt = ARRAY_SIZE(prog_ids);
	p.prog_ids = prog_ids;
	
	int ret = 0;
	if (bpf_prog_query_opts(cgroup_fd, BPF_CGROUP_INET_EGRESS, &p) == 0) {
		for (__u32 i = 0; i < p.prog_cnt; i++) {
			if (prog_ids[i] == prog_id) {
				ret = 1;
				break;
			}
		}
	}
	
	close(cgroup_fd);
	return ret;
}

/* 查找程序附加的cgroup并打印信息 */
static int find_and_print_prog_attachment(__u32 prog_id, const struct bpf_prog_info *info)
{
	char *attach_point = ATTACH_POINT;
	/* 首先检查根cgroup */
	if (check_prog_attached_to_cgroup(prog_id, attach_point)) {
		print_prog_info(prog_id, info, attach_point);
		return 1;
	}
	
	/* 遍历所有子cgroup */
	DIR *dir = opendir(attach_point);
	if (!dir) {
		return 0;
	}
	
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;
		
		char test_path[PATH_MAX];
		SAFE_PATH_JOIN(test_path, attach_point, entry->d_name);
		
		/* 检查是否为目录 */
		struct stat st;
		if (stat(test_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
		
		/* 检查程序是否附加到此cgroup */
		if (check_prog_attached_to_cgroup(prog_id, test_path)) {
			print_prog_info(prog_id, info, test_path);
			closedir(dir);
			return 1;
		}
	}

	closedir(dir);
	return 0;
}

/* 处理单个BPF程序 */
static int process_bpf_program(__u32 prog_id)
{
	int prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "无法通过ID获取程序 (%u): %s\n", prog_id, strerror(errno));
		return 0;
	}
	
	struct bpf_prog_info info = {0};
	__u32 info_len = sizeof(info);
	
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
		/* 检查是否是我们的limit_egress程序 */
		if (strcmp(info.name, "limit_egress") == 0) {
			find_and_print_prog_attachment(prog_id, &info);
		}
	}
	
	close(prog_fd);
	return 0;
}

/* 便捷子命令：list --bpf - 列出cgroup_id、BPF程序名和加载时间 */
int do_list_cgroup_bpf(void)
{
	printf("cgroup_id bpf_name loaded_time cgroup_path attach_mode\n");

	__u32 id = 0;
	int err = 0;

	/* 遍历所有BPF程序 */
	while (true) {
		err = bpf_prog_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			fprintf(stderr, "无法获取下一个程序: %s\n", strerror(errno));
			return 1;
		}

		process_bpf_program(id);
	}

	return 0;
}
