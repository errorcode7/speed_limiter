#include "managed.h"
#include "cgroup.h"
#include "bpf.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

/* 便捷子命令：set - 设置进程限速 */
int do_set(pid_t pid, const char *rate_str, const char *bucket_str, const char *bpf_obj_path)
{
	unsigned long long rate = parse_size(rate_str);
	if (rate == 0) return 1;
	
	unsigned long long bucket = bucket_str ? parse_size(bucket_str) : rate; /* 默认 bucket = rate */
	if (bucket == 0) return 1;
	
	/* 1. 确保托管根目录存在 */
	if (ensure_dir(MANAGED_CGROUP_ROOT, 0755) != 0) {
		fprintf(stderr, "无法创建托管根目录: %s\n", MANAGED_CGROUP_ROOT);
		return 1;
	}
	
	/* 2. 生成规则目录名并创建 */
	char rule_dir[PATH_MAX];
	char rule_path[PATH_MAX];
	int ret_len = make_rule_dirname(rule_dir, sizeof(rule_dir), bucket, rate);
	if (ret_len < 0 || (size_t)ret_len >= sizeof(rule_dir)) {
		fprintf(stderr, "规则目录名过长\n");
		return 1;
	}
	ret_len = snprintf(rule_path, sizeof(rule_path), "%s/%s", MANAGED_CGROUP_ROOT, rule_dir);
	if (ret_len < 0 || (size_t)ret_len >= sizeof(rule_path)) {
		fprintf(stderr, "规则路径过长\n");
		return 1;
	}
	
	if (ensure_dir(rule_path, 0755) != 0) {
		fprintf(stderr, "无法创建规则目录: %s\n", rule_path);
		return 1;
	}
	
	/* 3. 获取 cgroup ID */
	unsigned long long cgid = get_cgroup_id(rule_path);
	if (cgid == 0) return 1;
	
	/* 4. 附加 eBPF 程序（复用现有逻辑） */
	char rate_str_buf[32], bucket_str_buf[32];
	snprintf(rate_str_buf, sizeof(rate_str_buf), "%llu", rate);
	snprintf(bucket_str_buf, sizeof(bucket_str_buf), "%llu", bucket);
	
	int ret = do_load(cgid, rate_str_buf, bucket_str_buf, bpf_obj_path, 0);
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
	snprintf(proc_cgroup, sizeof(proc_cgroup), "/proc/%d/cgroup", pid);
	
	FILE *f = fopen(proc_cgroup, "r");
	if (!f) {
		fprintf(stderr, "无法读取进程 %d 的 cgroup 信息\n", pid);
		return 1;
	}
	
	char line[PATH_MAX];
	char *cgroup_path = NULL;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "0::") == line) { /* cgroup v2 */
			cgroup_path = strchr(line, ':');
			if (cgroup_path) {
				cgroup_path = strchr(cgroup_path + 1, ':');
				if (cgroup_path) {
					cgroup_path++; /* 跳过 ':' */
					/* 移除换行符 */
					char *nl = strchr(cgroup_path, '\n');
					if (nl) *nl = '\0';
					break;
				}
			}
		}
	}
	fclose(f);
	
	if (!cgroup_path || strcmp(cgroup_path, "/") == 0) {
		printf("进程 %d 不在任何限速 cgroup 中\n", pid);
		return 0;
	}
	
	/* 2. 检查是否在托管目录下 */
	if (strncmp(cgroup_path, MANAGED_CGROUP_ROOT, strlen(MANAGED_CGROUP_ROOT)) != 0) {
		printf("进程 %d 不在托管限速 cgroup 中: %s\n", pid, cgroup_path);
		return 0;
	}
	
	/* 3. 将进程移回根 cgroup */
	char root_procs[PATH_MAX];
	snprintf(root_procs, sizeof(root_procs), "/sys/fs/cgroup/cgroup.procs");
	FILE *procs_f = fopen(root_procs, "w");
	if (procs_f) {
		fprintf(procs_f, "%d", pid);
		fclose(procs_f);
		printf("已将进程 %d 移回根 cgroup\n", pid);
	} else {
		fprintf(stderr, "无法将进程移回根 cgroup: %s\n", strerror(errno));
		return 1;
	}
	
	/* 4. 检查规则目录是否为空，空则删除目录（但保留eBPF程序和配置） */
	char full_rule_path[PATH_MAX];
	snprintf(full_rule_path, sizeof(full_rule_path), "/sys/fs/cgroup%s", cgroup_path);
	
	/* 获取 cgroup ID（在删除目录前） */
	unsigned long long cgid = get_cgroup_id(full_rule_path);
	
	if (is_cgroup_empty(full_rule_path) == 1) {
		/* 删除空目录 */
		if (rmdir(full_rule_path) == 0) {
			printf("已删除空规则目录: %s\n", full_rule_path);
			if (cgid != 0) {
				printf("注意: eBPF程序(cgroup_id=%llu)和配置已保留，可使用 'limiter move --pid <PID> --last' 重新应用\n", 
				       (unsigned long long)cgid);
			}
		} else {
			printf("规则目录非空，保留目录: %s\n", full_rule_path);
		}
	} else {
		printf("规则目录非空，保留目录: %s\n", full_rule_path);
		if (cgid != 0) {
			printf("eBPF程序(cgroup_id=%llu)和配置已保留\n", (unsigned long long)cgid);
		}
	}
	
	printf("已取消进程 %d 的限速（cgroup和eBPF程序已保留）\n", pid);
	return 0;
}

/* 便捷子命令：list - 列出所有限速规则 */
int do_list_managed(void)
{
	DIR *dir = opendir(MANAGED_CGROUP_ROOT);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s\n", MANAGED_CGROUP_ROOT);
		return 1;
	}
	
	printf("限速规则列表:\n");
	printf("%-12s %-12s %-12s %-12s %s\n", "cgroup_id", "限速(bps)", "进程数", "状态", "规则路径");

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;
		
		char rule_path[PATH_MAX];
		snprintf(rule_path, sizeof(rule_path), "%s/%s", MANAGED_CGROUP_ROOT, entry->d_name);
		
		/* 解析规则目录名 */
		unsigned long long bucket = 0, rate = 0;
		if (sscanf(entry->d_name, "bucket_%llu_rate_%llu", &bucket, &rate) != 2) {
			continue; /* 跳过格式不匹配的目录 */
		}
		
		/* 统计进程数 */
		char procs_path[PATH_MAX];
		int ret_len = snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", rule_path);
		if (ret_len < 0 || (size_t)ret_len >= sizeof(procs_path)) {
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
			char pin_path[PATH_MAX]="/sys/fs/bpf/speed_limiter/cg_root_egress";
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

/* 便捷子命令：purge - 清理所有限速规则 */
int do_purge(void)
{
	DIR *dir = opendir(MANAGED_CGROUP_ROOT);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s\n", MANAGED_CGROUP_ROOT);
		return 1;
	}
	
	int count = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;
		
		char rule_path[PATH_MAX];
		snprintf(rule_path, sizeof(rule_path), "%s/%s", MANAGED_CGROUP_ROOT, entry->d_name);
		
		/* 获取 cgroup ID 并卸载 eBPF */
		unsigned long long cgid = get_cgroup_id(rule_path);
		if (cgid != 0) {
			do_unload(cgid);
		}
		
		/* 删除目录 */
		if (rmdir(rule_path) == 0) {
			printf("已删除规则目录: %s\n", entry->d_name);
			count++;
		} else {
			fprintf(stderr, "无法删除目录 %s: %s\n", rule_path, strerror(errno));
		}
	}
	
	closedir(dir);
	printf("已清理 %d 个限速规则\n", count);
	return 0;
}

/* 便捷子命令：list --pid - 列出cgroup_id和进程ID */
int do_list_cgroup_pids(void)
{
	DIR *dir = opendir(MANAGED_CGROUP_ROOT);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s\n", MANAGED_CGROUP_ROOT);
		return 1;
	}
	
	printf("cgroup_id pid\n");
	
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;
		
		char rule_path[PATH_MAX];
		snprintf(rule_path, sizeof(rule_path), "%s/%s", MANAGED_CGROUP_ROOT, entry->d_name);
		
		/* 获取 cgroup ID */
		unsigned long long cgid = get_cgroup_id(rule_path);
		if (cgid == 0) continue;
		
		/* 读取进程列表 */
        char procs_path[PATH_MAX];
        int ret_len = snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", rule_path);
        if (ret_len < 0 || (size_t)ret_len >= sizeof(procs_path)) {
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

/* 便捷子命令：list --bpf - 列出cgroup_id、BPF程序名和加载时间 */
int do_list_cgroup_bpf(void)
{
	printf("cgroup_id bpf_name loaded_time\n");
	
	/* 获取根cgroup的ID */
	unsigned long long root_cgid = get_cgroup_id(MANAGED_CGROUP_ROOT);
	if (root_cgid == 0) {
		fprintf(stderr, "无法获取根cgroup ID\n");
		return 1;
	}
	
	/* 遍历所有BPF程序，查找附加到我们cgroup的程序 */
	/* 这里我们使用一个简化的方法：查找名为limit_egress的程序 */
	/* 在实际应用中，应该遍历所有程序并检查其附加信息 */
	
	/* 方法：通过bpftool prog list获取所有程序，然后检查每个程序 */
	FILE *fp = popen("bpftool prog list | grep 'limit_egress' | awk '{print $1}'", "r");
	if (fp) {
		char prog_id_str[32];
		while (fgets(prog_id_str, sizeof(prog_id_str), fp)) {
			/* 移除换行符 */
			char *nl = strchr(prog_id_str, '\n');
			if (nl) *nl = '\0';
			
			/* 移除冒号 */
			char *colon = strchr(prog_id_str, ':');
			if (colon) *colon = '\0';
			
			int prog_id = atoi(prog_id_str);
			if (prog_id > 0) {
				/* 使用libbpf API获取程序信息 */
				int prog_fd = bpf_prog_get_fd_by_id(prog_id);
				if (prog_fd >= 0) {
					struct bpf_prog_info info = {0};
					__u32 info_len = sizeof(info);
					
					if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
						/* 检查是否是我们的程序 */
						if (strcmp(info.name, "limit_egress") == 0) {
							/* 转换load_time为可读格式 */
							/* load_time是相对于系统启动的纳秒数 */
							time_t current_time = time(NULL);
							
							/* 获取系统启动时间 */
							struct timespec uptime;
							if (clock_gettime(CLOCK_MONOTONIC, &uptime) == 0) {
                                __u64 uptime_ns = uptime.tv_sec * 1000000000ULL + uptime.tv_nsec;
								
								/* 计算程序加载时的绝对时间 */
								time_t load_time_abs = current_time - (uptime_ns - info.load_time) / 1000000000ULL;
								
								struct tm *tm_info = localtime(&load_time_abs);
								char time_str[64];
								strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
								
								printf("%llu %s %s\n", root_cgid, info.name, time_str);
							}
						}
					}
					close(prog_fd);
				}
			}
		}
		pclose(fp);
	}
	
	return 0;
}
