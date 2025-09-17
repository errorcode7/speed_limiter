#include "cli.h"
#include "managed.h"
#include "bpf.h"
#include "cgroup.h"
#include "utils.h"

/* 重载标志定义 */
#define RELOAD_PROGRAM 2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <dirent.h>

/* 打印使用说明 */
void print_usage(FILE *out)
{
	fprintf(out,
		"用法:\n"
		"  便捷模式（推荐）：\n"
		"    limiter set [--pid <pid>] --rate <rate> [--bucket <bucket>] [--bpf-obj <path>]\n"
		"    limiter move --pid <pid> [--cgroup-path <path> | --cgid <id> | --last]\n"
		"    limiter reload [-o <bpf.o>]\n"
		"    limiter unset --pid <pid>\n"
		"    limiter list [--pid | --bpf]\n"
		"    limiter purge\n\n"
		"  高级模式：\n"
		"    limiter --attach --cgroup-path <path> --cgroup-id <id> --rate <bps> --bucket <bytes> [--bpf-obj <path>] [--replace]\n"
		"    limiter --detach --cgroup-id <id>\n"
		"    limiter --cg-create --cgroup-path <path>\n"
		"    limiter --cg-delete --cgroup-path <path>\n"
		"    limiter --move-pid --pid <pid> --cgroup-path <path>\n"
		"    limiter --list\n"
		"    limiter --help\n\n"
		"说明:\n"
		"- 本工具通过 eBPF 程序在 cgroup egress 钩子上进行令牌桶限速。\n"
		"- 便捷模式：自动管理 cgroup。可先设置规则（输出路径与ID），再通过 move 迁移进程；reload 为全局重载。\n"
		"- 高级模式：手动管理 cgroup 和 eBPF 程序。\n"
		"- 规则按 cgroup_id 保存在 config_map；状态在 state_map 中，仅 eBPF 更新。\n"
		"- 链接会固定(pin)到 /sys/fs/bpf/speed_limiter/cg_<ID>_egress；map 固定到 /sys/fs/bpf/speed_limiter/。\n\n"
		"便捷模式参数:\n"
		"  set               设置限速规则（可选迁移进程）\n"
		"  move              将进程迁移到指定规则（支持 --last）\n"
		"  reload            全局重载程序与数据结构（对所有规则生效）\n"
		"  unset             取消进程限速（自动清理空 cgroup）\n"
		"  list              列出所有限速规则和状态\n"
		"  list --pid        列出cgroup_id和进程ID\n"
		"  list --bpf        列出cgroup_id、BPF程序名和加载时间\n"
		"  purge             清理所有限速规则\n"
		"  --pid/-p         目标进程 ID\n"
		"  --rate/-r         限速值，支持单位：k/K=1024, m/M=1024*1024（如：1m, 512k）\n"
		"  --bucket/-b       令牌桶大小，支持单位同上（可选，默认等于 rate）\n"
		"  --bpf-obj/-o      BPF 对象路径（可选，默认 /usr/lib/speed_limiter/limiter.bpf.o）\n\n"
		"高级模式参数:\n"
		"  --cgroup-path/-p  目标 cgroup v2 路径（attach 必填）\n"
		"  --cgroup-id/-g    该 cgroup 的 id（attach/detach 必填）\n"
		"  --rate/-r         限速字节/秒，例如 1048576 表示约 1MB/s（attach 必填）\n"
		"  --bucket/-b       令牌桶大小（突发上限，字节，attach 必填）\n"
		"  --bpf-obj/-o      BPF 对象路径（可选，默认 /usr/lib/speed_limiter/limiter.bpf.o）\n"
		"  --replace/-R      已有链接时执行替换（简化为先卸载再附加）\n"
		"  --cg-create       创建 cgroup 目录（需 root）\n"
		"  --cg-delete       删除空 cgroup 目录（需 root）\n"
		"  --move-pid/-m     将指定 PID 移入 --cgroup-path（需 root）\n"
		"  --list            列出 config+state 的合并视图\n"
	);
}

/* 解析便捷模式参数 */
int parse_convenient_args(int argc, char **argv)
{
	if (argc >= 2) {
		if (strcmp(argv[1], "set") == 0) {
			/* 便捷子命令：set */
			int opt;
			pid_t pid = 0;
			const char *rate_str = NULL;
			const char *bucket_str = NULL;
			const char *bpf_obj_path = "/usr/lib/speed_limiter/limiter.bpf.o";
			
			static struct option set_opts[] = {
				{"pid", required_argument, 0, 'p'},
				{"rate", required_argument, 0, 'r'},
				{"bucket", required_argument, 0, 'b'},
				{"bpf-obj", required_argument, 0, 'o'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};
			
			while ((opt = getopt_long(argc - 1, argv + 1, "p:r:b:o:h", set_opts, NULL)) != -1) {
				switch (opt) {
				case 'p': pid = (pid_t)strtoul(optarg, NULL, 10); break;
				case 'r': rate_str = optarg; break;
				case 'b': bucket_str = optarg; break;
				case 'o': bpf_obj_path = optarg; break;
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}
			
			if (!rate_str) {
				fprintf(stderr, "set 需要 --rate（--pid 可选）\n");
				print_usage(stderr);
				return 1;
			}
			return do_set(pid, rate_str, bucket_str, bpf_obj_path);
		}
		else if (strcmp(argv[1], "move") == 0) {
			/* 便捷子命令：move */
			int opt;
			pid_t pid = 0;
			const char *cgroup_path = NULL;
			unsigned long long cgid = 0ULL;
			int use_last = 0;

			static struct option move_opts[] = {
				{"pid", required_argument, 0, 'p'},
				{"cgroup-path", required_argument, 0, 'P'},
				{"cgid", required_argument, 0, 'g'},
				{"last", no_argument, 0, 'L'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};

			while ((opt = getopt_long(argc - 1, argv + 1, "p:P:g:Lh", move_opts, NULL)) != -1) {
				switch (opt) {
				case 'p': pid = (pid_t)strtoul(optarg, NULL, 10); break;
				case 'P': cgroup_path = optarg; break;
				case 'g': cgid = strtoull(optarg, NULL, 10); break;
				case 'L': use_last = 1; break;
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}

			if (pid == 0) {
				fprintf(stderr, "move 需要 --pid\n");
				print_usage(stderr);
				return 1;
			}

			char resolved_path[PATH_MAX] = {0};
			if (use_last) {
				unsigned long long last_id = 0ULL;
				if (read_last_rule(resolved_path, sizeof(resolved_path), &last_id) != 0) {
					fprintf(stderr, "没有可用的最近规则，请先执行 limiter set\n");
					return 1;
				}
			} else if (cgroup_path) {
				snprintf(resolved_path, sizeof(resolved_path), "%s", cgroup_path);
			} else if (cgid != 0ULL) {
				/* 扫描托管目录按 cgid 匹配 */
				DIR *dir = opendir(MANAGED_CGROUP_ROOT);
				if (!dir) {
					fprintf(stderr, "无法打开托管目录: %s\n", MANAGED_CGROUP_ROOT);
					return 1;
				}
				struct dirent *entry;
				int found = 0;
				while ((entry = readdir(dir)) != NULL) {
					if (entry->d_name[0] == '.') continue;
					char path[PATH_MAX];
					snprintf(path, sizeof(path), "%s/%s", MANAGED_CGROUP_ROOT, entry->d_name);
					unsigned long long id = get_cgroup_id(path);
					if (id == cgid) {
						snprintf(resolved_path, sizeof(resolved_path), "%s", path);
						found = 1;
						break;
					}
				}
				closedir(dir);
				if (!found) {
					fprintf(stderr, "未找到匹配的 cgroup: id=%llu\n", (unsigned long long)cgid);
					return 1;
				}
			} else {
				fprintf(stderr, "move 需要 --cgroup-path 或 --cgid 或 --last 其一\n");
				print_usage(stderr);
				return 1;
			}

			return do_move_pid(pid, resolved_path);
		}
		else if (strcmp(argv[1], "reload") == 0) {
			/* 全局重载：使用 --reload 标志调用 do_load */
			int opt;
			const char *bpf_obj_path = "/usr/lib/speed_limiter/limiter.bpf.o";
			static struct option reload_opts[] = {
				{"bpf-obj", required_argument, 0, 'o'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};
			while ((opt = getopt_long(argc - 1, argv + 1, "o:h", reload_opts, NULL)) != -1) {
				switch (opt) {
				case 'o': bpf_obj_path = optarg; break;
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}
			/* 重载程序：不需要 cgroup ID 和配置参数 */
			return do_load(0, NULL, NULL, bpf_obj_path, RELOAD_PROGRAM);
		}
		else if (strcmp(argv[1], "unset") == 0) {
			/* 便捷子命令：unset */
			int opt;
			pid_t pid = 0;
			
			static struct option unset_opts[] = {
				{"pid", required_argument, 0, 'p'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};
			
			while ((opt = getopt_long(argc - 1, argv + 1, "p:h", unset_opts, NULL)) != -1) {
				switch (opt) {
				case 'p': pid = (pid_t)strtoul(optarg, NULL, 10); break;
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}
			
			if (pid == 0) {
				fprintf(stderr, "unset 需要 --pid\n");
				print_usage(stderr);
				return 1;
			}
			return do_unset(pid);
		}
		else if (strcmp(argv[1], "list") == 0) {
			/* 便捷子命令：list */
			int opt;
			int list_pid = 0, list_bpf = 0;
			
			static struct option list_opts[] = {
				{"pid", no_argument, 0, 'p'},
				{"bpf", no_argument, 0, 'b'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};
			
			while ((opt = getopt_long(argc - 1, argv + 1, "pbh", list_opts, NULL)) != -1) {
				switch (opt) {
				case 'p': list_pid = 1; break;
				case 'b': list_bpf = 1; break;
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}
			
			if (list_pid && list_bpf) {
				fprintf(stderr, "list 不能同时使用 --pid 和 --bpf\n");
				print_usage(stderr);
				return 1;
			}
			
			if (list_pid) {
				return do_list_cgroup_pids();
			} else if (list_bpf) {
				return do_list_cgroup_bpf();
			} else {
				return do_list_managed();
			}
		}
		else if (strcmp(argv[1], "purge") == 0) {
			/* 便捷子命令：purge */
			return do_purge();
		}
	}
	return -1; /* 不是便捷模式 */
}

/* 解析高级模式参数 */
int parse_advanced_args(int argc, char **argv)
{
	int opt;
	int attach = 0, detach = 0;
	int cg_create = 0, cg_delete = 0, move_pid_flag = 0, list_flag = 0, reload_flag = 0;
	const char *cgroup_path = NULL;
	const char *rate_str = NULL;
	const char *bucket_str = NULL;
	const char *bpf_obj_path = "/usr/lib/speed_limiter/limiter.bpf.o";
	unsigned long long cgid = 0ULL;
	pid_t pid = 0;

	static struct option long_opts[] = {
		{"attach", no_argument, 0, 'a'},
		{"detach", no_argument, 0, 'd'},
		{"cgroup-path", required_argument, 0, 'p'},
		{"cgroup-id", required_argument, 0, 'g'},
		{"rate", required_argument, 0, 'r'},
		{"bucket", required_argument, 0, 'b'},
		{"bpf-obj", required_argument, 0, 'o'},
		{"cg-create", no_argument, 0, 'C'},
		{"cg-delete", no_argument, 0, 'D'},
		{"move-pid", no_argument, 0, 'M'},
		{"pid", required_argument, 0, 'i'},
		{"list", no_argument, 0, 'l'},
		{"replace", no_argument, 0, 'R'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "adp:g:r:b:o:CDMi:lRh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'a': attach = 1; break;
		case 'd': detach = 1; break;
		case 'p': cgroup_path = optarg; break;
		case 'g': cgid = strtoull(optarg, NULL, 10); break;
		case 'r': rate_str = optarg; break;
		case 'b': bucket_str = optarg; break;
		case 'o': bpf_obj_path = optarg; break;
		case 'C': cg_create = 1; break;
		case 'D': cg_delete = 1; break;
		case 'M': move_pid_flag = 1; break;
		case 'i': pid = (pid_t)strtoul(optarg, NULL, 10); break;
		case 'l': list_flag = 1; break;
		case 'R': reload_flag = 1; break;
		case 'h': print_usage(stdout); return 0;
		default: print_usage(stderr); return 1;
		}
	}

	/* 管理子命令优先处理 */
	if (cg_create) return do_cg_create(cgroup_path);
	if (cg_delete) return do_cg_delete(cgroup_path);
	if (move_pid_flag) return do_move_pid(pid, cgroup_path);
	if (list_flag) return do_list();

	/* 业务主路径：attach/detach 二选一 */
	if ((attach && detach) || (!attach && !detach)) {
		fprintf(stderr, "必须且只能指定 --attach 或 --detach 之一（或使用管理命令）\n");
		print_usage(stderr);
		return 1;
	}

	if (detach) {
		if (cgid == 0ULL) {
			fprintf(stderr, "--detach 需要 --cgroup-id\n");
			print_usage(stderr);
			return 1;
		}
		return do_unload(cgid);
	}

	/* attach 路径校验 */
	if (!cgroup_path || cgid == 0ULL || !rate_str || !bucket_str) {
		fprintf(stderr, "--attach 需要同时提供 --cgroup-path/--cgroup-id/--rate/--bucket\n");
		print_usage(stderr);
		return 1;
	}
	return do_load(cgid, rate_str, bucket_str, bpf_obj_path, reload_flag);
}
