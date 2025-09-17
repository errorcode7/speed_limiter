#include "cli.h"
#include "managed.h"
#include "bpf.h"
#include "cgroup.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <dirent.h>
#include <linux/bpf.h>

/* 打印使用说明 */
void print_usage(FILE *out)
{
	fprintf(out,
		"用法:\n"
		"  limiter set [--pid <pid>] --rate <rate> [--bucket <bucket>] [--bpf-obj <path>] [--deamon]\n"
		"  limiter move --pid <pid> [--cgroup-path <path> | --cgid <id> | --last]\n"
        "  limiter reload [-o <bpf.o>] [--cgroup-path <path>] [--attach-flag]\n"
		"  limiter unset --pid <pid>\n"
		"  limiter unload\n"
		"  limiter list [--pid | --bpf]\n"
		"  limiter purge\n"
		"  limiter --help\n\n"
		"说明:\n"
		"- 本工具通过 eBPF 程序在 cgroup egress 钩子上进行令牌桶限速。\n"
		"- 自动管理 cgroup。可先设置规则（输出路径与ID），再通过 move 迁移进程；reload 为全局重载。\n"
		"- 规则按 cgroup_id 保存在 config_map；状态在 state_map 中，仅 eBPF 更新。\n"
		"- 链接会固定(pin)到 " PIN_LINK_PERSISTENT "；map 固定到 " BPFFS_DIR "/。\n\n"
		"命令:\n"
		"  set               设置限速规则（可选迁移进程）\n"
		"  move              将进程迁移到指定规则（支持 --last）\n"
		"  reload            全局重载程序与数据结构（对所有规则生效）\n"
		"  unset             取消进程限速（自动清理空 cgroup）\n"
		"  unload            卸载 eBPF 程序（不修改配置）\n"
		"  list              列出所有限速规则和状态\n"
		"  list --pid        列出cgroup_id和进程ID\n"
		"  list --bpf        列出cgroup_id、BPF程序名和加载时间\n"
		"  purge             清理所有限速规则\n\n"
		"参数:\n"
		"  --pid/-p         目标进程 ID\n"
		"  --rate/-r         限速值，支持单位：k/K=1024, m/M=1024*1024（如：1m, 512k）\n"
		"  --bucket/-b       令牌桶大小，支持单位同上（可选，默认等于 rate）\n"
		"  --bpf-obj/-o      BPF 对象路径（可选，默认 " DEFAULT_BPF_OBJ ")\n"
		"  --deamon/-d         使用 bpf_prog_attach 方式附加（不支持持久化，但支持 MULTI）\n"
		"  --cgroup-path     目标 cgroup v2 路径\n"
		"  --cgid            目标 cgroup ID\n"
		"  --last            使用最近设置的规则\n"
		"  --attach-flag     传入附加标志\n"
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
			const char *bpf_obj_path = DEFAULT_BPF_OBJ;

			static struct option set_opts[] = {
				{"pid", required_argument, 0, 'p'},
				{"rate", required_argument, 0, 'r'},
				{"bucket", required_argument, 0, 'b'},
				{"bpf-obj", required_argument, 0, 'o'},
				{"deamon", no_argument, 0, 'd'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};

			int deamon = 0;
			while ((opt = getopt_long(argc - 1, argv + 1, "p:r:b:o:dh", set_opts, NULL)) != -1) {
				switch (opt) {
				case 'p': pid = (pid_t)strtoul(optarg, NULL, 10); break;
				case 'r': rate_str = optarg; break;
				case 'b': bucket_str = optarg; break;
				case 'o': bpf_obj_path = optarg; break;
				case 'd': deamon = 1; break;
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}

			if (!rate_str) {
				fprintf(stderr, "set 需要 --rate（--pid 可选）\n");
				print_usage(stderr);
				return 1;
			}
			unsigned long long rate_num = parse_size(rate_str);
			unsigned long long bucket_num = (bucket_str && bucket_str[0] != '\0') ? parse_size(bucket_str) : rate_num;
			if (rate_num == 0ULL || bucket_num == 0ULL) {
				fprintf(stderr, "无效的 rate/bucket 参数\n");
				return 1;
			}
			struct LimiterConfig cfg = { .cgid = 0ULL, .rate_bps = rate_num, .bucket_size = bucket_num };
			struct LoadOptions opts = { 
				.bpf_obj_path = bpf_obj_path, 
				.cgroup_path = MANAGED_ROOT, 
				.attach_flags = BPF_F_ALLOW_MULTI,
				.attach_mode = deamon ? ATTACH_MODE_PROG_ATTACH : ATTACH_MODE_LINK,
			};
			return do_set(pid, cfg, opts);
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
				SAFE_PATH_JOIN(resolved_path, cgroup_path);
			} else if (cgid != 0ULL) {
				/* 扫描托管目录按 cgid 匹配 */
				char *managed_dir = MANAGED_ROOT;
				DIR *dir = opendir(managed_dir);
				if (!dir) {
					fprintf(stderr, "无法打开托管目录: %s\n", managed_dir);
					return 1;
				}
				struct dirent *entry;
				int found = 0;
				while ((entry = readdir(dir)) != NULL) {
					if (entry->d_name[0] == '.') continue;
					char path[PATH_MAX];
					SAFE_PATH_JOIN(path, managed_dir, entry->d_name);
					
					/* 检查是否为目录 */
					struct stat st;
					if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
					
					unsigned long long id = get_cgroup_id(path);
					if (id == cgid) {
						SAFE_PATH_JOIN(resolved_path, path);
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
            const char *bpf_obj_path = DEFAULT_BPF_OBJ;
            unsigned int attach_flags = BPF_F_ALLOW_MULTI; /* 默认启用 MULTI */
            const char *cgroup_path = NULL;
			static struct option reload_opts[] = {
				{"bpf-obj", required_argument, 0, 'o'},
                {"cgroup-path", required_argument, 0, 'p'},
                {"attach-flag", no_argument, 0, 'm'},
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};
            while ((opt = getopt_long(argc - 1, argv + 1, "o:p:mh", reload_opts, NULL)) != -1) {
				switch (opt) {
				case 'o': bpf_obj_path = optarg; break;
                case 'p': cgroup_path = optarg; break;
                case 'm': attach_flags |= BPF_F_ALLOW_MULTI; break; /* 冪等设置 */
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}
			/* 重载程序：不需要 cgroup ID 和配置参数 */
            struct LimiterConfig cfg = { .cgid = 0, .rate_bps = 0ULL, .bucket_size = 0ULL };
            
            /* 检测当前的附加模式，保持一致性 */
            AttachMode current_mode = get_current_attach_mode();
            struct LoadOptions opts = { 
                .bpf_obj_path = bpf_obj_path, 
                .cgroup_path = cgroup_path, 
                .attach_flags = attach_flags,
                .attach_mode = current_mode  /* 保持当前的附加模式 */
            };
            return do_load(&cfg, &opts, RELOAD_PROGRAM);
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
		else if (strcmp(argv[1], "unload") == 0) {
			/* 便捷子命令：unload */
			int opt;
			static struct option unload_opts[] = {
				{"help", no_argument, 0, 'h'},
				{0, 0, 0, 0}
			};

			while ((opt = getopt_long(argc - 1, argv + 1, "h", unload_opts, NULL)) != -1) {
				switch (opt) {
				case 'h': print_usage(stdout); return 0;
				default: print_usage(stderr); return 1;
				}
			}

			/* 卸载程序，不修改配置 */
			return do_unload(0);
		}
		else if (strcmp(argv[1], "purge") == 0) {
			/* 便捷子命令：purge */
			return do_purge();
		}
	}
	return -1; /* 不是便捷模式 */
}

