#include "bpf.h"
#include "utils.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../include/limiter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "managed.h"
#include "cgroup.h"
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/syscall.h>


/* 前置声明，确保在严格编译下无隐式声明 */
unsigned long long get_cgroup_id(const char *cgroup_path);
static int bpf_attach_cgroup(int prog_fd, const char *attach_cg_path, unsigned int attach_flags);


static int bpf_load_program(const char *bpf_obj_path, struct bpf_object **out_obj, int *out_prog_fd)
{
	//指针赋值
	struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "bpf_object__open_file failed: %s (path=%s)\n", strerror(errno), bpf_obj_path);
		return 1;
	}
	int err_load = bpf_object__load(obj);
	if (err_load) {
		fprintf(stderr, "bpf_object__load failed: %s\n", strerror(-err_load));
		bpf_object__close(obj);
		return 1;
	}

	// 3. 获取程序句柄
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "limit_egress");
	if (!prog) {
		fprintf(stderr, "program 'limit_egress' not found\n");
		bpf_object__close(obj);
		return 1;
	}

    /* 先使用 bpf_prog_attach 传递 attach_flags（如 BPF_F_ALLOW_MULTI） */
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "获取 prog fd 失败\n");
        bpf_object__close(obj);
        return 1;
    }

	*out_prog_fd=prog_fd;
	*out_obj=obj;
	return 0;
}



/* 加载 eBPF 程序并固定到文件系统 */
static int do_load_bpf_program(const struct LoadOptions *opts)
{
	struct bpf_object *obj = NULL;
	int prog_fd = -1;

    // 2. 加载 eBPF 对象
    const char *bpf_obj_path = (opts && opts->bpf_obj_path) ? opts->bpf_obj_path : DEFAULT_BPF_OBJ;
	unsigned int attach_flags = (opts ? opts->attach_flags : BPF_F_ALLOW_MULTI);
	AttachMode attach_mode = (opts ? opts->attach_mode : ATTACH_MODE_LINK);
	//opts->cgroup_path具体cgroup
	//必须附加到根cgroup
	const char *attach_cg_path = ATTACH_POINT;

	//attach_cg_path不能为空
	if (attach_cg_path == NULL) {
		fprintf(stderr, "attach cgroup path can't be null\n");
		return 1;
	}

	/* 创建托管 cgroup 目录 */
	if (ensure_dir(attach_cg_path, 0755) != 0) {
		return 1;
	}

	/* 创建bpffs目录 */
	if (ensure_dir(BPFFS_DIR, 0755) != 0) {
		return 1;
	}

	int ret = bpf_load_program(bpf_obj_path, &obj, &prog_fd);//后续出错都要释放obj，prog_fd
	if (ret != 0) {
		fprintf(stderr, "bpf_load_program failed: %s\n", strerror(errno));
		return 1;
	}

	// 根据附加模式选择不同的附加方式
	if (attach_mode == ATTACH_MODE_LINK) {
		ret = bpf_attach_cgroup_with_link(prog_fd, attach_cg_path);
		if (ret != 0) {
			fprintf(stderr, "bpf_attach_cgroup_with_link failed: %s\n", strerror(errno));
			goto err;
		}
	} else {
		ret = bpf_attach_cgroup(prog_fd, attach_cg_path, attach_flags);
		if (ret != 0) {
			fprintf(stderr, "bpf_attach_cgroup failed: %s\n", strerror(errno));
			goto err;
		}
	}

	// 7. 固定 map
	struct bpf_map *pm;
	pm = bpf_object__find_map_by_name(obj, "rate_limit_config_map");
	if (pm) {
		(void)unlink(PIN_MAP_CFG);
		if (bpf_map__pin(pm, PIN_MAP_CFG) != 0 && errno != EEXIST) {
			fprintf(stderr, "warning: 无法固定 config_map: %s\n", strerror(errno));
			goto err;
		}
	}
	pm = bpf_object__find_map_by_name(obj, "rate_limit_state_map");
	if (pm) {
		(void)unlink(PIN_MAP_STATE);
		if (bpf_map__pin(pm, PIN_MAP_STATE) != 0 && errno != EEXIST) {
			fprintf(stderr, "warning: 无法固定 state_map: %s\n", strerror(errno));
			goto err;
		}
	}

    printf("eBPF 程序已加载并固定 (attach to: %s)\n", attach_cg_path);
	return 0;
err:
	bpf_object__close(obj);
	return 1;
}


static int bpf_attach_cgroup(int prog_fd, const char *attach_cg_path, unsigned int attach_flags)
{
	// 只使用 bpf_prog_attach 方式附加程序（支持 MULTI 但不持久化）
	int cg_fd = open_cgroup_fd(attach_cg_path);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", attach_cg_path, strerror(errno));
		return 1;
	}

	if (bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_INET_EGRESS, attach_flags) != 0) {
		fprintf(stderr, "bpf_prog_attach 失败: %s\n", strerror(errno));
		close(cg_fd);
		return 1;
	}
	
	close(cg_fd);
	printf("eBPF 程序已通过 prog_attach 方式附加 (attach to: %s)\n", attach_cg_path);
	return 0;
}

/* 使用 bpf_link 方式附加程序到 cgroup（支持持久化） */
int bpf_attach_cgroup_with_link(int prog_fd, const char *cgroup_path)
{
	// 打开目标 cgroup
	int cg_fd = open_cgroup_fd(cgroup_path);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", cgroup_path, strerror(errno));
		return 1;
	}

	// 使用 bpf_link 方式附加程序
	struct bpf_link_create_opts opts = {0};
	opts.sz = sizeof(opts);
	int link_fd = bpf_link_create(prog_fd, cg_fd, BPF_CGROUP_INET_EGRESS, &opts);
	if (link_fd < 0) {
		fprintf(stderr, "bpf_link_create 失败: %s\n", strerror(errno));
		close(cg_fd);
		return 1;
	}

	// 固定 link 到文件系统（持久化）
	(void)unlink(PIN_LINK_PERSISTENT); // 忽略不存在的错误
	if (bpf_obj_pin(link_fd, PIN_LINK_PERSISTENT) != 0) {
		fprintf(stderr, "warning: 无法固定链接到 %s（可能未挂载 bpffs）\n", PIN_LINK_PERSISTENT);
		close(link_fd);
		close(cg_fd);
		return 1;
	}
	
	close(link_fd);
	close(cg_fd);
	printf("eBPF 程序已通过 link 方式附加并持久化 (attach to: %s)\n", cgroup_path);
	return 0;
}

/* 检查 link 是否已附加 */
int bpf_is_link_attached(const char *cgroup_path)
{
	(void)cgroup_path; // 暂时不使用，因为 link 是全局的
	return (access(PIN_LINK_PERSISTENT, F_OK) == 0) ? 1 : 0;
}

/* 卸载 link 附加的程序 */
int bpf_detach_link(const char *cgroup_path)
{
	(void)cgroup_path; // link 是全局的，不需要指定 cgroup_path
	
	// 首先尝试从内核中分离 link
	int link_fd = open(PIN_LINK_PERSISTENT, O_RDONLY);
	if (link_fd >= 0) {
		// 从内核中分离 link
		if (bpf_link_detach(link_fd) == 0) {
			close(link_fd);
			// 然后删除 pinned link 文件
			if (unlink(PIN_LINK_PERSISTENT) == 0) {
				printf("已卸载 limit_egress 程序 (通过删除 link pin): %s\n", cgroup_path ? cgroup_path : "全局");
				return 1;
			}
		} else {
			close(link_fd);
		}
	}
	
	// 如果无法打开 link 文件，尝试直接删除
	if (unlink(PIN_LINK_PERSISTENT) == 0) {
		printf("已卸载 limit_egress 程序 (通过删除 link pin): %s\n", cgroup_path ? cgroup_path : "全局");
		return 1;
	}
	
	// 如果 pin 文件不存在，说明程序可能已经被卸载
	if (errno == ENOENT) {
		return 0; // 没有需要卸载的程序
	}
	
	fprintf(stderr, "卸载 limit_egress 程序失败: %s\n", strerror(errno));
	return -1;
}

/* 从托管目录恢复所有配置到 config_map */
static int do_restore_configs(void)
{
	int cfg_fd = bpf_obj_get(PIN_MAP_CFG);
	if (cfg_fd < 0) {
		// 如果 config_map 不存在，说明是首次加载或者 maps 被清理了
		// 这种情况下不需要恢复配置，直接返回成功
		if (errno == ENOENT) {
			printf("config_map 不存在，跳过配置恢复\n");
			return 0;
		}
		fprintf(stderr, "无法打开 config_map: %s\n", strerror(errno));
		return -1;
	}

	char *manage_dir = MANAGED_ROOT;
	DIR *dir = opendir(manage_dir);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s\n", manage_dir);
		close(cfg_fd);
		return -1;
	}

	struct dirent *entry;
	int restored = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;

		char rule_path[PATH_MAX];
		SAFE_PATH_JOIN(rule_path, manage_dir, entry->d_name);

		/* 检查是否为目录 */
		struct stat st;
		if (stat(rule_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

		/* 解析目录名格式：bucket_<bytes>_rate_<bps> */
		unsigned long long bucket = 0ULL, rate = 0ULL;
		if (sscanf(entry->d_name, "bucket_%llu_rate_%llu", &bucket, &rate) != 2) continue;

		/* 获取 cgroup ID */
		unsigned long long cgid_backfill = get_cgroup_id(rule_path);
		if (cgid_backfill == 0ULL) continue;

		/* 写入配置 */
		struct rate_limit_config conf2;
		conf2.rate_bps = rate;
		conf2.bucket_size = bucket;
		if (bpf_map_update_elem(cfg_fd, &cgid_backfill, &conf2, BPF_ANY) == 0) {
			restored++;
		}
	}
	closedir(dir);
	close(cfg_fd);

	if (restored > 0) {
		printf("已恢复 %d 个配置\n", restored);
	}
	return restored;
}

/* 更新指定 cgroup 的配置 */
static int do_update_config(unsigned long long cgid, unsigned long long rate, unsigned long long bucket)
{
	if (rate == 0ULL || bucket == 0ULL) {
		fprintf(stderr, "无效的配置参数: rate=%llu, bucket=%llu\n", rate, bucket);
		return 1;
	}

	struct rate_limit_config conf;
	conf.rate_bps = rate;
	conf.bucket_size = bucket;

	int cfg_fd = bpf_obj_get(PIN_MAP_CFG);
	if (cfg_fd < 0) {
		fprintf(stderr, "无法打开 config_map: %s\n", strerror(errno));
		return 1;
	}

	int err = bpf_map_update_elem(cfg_fd, &cgid, &conf, BPF_ANY);
	if (err) {
		fprintf(stderr, "update config failed: %s\n", strerror(errno));
		close(cfg_fd);
		return 1;
	}
	close(cfg_fd);

	printf("已更新配置：cgroup_id=%llu, rate=%llu, bucket=%llu\n", cgid, rate, bucket);
	return 0;
}

/* 检查 eBPF 程序是否已加载 */
static int is_bpf_program_loaded(void)
{
	// 检查 link 模式（持久化）
	if (access(PIN_LINK_PERSISTENT, F_OK) == 0) {
		return 1;
	}
	
	// 检查 prog_attach 模式（通过检查是否有程序附加到根 cgroup）
	int cg_fd = open_cgroup_fd(ATTACH_POINT);
	if (cg_fd < 0) {
		return 0;
	}
	
	__u32 prog_ids[256] = {0};
	__u32 prog_cnt = 256;
	int ret = bpf_prog_query(cg_fd, BPF_CGROUP_INET_EGRESS, 0, NULL, prog_ids, &prog_cnt);
	close(cg_fd);
	
	// 如果查询成功且有程序附加，说明是 prog_attach 模式
	return (ret == 0 && prog_cnt > 0) ? 1 : 0;
}

/* 检查指定程序 ID 是否有对应的 bpf_link */
static int has_bpf_link(__u32 prog_id)
{
	__u32 link_id = 0;
	int link_fd;
	struct bpf_link_info link_info;
	__u32 info_len = sizeof(link_info);
	
	// 遍历所有 bpf_link
	while (bpf_link_get_next_id(link_id, &link_id) == 0) {
		link_fd = bpf_link_get_fd_by_id(link_id);
		if (link_fd < 0) {
			continue;
		}
		
		// 获取 link 信息
		if (bpf_obj_get_info_by_fd(link_fd, &link_info, &info_len) == 0) {
			if (link_info.prog_id == prog_id) {
				close(link_fd);
				return 1; // 找到对应的 link
			}
		}
		close(link_fd);
	}
	
	return 0; // 没有找到对应的 link
}

/* 获取程序的附加模式信息 */
const char* get_prog_attach_mode(__u32 prog_id)
{
	// 检查是否有对应的 bpf_link
	if (has_bpf_link(prog_id)) {
		return "link";
	}
	
	// 否则是 prog_attach 模式
	return "prog_attach";
}

/* 检查当前附加模式 */
AttachMode get_current_attach_mode(void)
{
	// 检查 link 模式（持久化）- 这是最可靠的检测方法
	if (access(PIN_LINK_PERSISTENT, F_OK) == 0) {
		return ATTACH_MODE_LINK;
	}
	
	// 如果没有 link 文件，检查是否有程序附加到根 cgroup
	int cg_fd = open_cgroup_fd(ATTACH_POINT);
	if (cg_fd < 0) {
		return ATTACH_MODE_LINK; // 默认返回 link 模式
	}
	
	__u32 prog_ids[256] = {0};
	__u32 prog_cnt = 256;
	int ret = bpf_prog_query(cg_fd, BPF_CGROUP_INET_EGRESS, 0, NULL, prog_ids, &prog_cnt);
	close(cg_fd);
	
	// 如果没有 link 文件但有程序附加，检查程序是否有对应的 bpf_link
	if (ret == 0 && prog_cnt > 0) {
		// 检查第一个程序是否有对应的 bpf_link
		if (has_bpf_link(prog_ids[0])) {
			return ATTACH_MODE_LINK; // 有 bpf_link，说明是 link 模式
		} else {
			return ATTACH_MODE_PROG_ATTACH; // 没有 bpf_link，说明是 prog_attach 模式
		}
	}
	
	// 如果没有程序附加，说明没有程序加载，返回默认的 link 模式
	return ATTACH_MODE_LINK;
}

static int get_prog_info_name(int prog_fd, char *name_out, size_t name_sz)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return -1;
	/* 兼容不同内核头：name 通常为 char[BPF_OBJ_NAME_LEN] */
	if (name_out && name_sz > 0) {
		/* 防止未以'\0'结尾的情况，确保安全复制 */
		char tmp[BPF_OBJ_NAME_LEN + 1];
		memcpy(tmp, info.name, BPF_OBJ_NAME_LEN);
		tmp[BPF_OBJ_NAME_LEN] = '\0';
		strncpy(name_out, tmp, name_sz - 1);
		name_out[name_sz - 1] = '\0';
	}
	return 0;
}

//卸载cgroup_path下的limit_egress
int detach_limit_egress(const char *cgroup_path)
{
	if (!cgroup_path) return -1;
	int cg_fd = open_cgroup_fd(cgroup_path);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", cgroup_path, strerror(errno));
		return -1;
	}

	__u32 prog_ids[256] = {0};
	__u32 prog_cnt = 256;
	int err = bpf_prog_query(cg_fd, BPF_CGROUP_INET_EGRESS, 0 /* query_flags */, NULL /* attach_flags_out */, prog_ids, &prog_cnt);
	if (err != 0) {
		fprintf(stderr, "bpf_prog_query failed: %s\n", strerror(errno));
		close(cg_fd);
		return -1;
	}

	int success = 0;
	for (__u32 i = 0; i < prog_cnt; i++) {
		int pfd = bpf_prog_get_fd_by_id(prog_ids[i]);
		if (pfd < 0) continue;
		char pname[BPF_OBJ_NAME_LEN] = {0};
		if (get_prog_info_name(pfd, pname, sizeof(pname)) == 0) {
			if (strcmp(pname, "limit_egress") == 0) {
				if (bpf_prog_detach2(pfd, cg_fd, BPF_CGROUP_INET_EGRESS) != 0) {
					fprintf(stderr, "bpf_prog_detach2 failed for %s: %s\n", cgroup_path, strerror(errno));
				} else {
					success++;
				}
			}
		}
		close(pfd);
	}
	close(cg_fd);
	return success;
}

int bpf_purge_links(void)
{
	int removed_count = 0;
	char link_files[][PATH_MAX] = {PIN_LINK_PERSISTENT };
	
	for (int i = 0; i < 1; i++) {
		if (unlink(link_files[i]) == 0) {
			printf("已取消 BPF 程序链接: %s\n", link_files[i]);
			removed_count++;
		}
	}

	if (removed_count == 0) {
		printf("BPF 程序链接不存在或已取消\n");
	}
	
	return removed_count;
}

int bpf_purge_maps(void)
{
	int removed_count = 0;
	char map_files[][PATH_MAX] = { PIN_MAP_CFG, PIN_MAP_STATE };
	for (int i = 0; i < 2; i++) {
		if (unlink(map_files[i]) == 0) {
			printf("已删除: %s\n", map_files[i]);
			removed_count++;
		}
	}
	printf("已删除 %d 个 pinned BPF maps\n", removed_count);
	return removed_count;
}

int bpf_detach_limit_egress_all(void)
{
	// 首先尝试卸载 link 模式
	int link_result = bpf_detach_link(NULL);
	if (link_result > 0) {
		printf("已卸载 link 模式的程序\n");
		return link_result;
	}
	
	// 如果没有 link 模式，则卸载 prog_attach 模式
	int total = 0;
	int failed = 0;
	int n = detach_limit_egress(MANAGED_ROOT);
	if (n < 0) failed = 1; else total += n;
	DIR *dir = opendir(MANAGED_ROOT);
	if (!dir) return failed ? -1 : total;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;
		char rule_path[PATH_MAX];
		if (SAFE_PATH_JOIN(rule_path, MANAGED_ROOT, entry->d_name) != 0) continue;
		struct stat st;
		if (stat(rule_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
		n = detach_limit_egress(rule_path);
		if (n < 0) failed = 1; else total += n;
	}
	closedir(dir);
	return failed ? -1 : total;
}

/* 协调器函数：根据参数决定执行流程 */
int do_load(const struct LimiterConfig *cfg, const struct LoadOptions *opts, int reload_flag)
{
    int ret = 0;

    unsigned long long cgid = cfg ? cfg->cgid : 0ULL;
    unsigned long long rate = cfg ? cfg->rate_bps : 0ULL;
    unsigned long long bucket = cfg ? cfg->bucket_size : 0ULL;

    /* 场景1：仅更新配置（reload_flag == UPDATE_CONFIG_ONLY） */
    if (reload_flag == UPDATE_CONFIG_ONLY) {
        if (!is_bpf_program_loaded()) {
            fprintf(stderr, "eBPF 程序未加载，无法更新配置\n");
            return 1;
        }
        return do_update_config(cgid, rate, bucket ? bucket : rate);
    }

    /* 场景2：重载程序（reload_flag == RELOAD_PROGRAM） */
    if (reload_flag == RELOAD_PROGRAM) {
        /* 先卸载现有程序 */
        (void)do_unload(0);
        
        ret = do_load_bpf_program(opts);
        if (ret != 0) return ret;

        /* 加载后恢复所有现有配置 */
        do_restore_configs();
        return 0; /* reload 完成，不需要添加新配置 */
    }

    /* 场景3：首次加载或正常加载 */
    int need_load = !is_bpf_program_loaded();
    
    /* 检查是否需要重新加载（附加模式变化） */
    if (!need_load && opts) {
        AttachMode current_mode = get_current_attach_mode();
        if (current_mode != opts->attach_mode) {
            printf("检测到附加模式变化，重新加载程序\n");
            need_load = 1;
        }
    }
    
    if (need_load) {
        ret = do_load_bpf_program(opts);
        if (ret != 0) return ret;

        /* 加载后恢复所有现有配置 */
        do_restore_configs();
    }

    /* 场景4：需要添加新配置 */
    if (rate != 0ULL) {
        ret = do_update_config(cgid, rate, bucket ? bucket : rate);
        if (ret != 0) return ret;
    }

    return 0;
}

/* 卸载单个 BPF 程序 */
static int unload_single_program(__u32 prog_id, const char *prog_name)
{
	// 只处理我们的 limit_egress 程序
	if (strcmp(prog_name, "limit_egress") != 0) {
		return 0;
	}
	
	// 检查程序是否有对应的 bpf_link
	if (has_bpf_link(prog_id)) {
		// 有 link，使用 link 方式卸载
		int result = bpf_detach_link(NULL);
		if (result > 0) {
			printf("已卸载 link 模式的程序 (ID: %u)\n", prog_id);
			return 1;
		}
	} else {
		// 没有 link，使用 prog_attach 方式卸载
		int prog_fd = bpf_prog_get_fd_by_id(prog_id);
		if (prog_fd >= 0) {
			// 尝试从根 cgroup 卸载
			int cg_fd = open_cgroup_fd(ATTACH_POINT);
			if (cg_fd >= 0) {
				int ret = bpf_prog_detach2(prog_fd, cg_fd, BPF_CGROUP_INET_EGRESS);
				close(cg_fd);
				if (ret == 0) {
					printf("已卸载 prog_attach 模式的程序 (ID: %u)\n", prog_id);
					close(prog_fd);
					return 1;
				}
			}
			close(prog_fd);
		}
	}
	
	return 0;
}

/* 卸载 eBPF 程序，不清理数据 */
int do_unload(unsigned long long cgid)
{
	(void)cgid; // 暂时不使用 cgid 参数
	
	int total_detached = 0;
	int failed = 0;
	
	// 遍历所有 BPF 程序，找到 limit_egress 程序并卸载
	__u32 prog_id = 0;
	while (bpf_prog_get_next_id(prog_id, &prog_id) == 0) {
		int prog_fd = bpf_prog_get_fd_by_id(prog_id);
		if (prog_fd < 0) {
			if (errno == ENOENT) {
				continue; // 程序已被删除
			}
			fprintf(stderr, "无法通过ID获取程序 (%u): %s\n", prog_id, strerror(errno));
			failed = 1;
			continue;
		}
		
		// 获取程序信息
		struct bpf_prog_info info = {0};
		__u32 info_len = sizeof(info);
		if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) == 0) {
			int detached = unload_single_program(prog_id, info.name);
			total_detached += detached;
		}
		
		close(prog_fd);
	}
	
	// 清理 maps
	bpf_purge_maps();
	
	if (total_detached > 0) {
		printf("已卸载 %d 个 limit_egress 程序\n", total_detached);
	}
	
	return failed ? -1 : total_detached;
}

