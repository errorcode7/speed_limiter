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
#include "managed.h"
#include "cgroup.h"

/* 重载标志定义 */
#define UPDATE_CONFIG_ONLY 1
#define RELOAD_PROGRAM 2

/* 前置声明，确保在严格编译下无隐式声明 */
unsigned long long get_cgroup_id(const char *cgroup_path);

/* 加载 eBPF 程序并固定到文件系统 */
static int do_load_bpf_program(const char *bpf_obj_path)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	int root_fd = -1;

	// 1. 创建 bpffs 目录
	char pin_dir[PATH_MAX];
	char pin_path[PATH_MAX];
	strncpy(pin_dir, "/sys/fs/bpf/speed_limiter", sizeof(pin_dir));
	if (ensure_dir("/sys/fs/bpf", 0755) == 0) {
		ensure_dir(pin_dir, 0755);
	}

	int n = snprintf(pin_path, sizeof(pin_path), "%s/cg_root_egress", pin_dir);
	if (n < 0 || (size_t)n >= sizeof(pin_path)) {
		fprintf(stderr, "pin 路径过长: base=%s root\n", pin_dir);
		return 1;
	}

	// 2. 加载 eBPF 对象
	obj = bpf_object__open_file(bpf_obj_path, NULL);
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
	prog = bpf_object__find_program_by_name(obj, "limit_egress");
	if (!prog) {
		fprintf(stderr, "program 'limit_egress' not found\n");
		bpf_object__close(obj);
		return 1;
	}

	// 4. 确保托管 cgroup 根目录存在
	if (ensure_dir(MANAGED_CGROUP_ROOT, 0755) != 0) {
		fprintf(stderr, "无法创建托管 cgroup 目录: %s\n", MANAGED_CGROUP_ROOT);
		bpf_object__close(obj);
		return 1;
	}

	// 5. 附加程序到父 cgroup
	root_fd = open_cgroup_fd(MANAGED_CGROUP_ROOT);
	if (root_fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", MANAGED_CGROUP_ROOT, strerror(errno));
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_link *link = bpf_program__attach_cgroup(prog, root_fd);
	if (!link) {
		fprintf(stderr, "attach program failed\n");
		close(root_fd);
		bpf_object__close(obj);
		return 1;
	}

	// 6. 固定 link
	(void)unlink("/sys/fs/bpf/speed_limiter/cg_root_egress"); // 忽略不存在的错误
	if (bpf_link__pin(link, pin_path) != 0) {
		fprintf(stderr, "warning: 无法固定链接到 %s（可能未挂载 bpffs）\n", pin_path);
	}

	// 7. 固定 map
	struct bpf_map *pm;
	pm = bpf_object__find_map_by_name(obj, "rate_limit_config_map");
	if (pm) {
		(void)unlink("/sys/fs/bpf/speed_limiter/rate_limit_config_map");
		if (bpf_map__pin(pm, "/sys/fs/bpf/speed_limiter/rate_limit_config_map") != 0 && errno != EEXIST) {
			fprintf(stderr, "warning: 无法固定 config_map: %s\n", strerror(errno));
		}
	}
	pm = bpf_object__find_map_by_name(obj, "rate_limit_state_map");
	if (pm) {
		(void)unlink("/sys/fs/bpf/speed_limiter/rate_limit_state_map");
		if (bpf_map__pin(pm, "/sys/fs/bpf/speed_limiter/rate_limit_state_map") != 0 && errno != EEXIST) {
			fprintf(stderr, "warning: 无法固定 state_map: %s\n", strerror(errno));
		}
	}

	close(root_fd);
	bpf_object__close(obj);
	printf("eBPF 程序已加载并固定\n");
	return 0;
}

/* 从托管目录恢复所有配置到 config_map */
static int do_restore_configs(void)
{
	int cfg_fd = bpf_obj_get("/sys/fs/bpf/speed_limiter/rate_limit_config_map");
	if (cfg_fd < 0) {
		fprintf(stderr, "无法打开 config_map: %s\n", strerror(errno));
		return -1;
	}

	DIR *dir = opendir(MANAGED_CGROUP_ROOT);
	if (!dir) {
		fprintf(stderr, "无法打开托管目录: %s\n", MANAGED_CGROUP_ROOT);
		close(cfg_fd);
		return -1;
	}
	
	struct dirent *entry;
	int restored = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') continue;
		
		char rule_path[PATH_MAX];
		snprintf(rule_path, sizeof(rule_path), "%s/%s", MANAGED_CGROUP_ROOT, entry->d_name);
		
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
static int do_update_config(unsigned long long cgid, const char *rate_str, const char *bucket_str)
{
	unsigned long long rate = 0ULL, bucket = 0ULL;
	if (rate_str && rate_str[0] != '\0') rate = strtoull(rate_str, NULL, 10);
	if (bucket_str && bucket_str[0] != '\0') bucket = strtoull(bucket_str, NULL, 10);
	if (bucket == 0ULL) bucket = rate; /* 默认桶大小等于速率 */

	if (rate == 0ULL || bucket == 0ULL) {
		fprintf(stderr, "无效的配置参数: rate=%llu, bucket=%llu\n", rate, bucket);
		return 1;
	}

	struct rate_limit_config conf;
	conf.rate_bps = rate;
	conf.bucket_size = bucket;

	int cfg_fd = bpf_obj_get("/sys/fs/bpf/speed_limiter/rate_limit_config_map");
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
	return (access("/sys/fs/bpf/speed_limiter/cg_root_egress", F_OK) == 0);
}

/* 协调器函数：根据参数决定执行流程 */
int do_load(unsigned long long cgid, const char *rate_str,
            const char *bucket_str, const char *bpf_obj_path, int reload_flag)
{
	int ret = 0;

	/* 场景1：仅更新配置（reload_flag == UPDATE_CONFIG_ONLY） */
	if (reload_flag == UPDATE_CONFIG_ONLY) {
		if (!is_bpf_program_loaded()) {
			fprintf(stderr, "eBPF 程序未加载，无法更新配置\n");
			return 1;
		}
		return do_update_config(cgid, rate_str, bucket_str);
	}

	/* 场景2：重载程序（reload_flag == RELOAD_PROGRAM） */
	if (reload_flag == RELOAD_PROGRAM) {
		ret = do_load_bpf_program(bpf_obj_path);
		if (ret != 0) return ret;

		/* 加载后恢复所有现有配置 */
		do_restore_configs();
		return 0; /* reload 完成，不需要添加新配置 */
	}

	/* 场景3：首次加载或正常加载 */
	int need_load = !is_bpf_program_loaded();
	if (need_load) {
		ret = do_load_bpf_program(bpf_obj_path);
		if (ret != 0) return ret;

		/* 加载后恢复所有现有配置 */
		do_restore_configs();
	}

	/* 场景4：需要添加新配置 */
	if (rate_str && bucket_str) {
		ret = do_update_config(cgid, rate_str, bucket_str);
		if (ret != 0) return ret;
	}

	return 0;
}

/* 卸载 eBPF 程序 */
int do_unload(unsigned long long cgid)
{
	char pin_path[PATH_MAX];
	snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/speed_limiter/cg_root_egress");
	if (unlink(pin_path) != 0) {
		fprintf(stderr, "卸载失败：无法移除 pin %s: %s\n", pin_path, strerror(errno));
		return 1;
	}
	printf("已卸载并移除 pin: %s\n", pin_path);
	return 0;
}

/* 列出 eBPF 状态 */
int do_list(void)
{
	int cfg_fd = bpf_obj_get("/sys/fs/bpf/speed_limiter/rate_limit_config_map");
	int st_fd  = bpf_obj_get("/sys/fs/bpf/speed_limiter/rate_limit_state_map");
	if (cfg_fd < 0 || st_fd < 0) {
		fprintf(stderr, "无法打开已固定的 map: config/state\n");
		if (cfg_fd >= 0) close(cfg_fd);
		if (st_fd >= 0) close(st_fd);
		return 1;
	}
	__u64 key = 0, next_key;
	struct rate_limit_config conf;
	struct rate_limit_state st;
	int has_key = 0;
	if (bpf_map_get_next_key(cfg_fd, NULL, &key) == 0) has_key = 1;
	while (has_key) {
		int has_conf = (bpf_map_lookup_elem(cfg_fd, &key, &conf) == 0);
		int has_st = (bpf_map_lookup_elem(st_fd, &key, &st) == 0);
		if (has_conf || has_st) {
			printf("cgroup_id=%llu rate_bps=%llu bucket=%llu tokens=%s last_update_ns=%s\n",
			       (unsigned long long)key,
			       has_conf ? (unsigned long long)conf.rate_bps : 0ULL,
			       has_conf ? (unsigned long long)conf.bucket_size : 0ULL,
			       has_st ? ({ static char buf[32]; snprintf(buf, sizeof(buf), "%llu", (unsigned long long)st.tokens); buf; }) : "-",
			       has_st ? ({ static char buf2[32]; snprintf(buf2, sizeof(buf2), "%llu", (unsigned long long)st.last_update_ns); buf2; }) : "-");
		}
		if (bpf_map_get_next_key(cfg_fd, &key, &next_key) != 0) break;
		key = next_key;
	}
	close(cfg_fd);
	close(st_fd);
	return 0;
}

