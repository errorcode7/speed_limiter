#ifndef BPF_H
#define BPF_H

/* 加载 eBPF 程序并设置限速规则 */
int do_load(unsigned long long cgid, const char *rate_str, 
            const char *bucket_str, const char *bpf_obj_path, int reload_flag);

/* 卸载 eBPF 程序 */
int do_unload(unsigned long long cgid);

/* 列出 eBPF 状态 */
int do_list(void);


#endif /* BPF_H */
