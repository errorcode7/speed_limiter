#ifndef CLI_H
#define CLI_H

#include <stdio.h>

/* 打印使用说明 */
void print_usage(FILE *out);

/* 解析便捷模式参数 */
int parse_convenient_args(int argc, char **argv);

/* 解析高级模式参数 */
int parse_advanced_args(int argc, char **argv);

#endif /* CLI_H */
