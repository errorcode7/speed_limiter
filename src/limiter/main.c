#include "cli.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	/* 解析命令行参数 */
	int ret = parse_convenient_args(argc, argv);
	if (ret != -1) {
		return ret; /* 处理完成 */
	}

	/* 如果没有匹配的命令，显示帮助信息 */
	print_usage(stderr);
	return 1;
}
