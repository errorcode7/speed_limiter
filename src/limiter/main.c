#include "cli.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	/* 首先尝试便捷模式 */
	int ret = parse_convenient_args(argc, argv);
	if (ret != -1) {
		return ret; /* 便捷模式处理完成 */
	}
	
	/* 如果不是便捷模式，则使用高级模式 */
	return parse_advanced_args(argc, argv);
}
