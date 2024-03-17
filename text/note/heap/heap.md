- [内存管理器(ptmalloc)的学习](#内存管理器ptmalloc的学习)
  - [chunk的具体实现](#chunk的具体实现)
  - [堆空闲管理结构(bins)](#堆空闲管理结构bins)
    - [fast bin](#fast-bin)
    - [small bin](#small-bin)
    - [large bin](#large-bin)
    - [unsorted bin](#unsorted-bin)
    - [tcache bin( \>=glibc 2.26 )](#tcache-bin-glibc-226-)
    - [top chunk](#top-chunk)
    - [last remainder](#last-remainder)


#   内存管理器(ptmalloc)的学习
##  chunk的具体实现
```C
# define INTERNAL_SIZE_T size_t
struct malloc_chunk {

    INTERNAL_SIZE_T      mchunk_prev_size;    // 如果前面一个物理相邻的chunk是空闲的, 则表示其大小, 否则用于储存前一个chunk的数据
    INTERNAL_SIZE_T      mchunk_size;         // 当前chunk的大小, 低三位作为flag, 意义如下:
    /*
        A : 倒数第三位表示当前chunk是否属于主线程:1表示不属于主线程, 0表示属于主线程
        M : 倒数第二位表示当前chunk是从mmap(1)[多线程]分配的，还是从brk(0)[子线程]分配的
        P : 最低为表示前一个chunk是否在使用中, 1表示在使用, 0表示是空闲的
            通常堆中的第一个chunk的P位是1, 以便于防止访问前面的非法内存
    */

    /*
        1.用户使用的内存从这里开始分配
        3.只有在free之后, 以下数据才有效
    */
    struct malloc_chunk* fd;            // 当chunk空闲时才有意义,记录后一个空闲chunk的地址
    struct malloc_chunk* bk;            // 同上,记录前一个空闲chunk的地址

    /* 仅用于largebin */
    struct malloc_chunk* fd_nextsize;   // 指向比当前chunk大的第一个空闲chunk
    struct malloc_chunk* bk_nextsize;   // 指向比当前chunk小的第一个空闲chunk
};
```
`chunk`的大小必须是`2 * SIZE_SZ`的整数倍
*  __32位下__:`SIZE_SZ = 4`, 因此堆大小为`0x8`的整数倍, 最小堆块为`0x10`
*  __64位下__:`SIZE_SZ = 8`, 因此堆大小为`0x10`的整数倍, 最小堆块为`0x20`

##  堆空闲管理结构(bins)
每类`bin`的内部会有多个互不相关的链表来保存 __不同大小__ 的`chunk`
其中，对于`small bin``large bin``unsorted bin`, ptmalloc将其维护在`malloc_state`结构的同一个数组中:
```C
#define NBINS 128
mchunkptr bins[NBINS * 2 - 2];
```
每个双向链表需要占用 __两个索引__
*   第`0`个索引未被使用
*   第`1`个索引存放`unsorted bin`
*   第`2 ~ 63`个索引存放`small bin`, 因此`small bin`一共有`62`条双向链表
*   剩下的索引存放`large bin`, 因此`large bin`一共有`63`条双向链表

### fast bin
32位下存放`0x10 ~ 0x40`字节的堆块
64位下存放`0x20 ~ 0x80`字节的堆块
`fast bin`按单链表结构, `fd`指向下一堆块, 采用`LIFO`机制
防止释放时对`fast bin`合并, 下一堆块的p标志位为`1`

### small bin
双向链表, 采用FIFO策略
一共有`62`条双向链表

### large bin
双向链表, 采用FIFO策略
`large bins`中一共包括`63`个`bin`, 每个`bin`中的`chunk`的大小不一致, 处于一定区间范围内

### unsorted bin
双向链表, 采用FIFO策略
`free`的`chunk`大小如果大于`0x80`(64位下), 并且不与`top chunk`相连, 则会放到`unsorted bin`上
当一个`chunk`被分割后, 如果剩下的部分大于`MINSIZE`, 也会被放到`unsorted bin`中

### tcache bin( >=glibc 2.26 )
`tcache`是一个线程特定的数据结构, 每个线程都有自己的`tcache`, 它包含了一组`tcache bin`
使用`export GLIBC_TUNABLES=glibc.malloc.tcache_count=0`禁用`tcache`
*   `tcache`的两个重要的结构体如下:
```C
# define TCACHE_MAX_BINS 64
// 链接空闲的chunk结构体
typedef struct tcache_entry
{
    // next指向下一个具有相同大小的chunk
    // 与fast bin不同的是, chunk的fd指向的是下一个chunk的data部分
    struct tcache_entry *next;
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

### top chunk
`prev_inuse`比特位始终为`1`

### last remainder
堆块切割后, 剩下的小于`MINSIZE`的部分
