//chunk的具体实现
// mchunk_prev_size和mchunk_size组成了堆头
struct malloc_chunk
{
    INTERNAL_SIZE_T mchunk_prev_size;  // 如果前面一个物理相邻的堆块是空闲的, 则表示其大小, 否则用于储存前一个堆块的数据
    INTERNAL_SIZE_T mchunk_size;       // 当前chunk的大小, 低三位作为flag, 意义如下:
    /*
        A : 倒数第三位表示当前chunk是否属于主线程:1表示不属于主线程, 0表示属于主线程
        M : 倒数第二位表示当前chunk是从mmap(1)[多线程]分配的，还是从brk(0)[子线程]分配的
        P : 最低为表示前一个chunk是否在使用中, 1表示在使用, 0表示是空闲的
            通常堆中的第一个堆块的P位是1, 以便于防止访问前面的非法内存
    */

    /*
        1.真正的内存从这里开始分配
        2.malloc之后这些指针没有用,这时存放的是数据
        3.只有在free之后才有效。
    */
 
    struct  malloc_chunk*   fd;             // 当chunk空闲时才有意义,记录后一个空闲chunk的地址
    struct  malloc_chunk*   bk;             // 同上,记录前一个空闲chunk的地址
 
    /* 仅用于较大的块 */
    struct  malloc_chunk*   fd_nextsize;    // 当前chunk为largebin时才有意义，指向比当前chunk大的第一个空闲chunk
    struct  malloc_chunk*   bk_nextsize;    // 指向比当前chunk小的第一个空闲堆块
};

last remainder chunk
    表示分割原chunk后剩余的部分

bin
    管理arena中空闲chunk的结构, 以数值的形式存在,
    数字元素为相应大小的chunk链表的表头
    存放于arena的malloc_state
    {
        unsorted bin
        fast bins
        small bins
        large bins
        tcache(glibc-2.26)
    }

fastbins
    64位:小于80等于字节的堆块
unsorted bin
    刚刚释放出来还未分类的chunk
small bins
    双向链表