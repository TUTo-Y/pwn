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
