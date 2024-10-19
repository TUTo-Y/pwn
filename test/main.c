#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main()
{
    // 使用mmap分配一块可读、可写、可执行的内存
    void *mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // 写入一段汇编代码
    read(0, mem, 0x100);

    // 执行这段代码
    ((void (*)())mem)();

    return 0;
}