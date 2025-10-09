#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef D64
#include "sandbox64.h"
#pragma message("Compiling for 64-bit")
#elif D32
#include "sandbox32.h"
#pragma message("Compiling for 32-bit")
#endif

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    void *buf = mmap((void*)0x10000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    putchar('>');
    read(0, buf, 0x1000);

    install_seccomp();
    
    ((void(*)())buf)();

    return 0;
}