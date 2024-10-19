from pwn import *
context.arch = 'amd64'
context.os = 'linux'

p = process('./main')
p.send(b'')

p.interactive()