'''
    基础数据和操作
'''
from pwn import *
from struct import pack

s64 = lambda x: struct.pack('<Q', x)
s32 = lambda x: struct.pack('<I', x)
BINSH = u64(b'/bin/sh\x00')
SH    = u64(b'$0\x00'.ljust(8, b'\x00'))

# 获取泄露的地址
getaddr_ptr     = lambda p: int(str(p.recv(14)), 16)
getaddr_byte6   = lambda p: u64(p.recv(6).ljust(8, b'\x00'))

# 打印地址
msg = lambda str, addr: print(str + "的地址为: " + hex(addr))

# 发送数字
send_num = lambda p, num, size: p.send(bytes(str(num), 'utf-8').ljust(size, b'\x00'))

# 设置payload
def set_bytes(payload, offset, byte):
    '''
        payload: 要写入的payload
        offset: 偏移
        byte: 要写入的字节
    '''
    if payload is None:
        payload = b''
    if len(payload) < offset+len(byte):
        payload = payload.ljust(offset+len(byte), b'\x00')
    return payload[:offset] + byte + payload[offset+len(byte):]

def set_value(payload, offset, value, fill = b'\x00'):
    '''
        payload: 要写入的payload
        offset: 偏移
        value: 要写入的值
        fill: 填充字符
    '''
    if payload is None:
        payload = b''
    if len(payload) < offset+8:
        payload = payload.ljust(offset+8, fill)
    return payload[:offset] + p64(value) + payload[offset+8:]
def set_value32(payload, offset, value, fill = b'\x00'):
    '''
        payload: 要写入的payload
        offset: 偏移
        value: 要写入的值
        fill: 填充字符
    '''
    if payload is None:
        payload = b''
    if len(payload) < offset+4:
        payload = payload.ljust(offset+4, fill)
    return payload[:offset] + p32(value) + payload[offset+4:]
