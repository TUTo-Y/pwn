'''
    基础数据和操作
'''
from pwn import *
from struct import pack

s64 = lambda x: struct.pack('<Q', x)
s32 = lambda x: struct.pack('<I', x)
BINSH = u64(b'/bin/sh\x00')

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

# def set_value(payload, offset, value, fill = b'\x00'):
#     '''
#         payload: 要写入的payload
#         offset: 偏移
#         value: 要写入的值
#         fill: 填充字符
#     '''
#     return payload.ljust(offset, fill) + p64(value)

# def set_value32(payload, offset, value, fill = b'\x00'):
#     '''
#         payload: 要写入的payload
#         offset: 偏移
#         value: 要写入的值
#         fill: 填充字符
#     '''
#     return payload.ljust(offset, fill) + p32(value)