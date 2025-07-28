from pwn import *

def decrypt(cipher):
    '''
        解密堆指针, 适用于tcache bin和fast bin
        
        cipher: 密文指针
        返回: 明文指针
        
        实例:
            fd = decrypt(fd)
    '''
    key = 0
    plain = 0

    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12

    return plain