from demo import *
p = process('./boot.sh')

kernel_musl()
kernel_exploit_file(p, prompt=' $', run=True)

p.interactive()