# 检测或绕过KPIT

开启了`KPIT`之后，内核空间与用户空间分别使用两组不同的页表集，内核页表中属于用户地址空间的部分不再拥有执行权限

开启了`KPIT`之后，将无法再使用`ret2user`

开启了`KPIT`之后，在从内核返回到用户态需要做页表切换

## 检查是否开启KPIT保护

在root下通过命令`dmesg | grep 'page table'`和`cat /proc/cpuinfo | grep pti`来检查是否开启了KPIT保护

```sh
~ # dmesg | grep 'page table'
[    0.061340] Kernel/User page tables isolation: enabled
[    1.244963] x86/mm: Checking user space page tables
~ # cat /proc/cpuinfo | grep pti
fpu_exception   : yes
flags           : fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc nopl xtopology cpuid pni cx16 hypervisor pti smep smap
fpu_exception   : yes
flags           : fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx lm constant_tsc nopl xtopology cpuid pni cx16 hypervisor pti smep smap
```

## 启用KPTI保护

在`qemu`启动脚本中的`-append`选项中添加`pti=on`

## 绕过保护

### 注册signal (__推荐__)

在内核ROP之前，在用户态设置信号处理函数

```C
#include <signal.h>
signal(SIGSEGV, kernel_shell);
```

### 切换页表

原有的ROP切换为用户态时，还是使用的内核态的页表(无法执行用户内存中的代码)，需要手动切换成用户态页表

1. 在root模式下执行`cat /proc/kallsyms | grep swapgs_restore_regs_and_return_to_usermode` 获取`swapgs_restore_regs_and_return_to_usermode`地址
2. 使用`objdump -d --start-address=0xFFFFFFFF81A008DA ./vmlinux | head -n 32`找到`mov    %rsp,%rdi`那一行地址(使用IDA也行), 即为我们的切换页表地址
3. 重新布置栈如下:

```
swapgs_restore_regs_and_return_to_usermode
0
0
user_shell_addr
user_cs
user_rflags
user_sp
user_ss
```