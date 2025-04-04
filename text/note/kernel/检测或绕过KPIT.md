# 检测或绕过KPIT

开启了KPIT之后，不能跳转到用户态空间执行 Shellcode

## 检查保护

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

## 绕过保护

### 注册signal

```C
#include <signal.h>
signal(SIGSEGV, dmKernelGetRoot);
```
