# 绕过SMEP或SMAP

在未开启smep/smap保护之前可以使用ret2user将rop部署在用户空间

但是当开启了KPIT保护，则无法再使用ret2user

## 保护

__smep__ : 用户代码不可执行, CR4 寄存器中的第 20 位用来标记是否开启 SMEP 保护。
__smap__ : 用户数据不可访问, CR4 寄存器中的第 21 位用来标记是否开启 SMEP 保护。

## 检查保护

默认情况下，`SMEP/SMAP` 保护是开启的。

通过如下命令可以检查 `SMEP` 是否开启，如果发现了 `smep` 或 `smap` 字符串就说明开启了 `smep` 或 `smap` 保护，否则没有开启。

```bash
grep smep /proc/cpuinfo
```

或者通过gdb查看rc4寄存器检查是否关闭保护

```gdb
p $cr4
```

## 启用和关闭保护

如果是使用 `qemu` 启动的内核，我们可以在 `-append` 选项中添加 `+smep +smap` 或者 `nosmep nosmap` 来开启或关闭 `SMEP/SMAP`

在 QEMU 启动参数中，我们可以为 CPU 参数加上 `-smep,-smap` 或 `+smep,+smap` 以显式关闭或启用 SMEP和SMAP 保护，例如：

```bash
#!/bin/sh
qemu-system-x86_64 \
    -enable-kvm \
    -cpu host,-smep,-smap \
```

## 绕过保护

设置`cr4`寄存器 为 `0x6f0`即可关闭保护
