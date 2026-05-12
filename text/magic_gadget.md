- [magic\_gadget](#magic_gadget)
  - [特殊gadget](#特殊gadget)
    - [add \[rbp-3Dh\], ebx; ret](#add-rbp-3dh-ebx-ret)
    - [add bl, dh; ...; pop rbp; ret](#add-bl-dh--pop-rbp-ret)
    - [adc edx, dword ptr \[rbp + 0x48\]](#adc-edx-dword-ptr-rbp--0x48)
  - [快速找到gadget](#快速找到gadget)
    - [模板](#模板)

# magic_gadget

## 特殊gadget

### add [rbp-3Dh], ebx; ret

在`_do_global_dtors_aux`函数中，存在如下指令:

```asm
0x401196 C6 05 EB 2E 00 00 01   mov     cs:completed_0, 1
0x40119D 5D                     pop     rbp
0x40119E C3                     retn
```

将其错位可以得到如下指令:

```asm
0x40119C 01 5D C3   add [rbp-3Dh], ebx
0x40119F 90         nop
0x4011A0 C3         retn
```

### add bl, dh; ...; pop rbp; ret

在`_do_global_dtors_aux`函数末尾，存在如下指令:

```asm
0x4011A1 66 66 2E 0F 1F 84 00 00 00 00…   align 10h
```

将其错位可以得到如下指令:

```asm
0x4011AF 00 F3      add bl, dh
```

### adc edx, dword ptr [rbp + 0x48]

在`_do_global_dtors_aux`函数末尾，存在如下指令:

```asm
0x40118B 75 13              jnz     short locret_4011A0
0x40118D 55                 push    rbp
0x40118E 48 89 E5           mov     rbp, rsp
0x401191 E8 7A FF FF FF     call    deregister_tm_clones
```

将其错位可以得到如下指令:

```asm
.text:000000000040118C 13 55 48                                      adc     edx, [rbp+48h]
.text:000000000040118F 89 E5                                         mov     ebp, esp
.text:0000000000401191 E8 7A FF FF FF                                call    deregister_tm_clones
.text:0000000000401196 C6 05 EB 2E 00 00 01                          mov     cs:completed_0, 1
.text:000000000040119D 5D                                            pop     rbp
.text:000000000040119E C3                                            retn
```

## 快速找到gadget

### 模板

```python
magic_gadget = 0x40119C # add [rbp-3Dh], ebx; ret
magic_gadget2 = magic_gadget+0x13 # add bl, dh; ...; pop rbp; ret
magic_gadget3 = magic_gadget-0x10 # adc edx, dword ptr [rbp + 0x48]
```
