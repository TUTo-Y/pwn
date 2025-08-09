# 特殊gadget

## _do_global_dtors_aux的gadget
`_do_global_dtors_aux` 有个 `gadget` 为:

```asm
.text:0000000000400542 C6 05 DF 0A 20 00 01 mov cs:completed_7698, 1
.text:0000000000400549 5D                   pop rbp
.text:000000000040054A C3                   retn
```

将其错位可以得到

```asm
0x400548 (__do_global_dtors_aux+24) ◂— add dword ptr [rbp - 0x3d], ebx
0x400550 (__do_global_dtors_aux+32) ◂— repz ret
```