;编译:
;nasm -f elf64 sh.nasm -o sh.o
;ld sh.o -o sh

section .data
    args db '/bin/sh', 0
    argv dq args, 0

section .text
    global _start

_start:
    ; 设置GID为0
    xor rdi, rdi
    xor rsi, rsi
    mov eax, 106  ; setregid
    syscall

    ; 设置UID为0
    xor rdi, rdi
    xor rsi, rsi
    mov eax, 113  ; setreuid
    syscall

    ; 执行 /bin/sh
    lea rdi, [rel args]
    lea rsi, [rel argv]
    xor rax, rax
    mov al, 59    ; execve
    syscall

    ; 如果 execve 失败，退出程序
    mov eax, 60   ; exit
    xor edi, edi
    syscall
