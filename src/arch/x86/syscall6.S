.globl syscall6_asm
.type syscall6_asm, @function
syscall6_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    mov 16(%ebp), %ecx
    mov 20(%ebp), %edx
    mov 24(%ebp), %esi
    mov 28(%ebp), %edi
    mov 32(%ebp), %ebp
    int $0x80

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret
