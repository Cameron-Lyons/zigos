.section .text

.globl syscall3_asm
.type syscall3_asm, @function
syscall3_asm:
#if defined(__x86_64__)
    push %rbx
    mov %rdi, %rax
    mov %rsi, %rbx
    mov %rdx, %rcx
#else
    push %ebx
    mov 8(%esp), %eax
    mov 12(%esp), %ebx
    mov 16(%esp), %ecx
#endif
    int $0x80
#if defined(__x86_64__)
    pop %rbx
#else
    pop %ebx
#endif
    ret

.section .note.GNU-stack,"",@progbits
