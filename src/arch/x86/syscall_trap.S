.section .text

.globl syscall3_asm
.type syscall3_asm, @function
syscall3_asm:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    mov %r8, %r9
    syscall
    mov %eax, 0(%r9)
    mov %edx, 4(%r9)
    mov %r10w, 8(%r9)
    ret

.globl syscall_register_ipc_asm
.type syscall_register_ipc_asm, @function
syscall_register_ipc_asm:
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsi, %rbx
    movq 0(%rdi), %rax
    btsq $31, %rax
    movq 8(%rdi), %rdx
    movq 16(%rdi), %r10
    movq 24(%rdi), %r8
    movq 32(%rdi), %r9
    movq 40(%rdi), %rsi
    movq 48(%rdi), %r14
    movq 56(%rdi), %r15
    xorl %edi, %edi
    syscall
    movl %eax, 0(%rbx)
    movl %edx, 4(%rbx)
    movw %r10w, 8(%rbx)
    movq %r8, 16(%rbx)
    movq %rdi, 24(%rbx)
    movq %rsi, 32(%rbx)
    movq %r14, 40(%rbx)
    movq %r15, 48(%rbx)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    ret

.globl syscall_yield_asm
.type syscall_yield_asm, @function
syscall_yield_asm:
    xor %eax, %eax
    syscall
    ret

.section .note.GNU-stack,"",@progbits
