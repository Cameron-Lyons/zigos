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

.globl syscall_yield_asm
.type syscall_yield_asm, @function
syscall_yield_asm:
    # The public C ABI carries a u32 counter and a u32 disposition, whose
    # upper register bits are not arguments, plus the u64 UI revision in rdx.
    # Raw SYSCALL callers remain subject to kernel validation.
    movl %edi, %edi
    movl %esi, %esi
    xor %eax, %eax
    syscall
    ret

.section .note.GNU-stack,"",@progbits
