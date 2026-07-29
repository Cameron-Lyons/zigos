.section .text

.globl syscall3_asm
.type syscall3_asm, @function
syscall3_asm:
    mov $1, %eax
    syscall
    ret

.globl syscall_yield_asm
.type syscall_yield_asm, @function
syscall_yield_asm:
    xor %eax, %eax
    syscall
    ret

.section .note.GNU-stack,"",@progbits
