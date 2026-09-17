.section .text

.equ USER_DATA_SELECTOR, 0x1b
.equ SYSCALL_CALL_YIELD, 0

.section .text.zigos_syscall_benchmark_user,"ax",@progbits
.global zigos_syscall_benchmark_user_start
.type zigos_syscall_benchmark_user_start, @function
zigos_syscall_benchmark_user_start:
    movl $USER_DATA_SELECTOR, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movq %r12, %r15
.benchmark_dispatch_loop:
    movl $0x10f, %eax
    xorl %edi, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    syscall
    decq %r15
    jne .benchmark_dispatch_loop

    movq %r13, %rdi
    movl $SYSCALL_CALL_YIELD, %eax
    syscall
    ud2
.global zigos_syscall_benchmark_user_end
zigos_syscall_benchmark_user_end:

.section .note.GNU-stack,"",@progbits
