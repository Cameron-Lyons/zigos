.section .text.zigos_syscall_benchmark_user,"ax",@progbits
.global zigos_syscall_benchmark_user_start
.type zigos_syscall_benchmark_user_start, @function
zigos_syscall_benchmark_user_start:
    movl $0x1b, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movq %r12, %r15
.benchmark_dispatch_loop:
    movl $1, %eax
    xorl %edi, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    syscall
    decq %r15
    jne .benchmark_dispatch_loop

    movq %r13, %rdi
    movl $0, %eax
    syscall
    ud2
.global zigos_syscall_benchmark_user_end
zigos_syscall_benchmark_user_end:

.section .note.GNU-stack,"",@progbits
