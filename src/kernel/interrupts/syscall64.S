.section .text

.extern isrHandler
.extern syscall_handler
.extern zigos_userspace_resume_requested
.extern zigos_resume_from_userspace_interrupt

.equ SYSCALL_CALL_YIELD, 0
.equ SYSCALL_CALL_DISPATCH, 1
.equ SYSCALL_VECTOR, 128
.equ USERSPACE_YIELD_VECTOR, 129
.equ USER_DATA_SELECTOR, 0x1b
.equ USER_CODE_SELECTOR, 0x23
.equ CPU_KERNEL_STACK_TOP, 0
.equ CPU_USER_STACK_POINTER, 8
.equ XSAVE_BYTES, 576
.equ XSAVE_ALIGN_SLACK, 64
.equ XCOMP_BV, 0x8000000000000003

.macro SAVE_REGISTERS
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq $0
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq $0
.endm

.macro RESTORE_REGISTERS
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    addq $8, %rsp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
.endm

.global zigos_syscall_entry
.type zigos_syscall_entry, @function
zigos_syscall_entry:
    # endbr64
    .byte 0xf3, 0x0f, 0x1e, 0xfa
    swapgs
    movq %rsp, %gs:CPU_USER_STACK_POINTER
    movq %gs:CPU_KERNEL_STACK_TOP, %rsp
    testq %rsp, %rsp
    jz .invalid_kernel_stack

    pushq $USER_DATA_SELECTOR
    pushq %gs:CPU_USER_STACK_POINTER
    pushq %r11
    pushq $USER_CODE_SELECTOR
    pushq %rcx
    pushq $0

    cmpq $SYSCALL_CALL_YIELD, %rax
    je .yield_entry
    cmpq $SYSCALL_CALL_DISPATCH, %rax
    je .dispatch_entry
    xorq %rdi, %rdi

.dispatch_entry:
    pushq $SYSCALL_VECTOR
    jmp .save_and_dispatch

.yield_entry:
    movq %rdi, %rax
    pushq $USERSPACE_YIELD_VECTOR

.save_and_dispatch:
    SAVE_REGISTERS
    movq %rsp, %r12
    subq $(XSAVE_BYTES + XSAVE_ALIGN_SLACK), %rsp
    andq $-64, %rsp
    leaq 512(%rsp), %rdi
    xorl %eax, %eax
    movl $8, %ecx
    rep stosq
    movabsq $XCOMP_BV, %rax
    movq %rax, 520(%rsp)
    movl $3, %eax
    xorl %edx, %edx
    # xsaves (%rsp)
    .byte 0x48, 0x0f, 0xc7, 0x2c, 0x24
    cld
    movq %r12, %rdi

    cmpq $SYSCALL_VECTOR, 136(%r12)
    jne .handle_userspace_yield
    call syscall_handler
    jmp .dispatch_complete

.handle_userspace_yield:
    call isrHandler

.dispatch_complete:
    movl $3, %eax
    xorl %edx, %edx
    # xrstors (%rsp)
    .byte 0x48, 0x0f, 0xc7, 0x1c, 0x24
    movq %r12, %rsp
    cmpl $0, zigos_userspace_resume_requested(%rip)
    jne .userspace_resume

    RESTORE_REGISTERS
    movq 16(%rsp), %rcx
    movq 32(%rsp), %r11
    swapgs
    movq 40(%rsp), %rsp
    sysretq

.userspace_resume:
    swapgs
    jmp zigos_resume_from_userspace_interrupt

.invalid_kernel_stack:
    ud2

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
    movl $SYSCALL_CALL_DISPATCH, %eax
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
