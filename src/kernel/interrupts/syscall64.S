#include "../../arch/xstate64.inc"
.section .text

.extern isrHandler
.extern syscall_handler
.extern zigos_userspace_resume_requested
.extern zigos_userspace_resume_eip
.extern zigos_resume_from_userspace_interrupt

.equ SYSCALL_CALL_YIELD, 0
.equ SYSCALL_VECTOR, 128
.equ USERSPACE_YIELD_VECTOR, 129
.equ USER_DATA_SELECTOR, 0x1b
.equ USER_CODE_SELECTOR, 0x23
.equ CPU_KERNEL_STACK_TOP, 0
.equ CPU_USER_STACK_POINTER, 8

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
    # %rax is the native operation. %rdi stays the request pointer, matching FRED.
    pushq $SYSCALL_VECTOR
    jmp .save_and_dispatch

.yield_entry:
    movq %rdi, %rax
    pushq $USERSPACE_YIELD_VECTOR

.save_and_dispatch:
    SAVE_REGISTERS
    movq %rsp, %r12
    ENTER_KERNEL_XSTATE 160
    movq %r12, %rdi
    cmpq $SYSCALL_VECTOR, 136(%r12)
    jne .yield_dispatch
    call syscall_handler
    jmp .dispatch_complete
.yield_dispatch:
    call isrHandler
.dispatch_complete:
    cmpl $0, zigos_userspace_resume_requested(%rip)
    je .restore_user_xstate
    cmpq $0, zigos_userspace_resume_eip(%rip)
    jne .userspace_resume
.restore_user_xstate:
    LEAVE_KERNEL_XSTATE 160

.sysret:
    RESTORE_REGISTERS
    movq 16(%rsp), %rcx
    movq 32(%rsp), %r11
    swapgs
    movq 40(%rsp), %rsp
    sysretq

.userspace_resume:
    # Keep the kernel GS owner when bypassing SYSRET for the scheduler.
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
    movl $0x10f, %eax
    xorl %edi, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    syscall
    decq %r15
    jne .benchmark_dispatch_loop

    movq %r13, %rdi
    xorl %esi, %esi
    xorl %edx, %edx
    movl $SYSCALL_CALL_YIELD, %eax
    syscall
    ud2
.global zigos_syscall_benchmark_user_end
zigos_syscall_benchmark_user_end:

.section .note.GNU-stack,"",@progbits
