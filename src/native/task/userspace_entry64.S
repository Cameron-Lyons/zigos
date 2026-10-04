#include "../../arch/xstate64.inc"

.section .text

.extern zigos_userspace_resume_esp
.extern zigos_userspace_resume_eip

.macro LOAD_USER_REGISTERS
    movq 8(%rdi), %rbx
    movq 16(%rdi), %rcx
    movq 24(%rdi), %rdx
    movq 32(%rdi), %rbp
    movq 40(%rdi), %rsi
    movq 56(%rdi), %r8
    movq 64(%rdi), %r9
    movq 72(%rdi), %r10
    movq 80(%rdi), %r11
    movq 88(%rdi), %r12
    movq 96(%rdi), %r13
    movq 104(%rdi), %r14
    movq 112(%rdi), %r15
    movq 0(%rdi), %rax
    movq 48(%rdi), %rdi
.endm

.global zigos_enter_userspace
.type zigos_enter_userspace, @function
zigos_enter_userspace:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    pushfq
    cli
    movq %rdi, %r14
    movq %rsi, zigos_userspace_xstate(%rip)
    movq %rsp, zigos_userspace_resume_esp(%rip)
    subq $XSTATE_STACK_BYTES, %rsp
    andq $-64, %rsp
    movq %rsp, %r13
    movq %r13, zigos_kernel_xstate(%rip)
    XSAVE_FULL_STATE %r13
    movq zigos_userspace_xstate(%rip), %r13
    XRSTOR_STATE %r13
    movq %r14, %rdi
    leaq .resume_from_userspace(%rip), %rax
    movq %rax, zigos_userspace_resume_eip(%rip)

    movq %cr4, %rax
    btq $32, %rax
    jnc .enter_user_idt
    # Synthetic architectural FRED frame, RSP points to the error-code slot.
    # ERETU derives long-mode CS/SS from STAR; augmented CS bits must be zero.
    pushq $0
    pushq $0
    pushq $0x1b
    pushq 136(%rdi)
    pushq 128(%rdi)
    pushq $0x23
    pushq 120(%rdi)
    pushq $0
    LOAD_USER_REGISTERS
    .byte 0xf3, 0x0f, 0x01, 0xca
    ud2
.enter_user_idt:
    pushq $0x1b
    pushq 136(%rdi)
    pushq 128(%rdi)
    pushq $0x23
    pushq 120(%rdi)
    LOAD_USER_REGISTERS
    swapgs
    iretq

.resume_from_userspace:
    endbr64
    popfq
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    movl $1, %eax
    popq %rbp
    ret

.global zigos_resume_from_userspace_interrupt
.type zigos_resume_from_userspace_interrupt, @function
zigos_resume_from_userspace_interrupt:
    # The handler ran with kernel state, but restore the continuation's exact
    # state before leaving the assembly boundary.
    movq zigos_kernel_xstate(%rip), %r13
    XRSTOR_FULL_STATE %r13
    movq zigos_userspace_resume_esp(%rip), %rsp
    jmp *zigos_userspace_resume_eip(%rip)

.section .rodata
.align 64
.global zigos_initial_kernel_xstate
zigos_initial_kernel_xstate:
    .zero 24
    .long 0x1f80
    .zero 556

.section .bss
.align 8
.global zigos_userspace_xstate
zigos_userspace_xstate:
    .quad 0
.global zigos_kernel_xstate
zigos_kernel_xstate:
    .quad 0

.section .note.GNU-stack,"",@progbits
