#include "../../arch/xstate64.inc"

.section .text

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
    movq %rsi, %gs:CPU_USERSPACE_XSTATE
    # Kernel GS names this CPU's native-entry state. Its ready bit is published
    # only after the actual xstate controls and TS-clear invariant are verified.
    testb $(CPU_ENTRY_READY), %gs:CPU_NATIVE_ENTRY_MODES
    jz .Lunprepared_cpu
    movq %rsp, %gs:CPU_RESUME_RSP
    subq $XSTATE_STACK_BYTES, %rsp
    andq $-64, %rsp
    movq %rsp, %r13
    movq %r13, %gs:CPU_KERNEL_XSTATE
    XSAVE_FULL_STATE %r13, 1
    movq %gs:CPU_USERSPACE_XSTATE, %r13
    XRSTOR_STATE %r13, 0, 1
    movq %r14, %rdi
    leaq .Lresume_from_userspace(%rip), %rax
    movq %rax, %gs:CPU_RESUME_RIP

    testb $(CPU_ENTRY_FRED), %gs:CPU_NATIVE_ENTRY_MODES
    jz .enter_user_idt
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

.Lresume_from_userspace:
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

.Lunprepared_cpu:
    ud2

.global zigos_resume_from_userspace_interrupt
.type zigos_resume_from_userspace_interrupt, @function
zigos_resume_from_userspace_interrupt:
    # The handler ran with kernel state, but restore the continuation's exact
    # state before leaving the assembly boundary.
    movq %gs:CPU_KERNEL_XSTATE, %r13
    XRSTOR_FULL_STATE %r13, 1
    movq %gs:CPU_RESUME_RSP, %rsp
    jmp *%gs:CPU_RESUME_RIP

.section .rodata
.align 64
.global zigos_initial_kernel_xstate
zigos_initial_kernel_xstate:
    .zero 24
    .long 0x1f80
    .zero XSTATE_BYTES - 28

.section .note.GNU-stack,"",@progbits
