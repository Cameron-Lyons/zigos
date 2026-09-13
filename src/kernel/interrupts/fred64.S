.section .text
.align 64

.extern isrHandler
.extern syscall_handler
.extern zigos_userspace_resume_requested
.extern zigos_resume_from_userspace_interrupt

.equ SYSCALL_CALL_YIELD, 0
.equ SYSCALL_CALL_DISPATCH, 1
.equ SYSCALL_VECTOR, 128
.equ USERSPACE_YIELD_VECTOR, 129
.equ USER_CODE_SELECTOR, 0x23
.equ FRED_EVENT_DATA, 0
.equ FRED_SS, 8
.equ FRED_RSP, 16
.equ FRED_RFLAGS, 24
.equ FRED_CS, 32
.equ FRED_RIP, 40
.equ FRED_EVENT_INFO, 48
.equ FRED_EVENT_TYPE_SHIFT, 8
.equ FRED_EVENT_TYPE_MASK, 0x7
.equ FRED_EVENT_TYPE_SYSCALL, 7
.equ FRED_VECTOR_MASK, 0xff
.equ XSAVE_BYTES, 576
.equ XSAVE_ALIGN_SLACK, 64
.equ XCOMP_BV, 0x8000000000000003
.equ FRAME_CS, 160

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

.macro PUSH_IRET_FROM_FRED
    pushq FRED_SS(%rsp)
    pushq FRED_RSP+8(%rsp)
    pushq FRED_RFLAGS+16(%rsp)
    pushq FRED_CS+24(%rsp)
    pushq FRED_RIP+32(%rsp)
.endm

.global zigos_fred_entry
.type zigos_fred_entry, @function
zigos_fred_entry:
    .byte 0xf3, 0x0f, 0x1e, 0xfa
    movq FRED_EVENT_INFO(%rsp), %r12
    movq %r12, %r13
    shrq $FRED_EVENT_TYPE_SHIFT, %r13
    andq $FRED_EVENT_TYPE_MASK, %r13
    cmpq $FRED_EVENT_TYPE_SYSCALL, %r13
    je .fred_syscall

    movq %r12, %r13
    andq $FRED_VECTOR_MASK, %r13
    PUSH_IRET_FROM_FRED
    pushq FRED_EVENT_DATA+40(%rsp)
    pushq %r13
    SAVE_REGISTERS
    movq %rsp, %r12
    cmpq $USER_CODE_SELECTOR, FRAME_CS(%r12)
    jne .fred_interrupt_dispatch
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
    .byte 0x48, 0x0f, 0xc7, 0x2c, 0x24
    cld
    movq %r12, %rdi
    call isrHandler
    movl $3, %eax
    xorl %edx, %edx
    .byte 0x48, 0x0f, 0xc7, 0x1c, 0x24
    movq %r12, %rsp
    jmp .fred_complete

.fred_interrupt_dispatch:
    movq %r12, %rdi
    call isrHandler
    jmp .fred_complete

.fred_syscall:
    cmpq $SYSCALL_CALL_YIELD, %rax
    je .fred_yield
    PUSH_IRET_FROM_FRED
    pushq $0
    pushq $SYSCALL_VECTOR
    SAVE_REGISTERS
    movq %rsp, %rdi
    call syscall_handler
    jmp .fred_complete

.fred_yield:
    movq %rdi, %rax
    PUSH_IRET_FROM_FRED
    pushq $0
    pushq $USERSPACE_YIELD_VECTOR
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
    .byte 0x48, 0x0f, 0xc7, 0x2c, 0x24
    cld
    movq %r12, %rdi
    call isrHandler
    movl $3, %eax
    xorl %edx, %edx
    .byte 0x48, 0x0f, 0xc7, 0x1c, 0x24
    movq %r12, %rsp

.fred_complete:
    cmpl $0, zigos_userspace_resume_requested(%rip)
    jne .fred_userspace_resume
    RESTORE_REGISTERS
    addq $56, %rsp
    .byte 0xf2, 0x0f, 0x01, 0xca
    ud2

.fred_userspace_resume:
    jmp zigos_resume_from_userspace_interrupt

.section .note.GNU-stack,"",@progbits
