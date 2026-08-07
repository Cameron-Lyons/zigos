.section .text

.extern isrHandler
.extern zigos_userspace_resume_requested
.extern zigos_resume_from_userspace_interrupt

.equ FXSAVE_BYTES, 512
.equ FXSAVE_ALIGN_SLACK, 16

.macro ISR_NOERRCODE num
.global isr\num
.type isr\num, @function
isr\num:
    pushq $0
    pushq $\num
    jmp isr_common_stub
.endm

.macro ISR_ERRCODE num
.global isr\num
.type isr\num, @function
isr\num:
    pushq $\num
    jmp isr_common_stub
.endm

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

ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_NOERRCODE 9
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 15
ISR_NOERRCODE 16
ISR_ERRCODE   17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_ERRCODE   21
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_ERRCODE   29
ISR_ERRCODE   30
ISR_NOERRCODE 31
ISR_NOERRCODE 64
ISR_NOERRCODE 65
ISR_NOERRCODE 66
ISR_NOERRCODE 255

isr_common_stub:
    SAVE_REGISTERS
    movq %rsp, %r12
    movq %r12, %rdi
    subq $(FXSAVE_BYTES + FXSAVE_ALIGN_SLACK), %rsp
    andq $-16, %rsp
    fxsave64 (%rsp)
    cld

    call isrHandler

.isr_dispatch_complete:
    fxrstor64 (%rsp)
    movq %r12, %rsp
    cmpl $0, zigos_userspace_resume_requested(%rip)
    jne .userspace_resume

    RESTORE_REGISTERS
    addq $16, %rsp
    iretq

.userspace_resume:
    jmp zigos_resume_from_userspace_interrupt

.section .note.GNU-stack,"",@progbits
