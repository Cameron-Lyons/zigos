.section .text

.extern isrHandler
.extern zigos_userspace_resume_requested
.extern zigos_resume_from_userspace_interrupt
.extern zigos_handle_invalid_interrupt_return

.equ FXSAVE_BYTES, 512
.equ FXSAVE_ALIGN_SLACK, 16
.equ KERNEL_CODE_SELECTOR, 0x08
.equ USER_DATA_SELECTOR, 0x1b
.equ USER_CODE_SELECTOR, 0x23
.equ FRAME_RIP, 152
.equ FRAME_CS, 160
.equ FRAME_RFLAGS, 168
.equ FRAME_USER_RSP, 176
.equ FRAME_USER_SS, 184
.equ RFLAGS_RESERVED, 0x2
.equ RFLAGS_FORBIDDEN_RETURN, 0x27000
.equ DESCRIPTOR_RIGHTS_MASK, 0x00f0ff00
.equ USER_DATA_RIGHTS, 0x00c0f300
.equ USER_CODE_RIGHTS, 0x00a0fb00

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
ISR_NOERRCODE 67
ISR_NOERRCODE 255

isr_common_stub:
    clac
    SAVE_REGISTERS
    movq %rsp, %r12
    movq %r12, %rdi
    subq $(FXSAVE_BYTES + FXSAVE_ALIGN_SLACK), %rsp
    andq $-16, %rsp
    fxsave64 (%rsp)
    cld

    call isrHandler

    movq FRAME_CS(%r12), %rax
    cmpq $KERNEL_CODE_SELECTOR, %rax
    je .validate_common_return
    cmpq $USER_CODE_SELECTOR, %rax
    jne .invalid_interrupt_return
    cmpq $USER_DATA_SELECTOR, FRAME_USER_SS(%r12)
    jne .invalid_interrupt_return
    movq FRAME_USER_RSP(%r12), %rax
    shrq $32, %rax
    jne .invalid_interrupt_return

    movl $USER_DATA_SELECTOR, %eax
    larl %eax, %eax
    jnz .invalid_interrupt_return
    andl $DESCRIPTOR_RIGHTS_MASK, %eax
    cmpl $USER_DATA_RIGHTS, %eax
    jne .invalid_interrupt_return
    movl $USER_CODE_SELECTOR, %eax
    larl %eax, %eax
    jnz .invalid_interrupt_return
    andl $DESCRIPTOR_RIGHTS_MASK, %eax
    cmpl $USER_CODE_RIGHTS, %eax
    jne .invalid_interrupt_return

.validate_common_return:
    movq FRAME_RIP(%r12), %rax
    shrq $32, %rax
    jne .invalid_interrupt_return
    movq FRAME_RFLAGS(%r12), %rax
    testq $RFLAGS_RESERVED, %rax
    jz .invalid_interrupt_return
    testq $RFLAGS_FORBIDDEN_RETURN, %rax
    jnz .invalid_interrupt_return
    jmp .isr_dispatch_complete

.invalid_interrupt_return:
    movq %r12, %rdi
    call zigos_handle_invalid_interrupt_return

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
