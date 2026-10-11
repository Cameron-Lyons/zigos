#include "../../arch/xstate64.inc"
#include "idt_return64.inc"
.section .text

.extern isrHandler
.extern zigos_resume_from_userspace_interrupt
.extern zigos_handle_invalid_interrupt_return

.equ KERNEL_CODE_SELECTOR, IDT_KERNEL_CODE_SELECTOR
.equ USER_DATA_SEGMENT, IDT_USER_DATA_SEGMENT
.equ USER_DATA_SELECTOR, IDT_USER_DATA_SELECTOR
.equ USER_CODE_SELECTOR, IDT_USER_CODE_SELECTOR
.equ SELECTOR_RPL_MASK, IDT_SELECTOR_RPL_MASK
.equ FRAME_INT_NO, 136
.equ FRAME_RIP, IDT_FRAME_RIP
.equ FRAME_CS, IDT_FRAME_CS
.equ FRAME_RFLAGS, IDT_FRAME_RFLAGS
.equ FRAME_USER_RSP, IDT_FRAME_USER_RSP
.equ FRAME_USER_SS, IDT_FRAME_USER_SS
.equ RFLAGS_RESERVED, IDT_RFLAGS_RESERVED
.equ RFLAGS_FORBIDDEN_RETURN, IDT_RFLAGS_FORBIDDEN_RETURN
.equ DESCRIPTOR_RIGHTS_MASK, 0x00f0ff00
.equ USER_DATA_RIGHTS, 0x00c0f300
.equ USER_CODE_RIGHTS, 0x00a0fb00

.macro ISR_NOERRCODE num
.global isr\num
.type isr\num, @function
isr\num:
    endbr64
    pushq $0
    pushq $\num
    jmp isr_common_stub
.endm

.macro ISR_ERRCODE num
.global isr\num
.type isr\num, @function
isr\num:
    endbr64
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
ISR_NOERRCODE 112
ISR_NOERRCODE 113
ISR_NOERRCODE 114
ISR_NOERRCODE 115
ISR_NOERRCODE 116
ISR_NOERRCODE 255

isr_common_stub:
    # endbr64
    .byte 0xf3, 0x0f, 0x1e, 0xfa
    clac
    SAVE_REGISTERS
    movq %rsp, %r12
    cmpq $USER_CODE_SELECTOR, FRAME_CS(%r12)
    jne .isr_kernel_gs_ready
    swapgs
.isr_kernel_gs_ready:
    ENTER_KERNEL_XSTATE FRAME_CS
    movq %r12, %rdi
    call isrHandler

    ZIGOS_IDT_VALIDATE_RETURN_PREFIX %r12, .invalid_interrupt_return, .validate_common_return

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
    ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r12, .invalid_interrupt_return
    jmp .isr_dispatch_complete

.invalid_interrupt_return:
    movq %r12, %rdi
    call zigos_handle_invalid_interrupt_return

.isr_dispatch_complete:
    # Handoff keeps the saved user image owned by its mapping. Restore it
    # only when returning to that user, never before scheduler C code.
    cmpq $USER_CODE_SELECTOR, FRAME_CS(%r12)
    jne .restore_interrupted_xstate
    cmpl $0, %gs:CPU_RESUME_REQUESTED
    je .restore_interrupted_xstate
    cmpq $0, %gs:CPU_RESUME_RIP
    jne .userspace_resume
.restore_interrupted_xstate:
    LEAVE_KERNEL_XSTATE FRAME_CS
.interrupt_return:
    cmpq $USER_CODE_SELECTOR, FRAME_CS(%rsp)
    jne .interrupt_restore_registers
    swapgs
.interrupt_restore_registers:
    RESTORE_REGISTERS
    addq $16, %rsp
    iretq

.userspace_resume:
    jmp zigos_resume_from_userspace_interrupt

.section .note.GNU-stack,"",@progbits
