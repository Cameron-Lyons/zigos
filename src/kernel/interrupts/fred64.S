.section .text
.balign 4096

.extern isrHandler
.extern syscall_handler
.extern zigos_userspace_resume_requested
.extern zigos_userspace_resume_eip
.extern zigos_resume_from_userspace_interrupt

#include "fred_frame64.inc"
#include "../../arch/xstate64.inc"
.equ FRAME_CS, 160
.equ FRAME_INT_NO, 136

.global zigos_fred_entry
.type zigos_fred_entry, @function
zigos_fred_entry:
    .byte 0xf3, 0x0f, 0x1e, 0xfa
    jmp .fred_common_entry

    # FRED selects base+256 for events that originated in CPL0.
.balign 256
.global zigos_fred_kernel_entry
.type zigos_fred_kernel_entry, @function
zigos_fred_kernel_entry:
    .byte 0xf3, 0x0f, 0x1e, 0xfa
.fred_common_entry:
    ZIGOS_FRED_TEST_SYSCALL
    je .fred_syscall

    ZIGOS_FRED_SAVE_INTERRUPT_FRAME
    jmp .fred_isr_dispatch

.fred_syscall:
    cmpq $SYSCALL_CALL_YIELD, %rax
    je .fred_yield
    ZIGOS_FRED_SAVE_SYSCALL_FRAME
    movq %rsp, %r12
    ENTER_KERNEL_XSTATE FRAME_CS
    movq %r12, %rdi
    call syscall_handler
    jmp .fred_complete

.fred_yield:
    ZIGOS_FRED_SAVE_YIELD_FRAME
.fred_isr_dispatch:
    movq %rsp, %r12
    ENTER_KERNEL_XSTATE FRAME_CS
    movq %r12, %rdi
    call isrHandler

.fred_complete:
    # A kernel interrupt must finish its interrupted kernel operation, even if
    # task retirement has requested a later userspace-to-scheduler handoff.
    cmpq $USER_CODE_SELECTOR, FRAME_CS(%r12)
    jne .fred_restore_interrupted_xstate
    cmpl $0, zigos_userspace_resume_requested(%rip)
    je .fred_restore_interrupted_xstate
    cmpq $0, zigos_userspace_resume_eip(%rip)
    jne .fred_userspace_resume
.fred_restore_interrupted_xstate:
    LEAVE_KERNEL_XSTATE FRAME_CS
.fred_return:
    ZIGOS_FRED_COPY_RETURN_FRAME
    cmpq $USER_CODE_SELECTOR, FRAME_CS(%rsp)
    je .fred_user_return
    RESTORE_REGISTERS
    addq $56, %rsp
    # ERETS restores the interrupted kernel stack and event state.
    .byte 0xf2, 0x0f, 0x01, 0xca
    ud2
.fred_user_return:
    RESTORE_REGISTERS
    addq $56, %rsp
    # ERETU restores userspace and performs FRED's architectural GS swap.
    .byte 0xf3, 0x0f, 0x01, 0xca
    ud2

.fred_userspace_resume:
    jmp zigos_resume_from_userspace_interrupt

.section .note.GNU-stack,"",@progbits
