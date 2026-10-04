// Shared production FRED register capture. No privileged instructions.
.equ SYSCALL_CALL_YIELD, 0
.equ SYSCALL_CALL_DISPATCH, 1
.equ SYSCALL_VECTOR, 128
.equ USERSPACE_YIELD_VECTOR, 129
.equ USER_CODE_SELECTOR, 0x23
.equ FRED_ERROR, 0
.equ FRED_RIP, 8
.equ FRED_CS, 16
.equ FRED_RFLAGS, 24
.equ FRED_RSP, 32
.equ FRED_SS, 40
.equ FRED_EVENT_DATA, 48
.equ FRED_RESERVED, 56
.equ FRED_FRAME_BYTES, 64
.equ FRED_VECTOR_SHIFT, 32
.equ FRED_EVENT_TYPE_SHIFT, 48
.equ FRED_SYSCALL_CLASS_MASK, 0xf00ff
.equ FRED_SYSCALL_CLASS, 0x70001
.equ FRED_VECTOR_MASK, 0xff
.equ FRED_CANONICAL_FRAME_BYTES, 192
.equ FRED_CANONICAL_VECTOR, 136
.equ FRED_CANONICAL_ERROR, 144
.equ FRED_CANONICAL_RIP, 152
.equ FRED_CANONICAL_CS, 160
.equ FRED_CANONICAL_RFLAGS, 168
.equ FRED_CANONICAL_RSP, 176
.equ FRED_CANONICAL_SS, 184

.macro SAVE_REGISTERS
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq $(0)
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
    pushq $(0)
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
    andq $(0xffff), (%rsp)
    pushq FRED_RSP+8(%rsp)
    pushq FRED_RFLAGS+16(%rsp)
    pushq FRED_CS+24(%rsp)
    andq $(0xffff), (%rsp)
    pushq FRED_RIP+32(%rsp)
.endm

// Preserve incoming callee-saves before decoding the event. POP leaves the
// comparison flags intact; the caller branches without losing the original R12.
.macro ZIGOS_FRED_TEST_SYSCALL
    pushq %r12
    movq FRED_SS+8(%rsp), %r12
    shrq $FRED_VECTOR_SHIFT, %r12
    andq $FRED_SYSCALL_CLASS_MASK, %r12
    cmpq $FRED_SYSCALL_CLASS, %r12
    popq %r12
.endm

.macro ZIGOS_FRED_SAVE_INTERRUPT_FRAME
    PUSH_IRET_FROM_FRED
    pushq FRED_ERROR+40(%rsp)
    pushq FRED_SS+48(%rsp)
    shrq $FRED_VECTOR_SHIFT, (%rsp)
    andq $FRED_VECTOR_MASK, (%rsp)
    SAVE_REGISTERS
    // FRED INT n has no IDT privilege check. A user software interrupt cannot
    // impersonate a physical timer/device IRQ or an exception via its vector.
    // Exact SYSCALL type7/vector1 has already selected the native ABI above.
    movq FRED_CANONICAL_CS(%rsp), %rax
    andq $(3), %rax
    cmpq $(3), %rax
    jne .Lfred_interrupt_class_ready\@
    movq FRED_CANONICAL_FRAME_BYTES+FRED_SS(%rsp), %rax
    shrq $FRED_EVENT_TYPE_SHIFT, %rax
    andq $(0xf), %rax
    cmpq $(4), %rax
    je .Lfred_reject_user_software_event\@
    cmpq $(7), %rax
    jne .Lfred_interrupt_class_ready\@
.Lfred_reject_user_software_event\@:
    movq $(6), FRED_CANONICAL_VECTOR(%rsp)
    movq $(0), FRED_CANONICAL_ERROR(%rsp)
.Lfred_interrupt_class_ready\@:
.endm

.macro ZIGOS_FRED_SAVE_SYSCALL_FRAME
    PUSH_IRET_FROM_FRED
    pushq $(0)
    pushq $SYSCALL_VECTOR
    SAVE_REGISTERS
.endm

.macro ZIGOS_FRED_SAVE_YIELD_FRAME
    movq %rdi, %rax
    PUSH_IRET_FROM_FRED
    pushq $(0)
    pushq $USERSPACE_YIELD_VECTOR
    SAVE_REGISTERS
.endm

// The C handler edits the canonical return fields. Publish those edits back
// into the architectural frame without replacing FRED's augmented CS/SS:
// ERETS needs their stack level, IBT and event-blocking metadata unchanged.
// RSP points to the saved canonical GP frame; RAX is still saved below it.
.macro ZIGOS_FRED_COPY_RETURN_FRAME
    movq FRED_CANONICAL_RIP(%rsp), %rax
    movq %rax, FRED_CANONICAL_FRAME_BYTES+FRED_RIP(%rsp)
    movw FRED_CANONICAL_CS(%rsp), %ax
    movw %ax, FRED_CANONICAL_FRAME_BYTES+FRED_CS(%rsp)
    movq FRED_CANONICAL_RFLAGS(%rsp), %rax
    movq %rax, FRED_CANONICAL_FRAME_BYTES+FRED_RFLAGS(%rsp)
    movq FRED_CANONICAL_RSP(%rsp), %rax
    movq %rax, FRED_CANONICAL_FRAME_BYTES+FRED_RSP(%rsp)
    movw FRED_CANONICAL_SS(%rsp), %ax
    movw %ax, FRED_CANONICAL_FRAME_BYTES+FRED_SS(%rsp)
.endm
