// Exercise the same capture instructions as fred64.S without privileged entry
// or return instructions. The synthetic frame remains on the caller's stack.
#include "../../kernel/interrupts/fred_frame64.inc"
#if defined(__APPLE__)
#define PROBE_SYMBOL _zigos_fred_capture_probe
#define RETURN_PROBE_SYMBOL _zigos_fred_return_probe
#define HOST_TEXT_START ___kernel_start
#define HOST_TEXT_END ___kernel_end
#else
#define PROBE_SYMBOL zigos_fred_capture_probe
#define RETURN_PROBE_SYMBOL zigos_fred_return_probe
#define HOST_TEXT_START __kernel_start
#define HOST_TEXT_END __kernel_end
#endif
.text
// Hosted ISR tests link the real dispatcher and its unreachable fatal path.
// These diagnostic bounds describe only fixture text, never a production ELF.
.globl HOST_TEXT_START
HOST_TEXT_START:
.globl PROBE_SYMBOL
PROBE_SYMBOL:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rdx
    pushq %rdi
    subq $64, %rsp
    movq %rsp, %rdi
    movl $8, %ecx
    cld
    rep movsq
    movq 64(%rsp), %rdi
    movq 0(%rdi), %rax
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
    movq 48(%rdi), %rdi
    ZIGOS_FRED_TEST_SYSCALL
    je .fred_syscall
    ZIGOS_FRED_SAVE_INTERRUPT_FRAME
    jmp .capture
.fred_syscall:
    cmpq $SYSCALL_CALL_YIELD, %rax
    je .fred_yield
    ZIGOS_FRED_SAVE_SYSCALL_FRAME
    jmp .capture
.fred_yield:
    ZIGOS_FRED_SAVE_YIELD_FRAME
    jmp .capture
.capture:
    movq %rsp, %rsi
    movq 264(%rsp), %rdi
    movl $32, %ecx
    cld
    rep movsq
    addq $272, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

// Simulate edits made by a C handler, then execute the production publication
// macro. Keep its result observable without executing privileged ERETU/ERETS.
.globl RETURN_PROBE_SYMBOL
RETURN_PROBE_SYMBOL:
    pushq %rbx
    pushq %rdx
    subq $256, %rsp
    movq %rsi, %rbx
    movq %rdi, %rsi
    movq %rsp, %rdi
    movl $24, %ecx
    cld
    rep movsq
    movq %rbx, %rsi
    leaq 192(%rsp), %rdi
    movl $8, %ecx
    rep movsq
    ZIGOS_FRED_COPY_RETURN_FRAME
    leaq 192(%rsp), %rsi
    movq 256(%rsp), %rdi
    movl $8, %ecx
    rep movsq
    addq $264, %rsp
    popq %rbx
    ret
.globl HOST_TEXT_END
HOST_TEXT_END:
#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
