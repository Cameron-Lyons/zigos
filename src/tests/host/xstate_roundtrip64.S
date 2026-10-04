// Hosted execution of the production save/restore macros. XSAVE/XRSTOR are
// unprivileged here; this fixture does not claim to execute XSAVES or FRED.
#define ZIGOS_XSTATE_HOST_TEST
#include "../../arch/xstate64.inc"

#if defined(__APPLE__)
#define SYMBOL(name) _##name
#else
#define SYMBOL(name) name
#endif

.text
.globl SYMBOL(zigos_xstate_host_supported)
SYMBOL(zigos_xstate_host_supported):
    pushq %rbx
    movl $1, %eax
    cpuid
    andl $0x0c000000, %ecx
    cmpl $0x0c000000, %ecx
    jne .unsupported
    xorl %ecx, %ecx
    xgetbv
    andl $3, %eax
    cmpl $3, %eax
    jne .unsupported
    movl $1, %eax
    popq %rbx
    ret
.unsupported:
    xorl %eax, %eax
    popq %rbx
    ret

.globl SYMBOL(zigos_xstate_host_roundtrip)
SYMBOL(zigos_xstate_host_roundtrip):
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %rbx
    movq %rdi, %r12
    movq %rsi, %r14
    subq $XSTATE_STACK_BYTES, %rsp
    andq $-64, %rsp
    movq %rsp, %rbp
    cld
    XSAVE_FULL_STATE %rbp

    // Initialize one kernel and two userspace owners, each with its own image.
    movq %r12, %r13
    XRSTOR_FULL_STATE %r13
    movq %r14, %r13
    XSAVE_FULL_STATE %r13
    leaq 640(%r12), %r13
    XRSTOR_STATE %r13
    leaq 640(%r14), %r13
    XSAVE_STATE %r13
    leaq 1280(%r12), %r13
    XRSTOR_STATE %r13
    leaq 1280(%r14), %r13
    XSAVE_STATE %r13

    // No compiler-generated code executes between owner changes. Saving to
    // each persistent image must retain its x87, MXCSR and all sixteen XMMs.
    movl $128, %r15d
.roundtrip:
    movq %r14, %r13
    XRSTOR_FULL_STATE %r13
    XSAVE_FULL_STATE %r13
    leaq 640(%r14), %r13
    XRSTOR_STATE %r13
    XSAVE_STATE %r13
    leaq 1280(%r14), %r13
    XRSTOR_STATE %r13
    XSAVE_STATE %r13
    decl %r15d
    jnz .roundtrip

    // Leave the caller's original floating-point environment intact.
    XRSTOR_FULL_STATE %rbp
    movq %rbx, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

#if !defined(__APPLE__)
.section .note.GNU-stack,"",@progbits
#endif
