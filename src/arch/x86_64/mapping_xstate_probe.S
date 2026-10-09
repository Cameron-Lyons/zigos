#include "../xstate64.inc"

// The independent oracle always writes standard format, without reusing the
// compact production macro under test or a host-test preprocessor definition.
.macro MAPPING_STANDARD_READBACK pointer
    leaq 512(\pointer), %rdi
    xorl %eax, %eax
    movl $8, %ecx
    rep stosq
    movl $7, %eax
    xorl %edx, %edx
    xsave64 (\pointer)
.endm

.text
.code64
.global zigos_mapping_xstate_roundtrip
.type zigos_mapping_xstate_roundtrip,@function
// (owned compact State, standard seed, standard poison, Result, phase0..3).
// The selected lease and IF0 retain all pointers until the caller's ACK.
zigos_mapping_xstate_roundtrip:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $16, %rsp
    movq %rcx, (%rsp)
    movl %r8d, 8(%rsp)
    movq %rsp, %rbx
    movq %rdi, %r12
    movq %rsi, %r14
    movq %rdx, %r15
    subq $XSTATE_STACK_BYTES, %rsp
    andq $-64, %rsp
    movq %rsp, %rbp
    cld
    XSAVE_FULL_STATE %rbp

    movq %r12, %r13
    XRSTOR_STATE %r13
    cmpl $2, 8(%rbx)
    jae .Lmapping_resume
    // Both real Mapping images start with BV0/XCOMP(bit63|7). Observe that
    // init restore before loading the distinct seeded live register owner.
    movq (%rbx), %r13
    MAPPING_STANDARD_READBACK %r13
    jmp .Lmapping_seed
.Lmapping_resume:
    cmpl $3, 8(%rbx)
    jne .Lmapping_save
.Lmapping_seed:
    movq %r14, %r13
    XRSTOR_FULL_STATE %r13
.Lmapping_save:
    movq %r12, %r13
    // Phase2 intentionally saves the unchanged same-address restore. Its
    // bytes must persist even when XSAVES applies modified-state optimization.
    XSAVE_STATE %r13
    movq %r15, %r13
    XRSTOR_FULL_STATE %r13
    movq %r12, %r13
    XRSTOR_STATE %r13
    movq (%rbx), %r13
    addq $XSTATE_ALIGNED_BYTES, %r13
    MAPPING_STANDARD_READBACK %r13

    // No compiler-generated instruction runs between owner restore and the
    // independent capture. Restore the original standard caller before Zig.
    XRSTOR_FULL_STATE %rbp
    movq %rbx, %rsp
    addq $16, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size zigos_mapping_xstate_roundtrip,.-zigos_mapping_xstate_roundtrip
.section .note.GNU-stack,"",@progbits
