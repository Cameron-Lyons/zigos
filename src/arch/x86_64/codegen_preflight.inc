// This gate contains only architectural baseline instructions. Every native
// entry calls it before compiled v3+crypto code; CPUID clobbers EAX/EBX/ECX/EDX.
#include "cache_policy.inc"
.equ .Lzigos_native_leaf1_ecx, ((1 << 0) | (1 << 1) | (1 << 9) | (1 << 12) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 22) | (1 << 23) | (1 << 25) | (1 << 26) | (1 << 28) | (1 << 29))
.equ .Lzigos_native_leaf7_ebx, ((1 << 3) | (1 << 5) | (1 << 8) | (1 << 29))
.macro ZIGOS_REQUIRE_NATIVE reject
    xorl %eax, %eax
    xorl %ecx, %ecx
    cpuid
    cmpl $0xD, %eax
    jb \reject

    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    testl $(1 << 26), %edx
    jz \reject
    movl %ecx, %eax
    andl $.Lzigos_native_leaf1_ecx, %eax
    cmpl $.Lzigos_native_leaf1_ecx, %eax
    jne \reject

    movl $7, %eax
    xorl %ecx, %ecx
    cpuid
    andl $.Lzigos_native_leaf7_ebx, %ebx
    cmpl $.Lzigos_native_leaf7_ebx, %ebx
    jne \reject

    movl $0x80000000, %eax
    xorl %ecx, %ecx
    cpuid
    cmpl $0x80000001, %eax
    jb \reject
    movl $0x80000001, %eax
    xorl %ecx, %ecx
    cpuid
    testl $(1 << 29), %edx
    jz \reject
    andl $((1 << 0) | (1 << 5)), %ecx
    cmpl $((1 << 0) | (1 << 5)), %ecx
    jne \reject

    // Bound both standard and compacted x87/SSE/YMM ownership to 832 bytes.
    movl $0xD, %eax
    xorl %ecx, %ecx
    cpuid
    andl $7, %eax
    cmpl $7, %eax
    jne \reject
    movl $0xD, %eax
    movl $2, %ecx
    cpuid
    cmpl $256, %eax
    jne \reject
    cmpl $576, %ebx
    jne \reject
    testl $1, %ecx
    jnz \reject
.endm

// Must follow successful admission and precede the first compiled instruction.
// Firmware code keeps its original XCR0 until it has exited boot services.
// Requires a valid stack. Clobbers EAX/ECX/EDX; preserves the AP trampoline
// anchor and handoff registers, and restores the original stack pointer.
.macro ZIGOS_ENABLE_NATIVE_XSTATE
    movq %cr0, %rax
    andq $~((1 << 2) | (1 << 3)), %rax
    orq $(1 << 1), %rax
    movq %rax, %cr0
    movq %cr4, %rax
    orq $((1 << 9) | (1 << 10) | (1 << 18)), %rax
    movq %rax, %cr4
    xorl %ecx, %ecx
    movl $7, %eax
    xorl %edx, %edx
    xsetbv
    // Firmware may leave non-default exception masks and rounding modes.
    // Establish deterministic controls before the first generated FP operation.
    fninit
    pushq $0x1f80
    ldmxcsr (%rsp)
    addq $8, %rsp
.endm
