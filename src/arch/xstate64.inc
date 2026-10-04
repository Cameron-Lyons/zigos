#ifndef ZIGOS_XSTATE64_INC
#define ZIGOS_XSTATE64_INC
/* XCR0 is exactly x87|SSE and IA32_XSS is zero on every CPU. PKRU is
 * separately owned because CR4.PKE does not imply XCR0.PKRU. */
.equ XSTATE_IMAGE_BYTES, 576
.equ XSTATE_BYTES, 584
.equ XSTATE_STACK_BYTES, 648
.equ XSTATE_PKRU, 576

/* pointer must be a saved register other than rax/rcx/rdx/rdi. Prepared mode
 * is valid only while the current runtime CPU owns the published userspace
 * context: TS is clear and its entry captured the invariant CR4.PKE mode. */
.macro XSAVE_STATE pointer, full=0, prepared=0
    cld
#ifndef ZIGOS_XSTATE_HOST_TEST
.if !\prepared
    clts
.endif
#endif
    leaq 512(\pointer), %rdi
    xorl %eax, %eax
    movl $8, %ecx
    rep stosq
#ifndef ZIGOS_XSTATE_HOST_TEST
.if !\full
    movabsq $0x8000000000000003, %rax
    movq %rax, 520(\pointer)
.endif
#endif
    movl $3, %eax
    xorl %edx, %edx
#ifdef ZIGOS_XSTATE_HOST_TEST
    xsave64 (\pointer)
#else
.if \full
    xsave64 (\pointer)
.else
    xsaves64 (\pointer)
.endif
    movl $(0), XSTATE_PKRU(\pointer)
.if \prepared
    cmpl $(0), zigos_userspace_xstate_pku_enabled(%rip)
.else
    movq %cr4, %rax
    testq $(1 << 22), %rax
.endif
    jz .Lsave_no_pku\@
    xorl %ecx, %ecx
    rdpkru
    movl %eax, XSTATE_PKRU(\pointer)
.Lsave_no_pku\@:
#endif
.endm

// Stack images may occupy an address last used by XRSTORS but overwritten
// after unwinding. Full XSAVE prevents modified-state optimization from omitting
// bytes in that ephemeral storage; persistent user images remain XSAVES-owned.
.macro XSAVE_FULL_STATE pointer, prepared=0
    XSAVE_STATE \pointer, 1, \prepared
.endm

.macro XRSTOR_STATE pointer, full=0, prepared=0
#ifndef ZIGOS_XSTATE_HOST_TEST
.if !\prepared
    clts
.endif
.if \prepared
    cmpl $(0), zigos_userspace_xstate_pku_enabled(%rip)
.else
    movq %cr4, %rax
    testq $(1 << 22), %rax
.endif
    jz .Lrestore_no_pku\@
    movl XSTATE_PKRU(\pointer), %eax
    xorl %ecx, %ecx
    xorl %edx, %edx
    wrpkru
    lfence
.Lrestore_no_pku\@:
#endif
    movl $3, %eax
    xorl %edx, %edx
#ifdef ZIGOS_XSTATE_HOST_TEST
    xrstor64 (\pointer)
#else
.if \full
    xrstor64 (\pointer)
.else
    xrstors64 (\pointer)
.endif
#endif
.endm

.macro XRSTOR_FULL_STATE pointer, prepared=0
    XRSTOR_STATE \pointer, 1, \prepared
.endm

#ifndef ZIGOS_XSTATE_HOST_TEST
.extern zigos_initial_kernel_xstate
.extern zigos_userspace_xstate
.extern zigos_kernel_xstate
.extern zigos_userspace_xstate_pku_enabled
/* r12 always points to the already-saved GP/return frame. Kernel entries
 * preserve their interrupted live SIMD state; user entries switch owners
 * before the first compiler-generated instruction. */
.macro ENTER_KERNEL_XSTATE frame_cs
    cli
    subq $XSTATE_STACK_BYTES, %rsp
    andq $-64, %rsp
    movq %rsp, %r13
    movq $(0), XSTATE_BYTES(%rsp)
    cmpq $0x23, \frame_cs(%r12)
    jne .Lsave_kernel_xstate\@
    movq zigos_userspace_xstate(%rip), %r13
    testq %r13, %r13
    jz .Lmissing_xstate\@
    # The prepared owner has TS clear and a CPU-bound PKE mode. Avoid
    # serializing control-register instructions on every native operation.
    XSAVE_STATE %r13, 0, 1
    movq zigos_kernel_xstate(%rip), %r13
    testq %r13, %r13
    jz .Lmissing_xstate\@
    XRSTOR_FULL_STATE %r13, 1
    jmp .Lkernel_xstate_ready\@
.Lsave_kernel_xstate\@:
    # Diagnostic faults may precede OSXSAVE initialization on this CPU.
    movq %cr4, %rax
    testq $(1 << 18), %rax
    jz .Lkernel_xstate_ready\@
    xorl %ecx, %ecx
    xgetbv
    cmpl $3, %eax
    jne .Lkernel_xstate_ready\@
    testl %edx, %edx
    jne .Lkernel_xstate_ready\@
    movq $1, XSTATE_BYTES(%rsp)
    XSAVE_FULL_STATE %r13
    # Even an NMI during the final user-state restore window arrives with a
    # kernel CS. Do not let its C handler inherit user FP controls or PKRU.
    leaq zigos_initial_kernel_xstate(%rip), %r13
    XRSTOR_FULL_STATE %r13
.Lkernel_xstate_ready\@:
    cld
    jmp .Lenter_xstate_done\@
.Lmissing_xstate\@:
    ud2
.Lenter_xstate_done\@:
.endm

.macro LEAVE_KERNEL_XSTATE frame_cs
    movq %rsp, %r13
    cmpq $0x23, \frame_cs(%r12)
    jne .Lrestore_saved_kernel_xstate\@
    movq zigos_userspace_xstate(%rip), %r13
    XRSTOR_STATE %r13, 0, 1
    jmp .Lleave_xstate_done\@
.Lrestore_saved_kernel_xstate\@:
    cmpq $(0), XSTATE_BYTES(%rsp)
    je .Lleave_xstate_done\@
.Lrestore_kernel_xstate\@:
    XRSTOR_FULL_STATE %r13
.Lleave_xstate_done\@:
    movq %r12, %rsp
.endm
#endif
#endif
