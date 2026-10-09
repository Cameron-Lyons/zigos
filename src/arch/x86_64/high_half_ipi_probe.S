/* Isolated CPL0 interrupt evidence. Standard XSAVE, XCR0=7 and dormant per-CPU
 * GS canaries do not publish nativeReady or establish native trap ownership,
 * userspace, FRED or production XSAVES admission. */
#include "../xstate64.inc"
#include "../../kernel/interrupts/idt_return64.inc"
.section .text
.code64

.macro PUSH_GP
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
.endm
.macro POP_GP
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
.endm

.macro PROOF_IPI_ENTRY entry, handler
.global \entry
.type \entry,@function
\entry:
    endbr64
    clac
    cld
    PUSH_GP
    movq %rsp, %r12
    subq $XSTATE_STACK_BYTES, %rsp
    andq $-64, %rsp
    movq %rsp, %r13
    /* The macro owns 840 bytes, including its separate PKRU slot. */
    XSAVE_FULL_STATE %r13
    fninit
    ldmxcsr .Ldefault_mxcsr(%rip)
    call \handler
    /* Fifteen saved GPRs occupy 120 bytes, placing hardware RIP/CS/RFLAGS
     * at 120/128/136. Bias the synthetic base by -32 so production canonical
     * offsets 152/160/168 address that untouched hardware return frame.
     * R14 and RAX are saved, and IRETQ restores the interrupted flags. */
    leaq -32(%r12), %r14
    ZIGOS_IDT_VALIDATE_RETURN_PREFIX %r14, .Linvalid_kernel_return\@, .Lvalidate_kernel_return\@
    /* This isolated gate admits only CPL0; it has no user descriptor path. */
    jmp .Linvalid_kernel_return\@
.Lvalidate_kernel_return\@:
    ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS %r14, .Linvalid_kernel_return\@
    /* Poison every SIMD lane so restoration cannot pass by accident. */
    vzeroall
    fninit
    XRSTOR_FULL_STATE %r13
    movq %r12, %rsp
    POP_GP
    iretq
.Linvalid_kernel_return\@:
    cli
    ud2
.Linvalid_kernel_return_halt\@:
    hlt
    jmp .Linvalid_kernel_return_halt\@
.size \entry,.-\entry

.endm

PROOF_IPI_ENTRY zigos_arch_smp_tlb_ipi, zigos_arch_smp_handle_tlb_ipi
PROOF_IPI_ENTRY zigos_arch_smp_execution_stop_ipi, zigos_arch_smp_handle_execution_stop_ipi
PROOF_IPI_ENTRY zigos_arch_smp_syscall_request_ipi, zigos_arch_smp_handle_syscall_request_ipi
PROOF_IPI_ENTRY zigos_arch_smp_syscall_completion_ipi, zigos_arch_smp_handle_syscall_completion_ipi
PROOF_IPI_ENTRY zigos_arch_smp_prepared_execution_ipi, zigos_arch_smp_handle_prepared_execution_ipi

.global zigos_arch_smp_spurious_ipi
.type zigos_arch_smp_spurious_ipi,@function
zigos_arch_smp_spurious_ipi:
    endbr64
    iretq
.size zigos_arch_smp_spurious_ipi,.-zigos_arch_smp_spurious_ipi

/* C ABI: (seed standard image, output image, restored RFLAGS) -> GP match.
 * The caller enters with IF clear. Its own xstate and nonvolatile GPRs are
 * restored before returning to compiler code; only the fixture is live at STI.
 * A pending fixed IPI cannot arrive until all sixteen YMM and fifteen GPR
 * canaries are installed. Spurious wakeups may be retried by the C caller. */
.macro CHECK_GP register, value, failure
    cmpq $\value, \register
    jne \failure
.endm

.macro PROOF_IPI_WAIT entry, bounded, signal_window=0, trap_stack=0
.global \entry
.type \entry,@function
\entry:
    endbr64
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %rax
.if \trap_stack
    /* RCX is the admitted selected trap top. Keep the upper 64-byte canary
     * region untouched; RAX retains the ordinary stack for the final RET. */
    movq %rcx, %rsp
    subq $64, %rsp
.endif
    subq $1024, %rsp
    andq $-64, %rsp
    movq %rax, 896(%rsp)
    movq %rdi, 904(%rsp)
    movq %rsi, 912(%rsp)
    movq %rdx, 920(%rsp)
    movq $1, 928(%rsp)
.if \bounded
    /* Keep the finite BSP window outside both xstate and saved metadata. */
    movq $16384, 936(%rsp)
.endif
    movq %rsp, %r13
    XSAVE_FULL_STATE %r13
    movq 904(%rsp), %r13
    XRSTOR_FULL_STATE %r13
    /* Every canary has live upper bits, so 32-bit truncation also fails. */
    movq $-0x1101, %rax
    movq $-0x1102, %rbx
    movq $-0x1103, %rcx
    movq $-0x1104, %rdx
    movq $-0x1105, %rsi
    movq $-0x1106, %rdi
    movq $-0x1107, %rbp
    movq $-0x1108, %r8
    movq $-0x1109, %r9
    movq $-0x110a, %r10
    movq $-0x110b, %r11
    movq $-0x110c, %r12
    movq $-0x110d, %r13
    movq $-0x110e, %r14
    movq $-0x110f, %r15
    std
    stac
    sti
.if \trap_stack
    movl $1, zigos_arch_smp_trap_ipi_window(%rip)
.endif
.if \signal_window
    /* The BSP sends this proof's second dispatch prompt only after acquiring
     * this owner-local window witness. RIP-relative stores preserve every
     * live GPR canary. No command/domain pointer crosses this boundary. */
    movl $1, zigos_arch_smp_prepared_ipi_window(%rip)
.endif
.if \bounded
    /* The isolated BSP has no armed timer. Return even without a doorbell
     * so its C caller can check the deadline; all fifteen GPRs stay live. */
.Lpoll_ipi\@:
    pause
    decq 936(%rsp)
    jnz .Lpoll_ipi\@
.else
    hlt
.endif
    cli
.if \trap_stack
    movl $0, zigos_arch_smp_trap_ipi_window(%rip)
.endif
.if \signal_window
    movl $0, zigos_arch_smp_prepared_ipi_window(%rip)
.endif
    CHECK_GP %rax, -0x1101, .Lbad_gp\@
    CHECK_GP %rbx, -0x1102, .Lbad_gp\@
    CHECK_GP %rcx, -0x1103, .Lbad_gp\@
    CHECK_GP %rdx, -0x1104, .Lbad_gp\@
    CHECK_GP %rsi, -0x1105, .Lbad_gp\@
    CHECK_GP %rdi, -0x1106, .Lbad_gp\@
    CHECK_GP %rbp, -0x1107, .Lbad_gp\@
    CHECK_GP %r8, -0x1108, .Lbad_gp\@
    CHECK_GP %r9, -0x1109, .Lbad_gp\@
    CHECK_GP %r10, -0x110a, .Lbad_gp\@
    CHECK_GP %r11, -0x110b, .Lbad_gp\@
    CHECK_GP %r12, -0x110c, .Lbad_gp\@
    CHECK_GP %r13, -0x110d, .Lbad_gp\@
    CHECK_GP %r14, -0x110e, .Lbad_gp\@
    CHECK_GP %r15, -0x110f, .Lbad_gp\@
    jmp .Lsnapshot\@
.Lbad_gp\@:
    movq $0, 928(%rsp)
.Lsnapshot\@:
    pushfq
    popq %rax
    movq 920(%rsp), %rdx
    movq %rax, (%rdx)
    cld
    clac
    movq 912(%rsp), %r13
    XSAVE_FULL_STATE %r13
    movq %rsp, %r13
    XRSTOR_FULL_STATE %r13
    movq 928(%rsp), %rax
    movq 896(%rsp), %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.size \entry,.-\entry
.endm

PROOF_IPI_WAIT zigos_arch_smp_wait_for_ipi, 0
PROOF_IPI_WAIT zigos_arch_smp_poll_for_ipi, 1
PROOF_IPI_WAIT zigos_arch_smp_poll_prepared_ipi, 1, 1
PROOF_IPI_WAIT zigos_arch_smp_poll_trap_stack, 1, 0, 1

.section .rodata
.balign 4
.Ldefault_mxcsr:
    .long 0x1f80
.section .note.GNU-stack,"",@progbits
