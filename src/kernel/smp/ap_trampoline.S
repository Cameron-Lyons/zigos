.section .text
#include "../../arch/x86_64/codegen_preflight.inc"
#include "../../arch/x86_64/mtrr_bootstrap.inc"

.global smp_trampoline_start
.global smp_trampoline_end
.global smp_trampoline_cr3
.global smp_trampoline_entry
.global smp_trampoline_stack
.global smp_trampoline_cpu

.equ CR0_PE, (1 << 0)
.equ CR0_EM, (1 << 2)
.equ CR0_MP, (1 << 1)
.equ CR0_WP, (1 << 16)
.equ CR0_PG, (1 << 31)
.equ CR4_PAE, (1 << 5)
.equ CR4_OSFXSR, (1 << 9)
.equ CR4_OSXMMEXCPT, (1 << 10)
.equ EFER_MSR, 0xc0000080
.equ EFER_LME, (1 << 8)
.equ EFER_NXE, (1 << 11)
.equ CODE32_SEL, 0x08
.equ DATA32_SEL, 0x10
.equ CODE64_SEL, 0x18
.equ DATA64_SEL, 0x20

smp_trampoline_start:
.code16
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %sp, %sp

    xorl %ebx, %ebx
    movw %cs, %bx
    shll $4, %ebx

    leal (smp_trampoline_gdt - smp_trampoline_start)(%ebx), %eax
    movl %eax, (smp_trampoline_gdt_ptr - smp_trampoline_start + 2)
    movw $(smp_trampoline_gdt_end - smp_trampoline_gdt - 1), (smp_trampoline_gdt_ptr - smp_trampoline_start)

    lgdtl (smp_trampoline_gdt_ptr - smp_trampoline_start)

    movl %cr0, %eax
    orl $CR0_PE, %eax
    movl %eax, %cr0

    leal (smp_protected_mode - smp_trampoline_start)(%ebx), %eax
    movl %eax, (smp_far_ptr - smp_trampoline_start)
    movw $CODE32_SEL, (smp_far_ptr - smp_trampoline_start + 4)
    ljmpl *(smp_far_ptr - smp_trampoline_start)

.code32
smp_protected_mode:
    movw $DATA32_SEL, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    # The final root uses NX and 1GiB leaves. Reject missing transition
    # capabilities before touching EFER.NXE or enabling that root's paging.
    # CPUID destroys EBX, which holds the physical bridge anchor.
    movl %ebx, %esi
    movl $0x80000000, %eax
    xorl %ecx, %ecx
    cpuid
    cmpl $0x80000001, %eax
    jb .Lap_transition_rejected
    movl $0x80000001, %eax
    xorl %ecx, %ecx
    cpuid
    andl $((1 << 29) | (1 << 20) | (1 << 26)), %edx
    cmpl $((1 << 29) | (1 << 20) | (1 << 26)), %edx
    jne .Lap_transition_rejected
    # The last128 bytes of this SIPI page are reserved for bounded bootstrap
    # calls. No compiled code or firmware stack is used before the high stack.
    leal 4096(%esi), %esp
    ZIGOS_INITIALIZE_AP_MTRRS .Lap_cache_rejected, (smp_trampoline_cpu - smp_trampoline_start + 8), smp_trampoline_start
    # PAT retains its firmware value. Require the complete native selector
    # contract before loading CR3 or enabling any mapped alias.
    ZIGOS_REQUIRE_BOOTSTRAP_CACHE .Lap_cache_rejected, 32
    movl %esi, %ebx

    movl (smp_trampoline_cr3 - smp_trampoline_start)(%ebx), %eax
    movl %eax, %cr3

    # The bridge owns only four-level paging and baseline FP controls. Every
    # runtime feature is admitted and activated by this AP after high entry.
    movl $(CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT), %eax
    movl %eax, %cr4

    movl $EFER_MSR, %ecx
    rdmsr
    orl $(EFER_LME | EFER_NXE), %eax
    wrmsr

    movl %cr0, %eax
    andl $~CR0_EM, %eax
    orl $(CR0_MP | CR0_WP | CR0_PG), %eax
    movl %eax, %cr0

    leal (smp_long_mode - smp_trampoline_start)(%ebx), %eax
    movl %eax, (smp_far_ptr - smp_trampoline_start)(%ebx)
    movw $CODE64_SEL, (smp_far_ptr - smp_trampoline_start + 4)(%ebx)
    ljmpl *(smp_far_ptr - smp_trampoline_start)(%ebx)

.Lap_cache_rejected:
    leal (.Lap_cache_prefix - smp_trampoline_start)(%esi), %esi
    ZIGOS_HALT_BOOTSTRAP_CACHE 32
.Lap_cache_prefix:
    .asciz "ZIGOS:BOOT:CACHE:AP:REJECT:"

.Lap_transition_rejected:
    cli
.Lap_transition_halted:
    hlt
    jmp .Lap_transition_halted

.code64
smp_long_mode:
    movw $DATA64_SEL, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    # The trampoline base must survive CPUID before entering compiled native code.
    movq %rbx, %rsi
    ZIGOS_REQUIRE_NATIVE .Lap_codegen_rejected
    movq %rsi, %rbx

    movq (smp_trampoline_stack - smp_trampoline_start)(%rbx), %rsp
    ZIGOS_ENABLE_NATIVE_XSTATE
    xorq %rbp, %rbp
    movq (smp_trampoline_cpu - smp_trampoline_start)(%rbx), %rdi
    movq (smp_trampoline_entry - smp_trampoline_start)(%rbx), %rax
    # A jump into a SysV C callee needs the same 8-byte return slot as CALL.
    # The published FRED stack top remains 64-byte aligned above this slot.
    pushq $0
    # The bridge can dirty its far pointer and temporary stack after enabling
    # WB caches. Retire this AP's private lines before high-entry publication;
    # a later BSP WBINVD need not invalidate another core's private cache.
    wbinvd
    jmpq *%rax

.Lap_codegen_rejected:
    cli
.Lap_codegen_halted:
    hlt
    jmp .Lap_codegen_halted

.align 16
smp_trampoline_gdt:
    .quad 0x0000000000000000
    # Pre-set accessed bits so descriptor loads never write the shared page.
    .quad 0x00cf9b000000ffff
    .quad 0x00cf93000000ffff
    .quad 0x00af9b000000ffff
    .quad 0x00af93000000ffff
smp_trampoline_gdt_end:

.align 8
smp_trampoline_gdt_ptr:
    .word 0
    .long 0
    .word 0

.align 8
smp_far_ptr:
    .long 0
    .word 0
    .word 0

.align 8
smp_trampoline_cr3:
    .quad 0
smp_trampoline_entry:
    .quad 0
smp_trampoline_stack:
    .quad 0
smp_trampoline_cpu:
    .quad 0

    # Derive the shared cache payload from the existing CPU slot export.
    .zero ZIGOS_MTRR_SNAPSHOT_BYTES
    # A backward .org is an assembly error if code/payload exceed this bound.
    # The final128 physical bytes are exclusively the temporary AP stack.
    .org smp_trampoline_start + 3968, 0
smp_trampoline_end:

.section .note.GNU-stack,"",@progbits
