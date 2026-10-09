// Isolated offline AP evidence. One actual bootstrap expansion is called twice
// before paging, with no reset or external MTRR writer between the calls.
#include "cache_policy.inc"
#include "mtrr_bootstrap.inc"

#define PROOF_FIRST_OFFSET 0
#define PROOF_SECOND_OFFSET 24
#define PROOF_OBSERVED_OFFSET 48
#define PROOF_STATUS_OFFSET 672
#define PROOF_RESULT_BYTES 680
#define PROOF_CR0_OFFSET 0
#define PROOF_FLAGS_OFFSET 4
#define PROOF_PAT_OFFSET 8
#define PROOF_DEFAULT_OFFSET 16

.section .text,"ax",@progbits
.global zigos_arch_smp_cache_start
.global zigos_arch_smp_cache_end
.global zigos_arch_smp_cache_snapshot
.global zigos_arch_smp_cache_result
.global zigos_arch_smp_cache_initialize
.global zigos_arch_smp_cache_first_call
.global zigos_arch_smp_cache_second_call

zigos_arch_smp_cache_start:
.code16
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %sp, %sp
    xorl %esi, %esi
    movw %cs, %si
    shll $4, %esi
    leal (.Lproof_gdt - zigos_arch_smp_cache_start)(%esi), %eax
    movl %eax, (.Lproof_gdt_pointer - zigos_arch_smp_cache_start + 2)
    lgdtl (.Lproof_gdt_pointer - zigos_arch_smp_cache_start)
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    leal (.Lproof_protected - zigos_arch_smp_cache_start)(%esi), %eax
    movl %eax, (.Lproof_far_pointer - zigos_arch_smp_cache_start)
    ljmpl *(.Lproof_far_pointer - zigos_arch_smp_cache_start)

.code32
.Lproof_protected:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs
    leal 4096(%esi), %esp

zigos_arch_smp_cache_first_call:
    call zigos_arch_smp_cache_initialize
    leal (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_FIRST_OFFSET)(%esi), %edi
    call .Lproof_capture_controls
    call .Lproof_require_enabled
    mfence
    movl $1, (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_STATUS_OFFSET)(%esi)

    // The captured enabled DEF_TYPE is independently checked above. No INIT
    // or external MTRR writer intervenes on this offline core.
zigos_arch_smp_cache_second_call:
    call zigos_arch_smp_cache_initialize
    leal (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_SECOND_OFFSET)(%esi), %edi
    call .Lproof_capture_controls
    call .Lproof_require_enabled
    call .Lproof_capture_snapshot
    mfence
    movl $2, (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_STATUS_OFFSET)(%esi)
.Lproof_park:
    cli
    hlt
    jmp .Lproof_park

// Private code32 ABI: ESI is the physical anchor; the actual macro preserves
// it and balances ESP. Other GP registers are caller-clobbered. Its nested
// scratch plus this near-call return fit the reserved128-byte stack.
zigos_arch_smp_cache_initialize:
    ZIGOS_INITIALIZE_AP_MTRRS .Lproof_rejected, (zigos_arch_smp_cache_snapshot - zigos_arch_smp_cache_start), zigos_arch_smp_cache_start
    ret

.Lproof_capture_controls:
    movl %cr0, %eax
    movl %eax, PROOF_CR0_OFFSET(%edi)
    pushfl
    popl %eax
    movl %eax, PROOF_FLAGS_OFFSET(%edi)
    movl $ZIGOS_CACHE_PAT_MSR, %ecx
    rdmsr
    movl %eax, PROOF_PAT_OFFSET(%edi)
    movl %edx, PROOF_PAT_OFFSET+4(%edi)
    movl $ZIGOS_MTRR_DEFAULT_MSR, %ecx
    rdmsr
    movl %eax, PROOF_DEFAULT_OFFSET(%edi)
    movl %edx, PROOF_DEFAULT_OFFSET+4(%edi)
    ret

.Lproof_require_enabled:
    testl $(ZIGOS_CACHE_CR0_PG | ZIGOS_CACHE_CONTROL_MASK), PROOF_CR0_OFFSET(%edi)
    jnz .Lproof_invalid_controls
    testl $(1 << 9), PROOF_FLAGS_OFFSET(%edi)
    jnz .Lproof_invalid_controls
    cmpl $ZIGOS_CACHE_PAT_LOW, PROOF_PAT_OFFSET(%edi)
    jne .Lproof_invalid_controls
    cmpl $ZIGOS_CACHE_PAT_HIGH, PROOF_PAT_OFFSET+4(%edi)
    jne .Lproof_invalid_controls
    movl PROOF_DEFAULT_OFFSET(%edi), %eax
    testl $ZIGOS_MTRR_ENABLE, %eax
    jz .Lproof_invalid_controls
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax
    jne .Lproof_invalid_controls
    movl PROOF_DEFAULT_OFFSET+4(%edi), %eax
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp), %eax
    jne .Lproof_invalid_controls
    ret

// Independent raw acquisition, separate from the macro's comparison helper.
// Preserve zero for unimplemented fixed/variable entries, exactly as the BSP
// snapshot producer does. Capability admission already preceded every RDMSR.
.Lproof_capture_snapshot:
    leal (zigos_arch_smp_cache_result - zigos_arch_smp_cache_start + PROOF_OBSERVED_OFFSET)(%esi), %edi
    pushl %edi
    xorl %eax, %eax
    movl $(ZIGOS_MTRR_SNAPSHOT_BYTES / 4), %ecx
    rep stosl
    popl %edi
    movl $ZIGOS_MTRR_SNAPSHOT_VERSION, ZIGOS_MTRR_VERSION_OFFSET(%edi)
    movl $0x80000008, %eax
    xorl %ecx, %ecx
    cpuid
    andl $0xff, %eax
    movl %eax, ZIGOS_MTRR_WIDTH_OFFSET(%edi)
    movl $ZIGOS_MTRR_CAP_MSR, %ecx
    rdmsr
    movl %eax, ZIGOS_MTRR_CAP_OFFSET(%edi)
    movl %edx, ZIGOS_MTRR_CAP_OFFSET+4(%edi)
    movl $ZIGOS_MTRR_DEFAULT_MSR, %ecx
    rdmsr
    movl %eax, ZIGOS_MTRR_DEFAULT_OFFSET(%edi)
    movl %edx, ZIGOS_MTRR_DEFAULT_OFFSET+4(%edi)
    testl $ZIGOS_MTRR_FIXED_SUPPORT, ZIGOS_MTRR_CAP_OFFSET(%edi)
    jz .Lproof_capture_variable
    xorl %ebx, %ebx
.Lproof_capture_fixed:
    movl (.Lproof_fixed_msrs - zigos_arch_smp_cache_start)(%esi,%ebx,4), %ecx
    rdmsr
    movl %eax, ZIGOS_MTRR_FIXED_OFFSET(%edi,%ebx,8)
    movl %edx, ZIGOS_MTRR_FIXED_OFFSET+4(%edi,%ebx,8)
    incl %ebx
    cmpl $11, %ebx
    jb .Lproof_capture_fixed
.Lproof_capture_variable:
    movzbl ZIGOS_MTRR_CAP_OFFSET(%edi), %eax
    shll $1, %eax
    pushl %eax
    xorl %ebx, %ebx
    movl $ZIGOS_MTRR_VARIABLE_MSR, %ecx
.Lproof_capture_pair:
    cmpl (%esp), %ebx
    je .Lproof_capture_done
    rdmsr
    movl %eax, ZIGOS_MTRR_VARIABLE_OFFSET(%edi,%ebx,8)
    movl %edx, ZIGOS_MTRR_VARIABLE_OFFSET+4(%edi,%ebx,8)
    incl %ecx
    incl %ebx
    jmp .Lproof_capture_pair
.Lproof_capture_done:
    addl $4, %esp
    ret

.Lproof_invalid_controls:
    movl $6, %eax
.Lproof_rejected:
    leal (.Lproof_reject_prefix - zigos_arch_smp_cache_start)(%esi), %esi
    ZIGOS_HALT_BOOTSTRAP_CACHE 32
.Lproof_reject_prefix:
    .asciz "ZIGOS:ARCH:X86_64:AP_CACHE:FAIL:REJECT:"

.balign 8
.Lproof_gdt:
    .quad 0
    .quad 0x00cf9b000000ffff
    .quad 0x00cf93000000ffff
.Lproof_gdt_end:
.Lproof_gdt_pointer:
    .word .Lproof_gdt_end - .Lproof_gdt - 1
    .long 0
.Lproof_far_pointer:
    .long 0
    .word 0x08
.balign 4
.Lproof_fixed_msrs:
    .long 0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f
.balign 8
zigos_arch_smp_cache_snapshot:
    .zero ZIGOS_MTRR_SNAPSHOT_BYTES
zigos_arch_smp_cache_result:
    .zero PROOF_RESULT_BYTES
    // A backward .org rejects overflow before the reserved temporary stack.
    .org zigos_arch_smp_cache_start + 3968, 0
zigos_arch_smp_cache_end:

.section .note.GNU-stack,"",@progbits
