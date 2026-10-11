// Bounded, pointer-free SIPI payload. Numeric definitions do not add ABS symbols.
#define ZIGOS_MTRR_SNAPSHOT_VERSION 1
#define ZIGOS_MTRR_SNAPSHOT_BYTES 624
#define ZIGOS_MTRR_VERSION_OFFSET 0
#define ZIGOS_MTRR_WIDTH_OFFSET 4
#define ZIGOS_MTRR_CAP_OFFSET 8
#define ZIGOS_MTRR_DEFAULT_OFFSET 16
#define ZIGOS_MTRR_FIXED_OFFSET 24
#define ZIGOS_MTRR_VARIABLE_OFFSET 112
#define ZIGOS_MTRR_MAX_VARIABLE 32
#define ZIGOS_MTRR_CAP_MSR 0xfe
#define ZIGOS_MTRR_DEFAULT_MSR 0x2ff
#define ZIGOS_MTRR_VARIABLE_MSR 0x200
#define ZIGOS_MTRR_ENABLE 0x800
#define ZIGOS_MTRR_FIXED_ENABLE 0x400
#define ZIGOS_MTRR_FIXED_SUPPORT 0x100
#define ZIGOS_MTRR_WC_SUPPORT 0x400
#define ZIGOS_MTRR_CPUID_SUPPORT 0x1000

// ESI is the physical bridge anchor; ESP points inside its reserved last128
// bytes. EBP becomes the payload pointer. All operands are preflighted before
// any WRMSR. Only E=0 may be repaired: MTRRs may be SMT-shared, so an enabled
// mismatch must halt, and an enabled exact match performs no MTRR writes.
// Intel SDM12.11.8: IF0/PG0, CD1NW0, WBINVD/TLB flush, disabled MTRRs,
// programming/readback, enabled policy, second WBINVD/TLB flush, CD0NW0.
.macro ZIGOS_INITIALIZE_AP_MTRRS reject payload anchor
    cli
    movl %cr0, %eax
    testl $ZIGOS_CACHE_CR0_PG, %eax
    jnz .Lmtrr_bad\@
    leal \payload(%esi), %ebp
    cmpl $ZIGOS_MTRR_SNAPSHOT_VERSION, ZIGOS_MTRR_VERSION_OFFSET(%ebp)
    jne .Lmtrr_bad\@
    xorl %eax, %eax
    xorl %ecx, %ecx
    cpuid
    cmpl $1, %eax
    jb .Lmtrr_bad\@
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    testl $ZIGOS_MTRR_CPUID_SUPPORT, %edx
    jz .Lmtrr_bad\@
    testl $ZIGOS_CACHE_CPUID_PAT, %edx
    jz .Lmtrr_bad\@
    movl $ZIGOS_CACHE_PAT_MSR, %ecx
    rdmsr
    cmpl $ZIGOS_CACHE_PAT_LOW, %eax
    jne .Lmtrr_bad\@
    cmpl $ZIGOS_CACHE_PAT_HIGH, %edx
    jne .Lmtrr_bad\@
    movl $0x80000000, %eax
    xorl %ecx, %ecx
    cpuid
    cmpl $0x80000008, %eax
    jb .Lmtrr_bad\@
    movl $0x80000008, %eax
    xorl %ecx, %ecx
    cpuid
    andl $0xff, %eax
    cmpl $32, %eax
    jb .Lmtrr_bad\@
    cmpl $52, %eax
    ja .Lmtrr_bad\@
    cmpl ZIGOS_MTRR_WIDTH_OFFSET(%ebp), %eax
    jne .Lmtrr_bad\@
    movl $ZIGOS_MTRR_CAP_MSR, %ecx
    rdmsr
    cmpl ZIGOS_MTRR_CAP_OFFSET(%ebp), %eax
    jne .Lmtrr_bad\@
    cmpl ZIGOS_MTRR_CAP_OFFSET+4(%ebp), %edx
    jne .Lmtrr_bad\@
    andl $0xff, %eax
    cmpl $ZIGOS_MTRR_MAX_VARIABLE, %eax
    ja .Lmtrr_bad\@
    movl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax
    cmpl $0, ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp)
    jne .Lmtrr_bad\@
    testl $~0xcff, %eax
    jnz .Lmtrr_bad\@
    testl $ZIGOS_MTRR_ENABLE, %eax
    jz .Lmtrr_bad\@
    testl $ZIGOS_MTRR_FIXED_ENABLE, %eax
    jz .Lmtrr_default_type\@
    testl $ZIGOS_MTRR_FIXED_SUPPORT, ZIGOS_MTRR_CAP_OFFSET(%ebp)
    jz .Lmtrr_bad\@
.Lmtrr_default_type\@:
    call .Lmtrr_type\@
    testl $ZIGOS_MTRR_FIXED_SUPPORT, ZIGOS_MTRR_CAP_OFFSET(%ebp)
    jz .Lmtrr_variable_preflight\@
    leal ZIGOS_MTRR_FIXED_OFFSET(%ebp), %ebx
    movl $88, %edi
.Lmtrr_fixed_preflight\@:
    movzbl (%ebx), %eax
    call .Lmtrr_type\@
    incl %ebx
    decl %edi
    jnz .Lmtrr_fixed_preflight\@
.Lmtrr_variable_preflight\@:
    movl ZIGOS_MTRR_WIDTH_OFFSET(%ebp), %ecx
    subl $32, %ecx
    movl $1, %edi
    shll %cl, %edi
    decl %edi
    movzbl ZIGOS_MTRR_CAP_OFFSET(%ebp), %eax
    shll $4, %eax
    leal ZIGOS_MTRR_VARIABLE_OFFSET(%ebp), %ebx
    addl %ebx, %eax
    pushl %eax
.Lmtrr_pair_preflight\@:
    cmpl (%esp), %ebx
    je .Lmtrr_preflight_done\@
    movl (%ebx), %eax
    testl $0xf00, %eax
    jnz .Lmtrr_bad\@
    call .Lmtrr_type\@
    movl %edi, %eax
    notl %eax
    testl %eax, 4(%ebx)
    jnz .Lmtrr_bad\@
    testl %eax, 12(%ebx)
    jnz .Lmtrr_bad\@
    testl $0x7ff, 8(%ebx)
    jnz .Lmtrr_bad\@
    testl $ZIGOS_MTRR_ENABLE, 8(%ebx)
    jz .Lmtrr_next_pair\@
    // The inverted address mask is a contiguous low-ones size-1 value.
    movl 8(%ebx), %eax
    notl %eax
    orl $0xfff, %eax
    movl 12(%ebx), %edx
    notl %edx
    andl %edi, %edx
    pushl %edx
    movl %eax, %ecx
    addl $1, %ecx
    adcl $0, %edx
    andl (%esp), %edx
    jnz .Lmtrr_bad\@
    testl %ecx, %eax
    jnz .Lmtrr_bad\@
    popl %edx
    testl %edx, 4(%ebx)
    jnz .Lmtrr_bad\@
    andl $~0xfff, %eax
    testl %eax, (%ebx)
    jnz .Lmtrr_bad\@
.Lmtrr_next_pair\@:
    addl $16, %ebx
    jmp .Lmtrr_pair_preflight\@
.Lmtrr_preflight_done\@:
    addl $4, %esp
    movl $ZIGOS_MTRR_DEFAULT_MSR, %ecx
    rdmsr
    testl $ZIGOS_MTRR_ENABLE, %eax
    jz .Lmtrr_repair\@
    // Never disable an enabled policy, even when it belongs to this AP.
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax
    jne .Lmtrr_bad\@
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp), %edx
    jne .Lmtrr_bad\@
    call .Lmtrr_compare\@
    ZIGOS_ENABLE_AP_CACHES \reject
    jmp .Lmtrr_done\@
.Lmtrr_repair\@:
    movl %cr0, %eax
    andl $~ZIGOS_CACHE_CR0_NW, %eax
    orl $ZIGOS_CACHE_CR0_CD, %eax
    movl %eax, %cr0
    wbinvd
    // INIT clears translations. Explicitly flush retained controls as well;
    // paging remains off throughout the local offline-AP initialization.
    movl %cr4, %eax
    andl $~((1 << 7) | (1 << 17)), %eax
    movl %eax, %cr4
    movl %cr3, %eax
    movl %eax, %cr3
    movl $ZIGOS_MTRR_DEFAULT_MSR, %ecx
    movl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax
    andl $~ZIGOS_MTRR_ENABLE, %eax
    movl ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp), %edx
    wrmsr
    call .Lmtrr_program\@
    call .Lmtrr_compare\@
    movl $ZIGOS_MTRR_DEFAULT_MSR, %ecx
    rdmsr
    movl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %ebx
    andl $~ZIGOS_MTRR_ENABLE, %ebx
    cmpl %ebx, %eax
    jne .Lmtrr_bad\@
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp), %edx
    jne .Lmtrr_bad\@
    movl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax
    movl ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp), %edx
    wrmsr
    rdmsr
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET(%ebp), %eax
    jne .Lmtrr_bad\@
    cmpl ZIGOS_MTRR_DEFAULT_OFFSET+4(%ebp), %edx
    jne .Lmtrr_bad\@
    wbinvd
    movl %cr3, %eax
    movl %eax, %cr3
    movl %cr0, %eax
    andl $~ZIGOS_CACHE_CONTROL_MASK, %eax
    movl %eax, %cr0
    jmp .Lmtrr_done\@

// Both loops include all implemented disabled pairs and all supported fixed
// registers. The producer has validated their WRMSR encodings even when FE=0.
.Lmtrr_program\@:
    movl $1, %edi
    jmp .Lmtrr_registers\@
.Lmtrr_compare\@:
    xorl %edi, %edi
.Lmtrr_registers\@:
    pushl %edi
    testl $ZIGOS_MTRR_FIXED_SUPPORT, ZIGOS_MTRR_CAP_OFFSET(%ebp)
    jz .Lmtrr_variable_registers\@
    leal ZIGOS_MTRR_FIXED_OFFSET(%ebp), %ebx
    xorl %edi, %edi
.Lmtrr_fixed_registers\@:
    movl (.Lmtrr_fixed_msrs\@ - \anchor)(%esi,%edi,4), %ecx
    cmpl $0, (%esp)
    je .Lmtrr_fixed_read\@
    movl (%ebx), %eax
    movl 4(%ebx), %edx
    wrmsr
    jmp .Lmtrr_fixed_next\@
.Lmtrr_fixed_read\@:
    rdmsr
    cmpl (%ebx), %eax
    jne .Lmtrr_bad\@
    cmpl 4(%ebx), %edx
    jne .Lmtrr_bad\@
.Lmtrr_fixed_next\@:
    addl $8, %ebx
    incl %edi
    cmpl $11, %edi
    jb .Lmtrr_fixed_registers\@
.Lmtrr_variable_registers\@:
    movzbl ZIGOS_MTRR_CAP_OFFSET(%ebp), %edi
    shll $1, %edi
    leal ZIGOS_MTRR_VARIABLE_OFFSET(%ebp), %ebx
    movl $ZIGOS_MTRR_VARIABLE_MSR, %ecx
.Lmtrr_variable_register\@:
    testl %edi, %edi
    jz .Lmtrr_registers_done\@
    cmpl $0, (%esp)
    je .Lmtrr_variable_read\@
    movl (%ebx), %eax
    movl 4(%ebx), %edx
    wrmsr
    jmp .Lmtrr_variable_next\@
.Lmtrr_variable_read\@:
    rdmsr
    cmpl (%ebx), %eax
    jne .Lmtrr_bad\@
    cmpl 4(%ebx), %edx
    jne .Lmtrr_bad\@
.Lmtrr_variable_next\@:
    addl $8, %ebx
    incl %ecx
    decl %edi
    jmp .Lmtrr_variable_register\@
.Lmtrr_registers_done\@:
    addl $4, %esp
    ret
.Lmtrr_type\@:
    andl $0xff, %eax
    cmpl $0, %eax
    je .Lmtrr_type_valid\@
    cmpl $1, %eax
    jne .Lmtrr_non_wc\@
    testl $ZIGOS_MTRR_WC_SUPPORT, ZIGOS_MTRR_CAP_OFFSET(%ebp)
    jz .Lmtrr_bad\@
    ret
.Lmtrr_non_wc\@:
    cmpl $4, %eax
    jb .Lmtrr_bad\@
    cmpl $6, %eax
    ja .Lmtrr_bad\@
.Lmtrr_type_valid\@:
    ret
.Lmtrr_bad\@:
    movl $5, %eax
    jmp \reject
.align 4
.Lmtrr_fixed_msrs\@:
    .long 0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f
.Lmtrr_done\@:
.endm
