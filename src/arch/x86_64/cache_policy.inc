// Numeric preprocessing constants avoid resident ABS symbols. Keep this full
// bootstrap contract synchronized with arch/cache_policy.zig's embedded test.
#define ZIGOS_CACHE_PAT_MSR 0x277
#define ZIGOS_CACHE_CPUID_PAT 0x10000
#define ZIGOS_CACHE_CONTROL_MASK 0x60000000
#define ZIGOS_CACHE_CR0_CD 0x40000000
#define ZIGOS_CACHE_CR0_NW 0x20000000
#define ZIGOS_CACHE_CR0_PG 0x80000000
#define ZIGOS_CACHE_PAT_LOW 0x00070406
#define ZIGOS_CACHE_PAT_HIGH 0x00070406
#define ZIGOS_CACHE_WB_SELECTOR 0
#define ZIGOS_CACHE_UC_SELECTOR 0x18

// INIT retains CD/NW and cache contents; a cold AP may still have reset's
// disabled controls. Intel SDM10.3/12.5.3: enter no-fill, write back/invalidate,
// then enable normal caching. Only the AP bridge before paging may do this;
// This helper does not write PAT or MTRRs. The SIPI MTRR bootstrap separately
// initializes only a disabled AP policy before this cache enablement.
.macro ZIGOS_ENABLE_AP_CACHES reject
    cli
    movl %cr0, %eax
    testl $ZIGOS_CACHE_CR0_PG, %eax
    jnz .Lcache_ap_live_paging\@
    andl $~ZIGOS_CACHE_CR0_NW, %eax
    orl $ZIGOS_CACHE_CR0_CD, %eax
    movl %eax, %cr0
    wbinvd
    movl %cr0, %eax
    andl $~ZIGOS_CACHE_CONTROL_MASK, %eax
    movl %eax, %cr0
    jmp .Lcache_ap_enabled\@
.Lcache_ap_live_paging\@:
    movl $4, %eax
    jmp \reject
.Lcache_ap_enabled\@:
.endm

// Baseline 32/64-bit instructions only; no stack or GS required. CPUID
// clobbers EBX, so an AP bridge must preserve its anchor before invoking this.
// Reject code EAX: 1 = PAT unsupported, 2 = CD/NW, 3 = noncanonical PAT.
.macro ZIGOS_REQUIRE_BOOTSTRAP_CACHE reject bits=64
    xorl %eax, %eax
    xorl %ecx, %ecx
    cpuid
    cmpl $1, %eax
    jb .Lcache_unsupported\@
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    testl $ZIGOS_CACHE_CPUID_PAT, %edx
    jz .Lcache_unsupported\@
    .if \bits == 64
    movq %cr0, %rax
    .else
    movl %cr0, %eax
    .endif
    testl $ZIGOS_CACHE_CONTROL_MASK, %eax
    jnz .Lcache_disabled\@
    movl $ZIGOS_CACHE_PAT_MSR, %ecx
    rdmsr
    cmpl $ZIGOS_CACHE_PAT_LOW, %eax
    jne .Lcache_layout\@
    cmpl $ZIGOS_CACHE_PAT_HIGH, %edx
    jne .Lcache_layout\@
    jmp .Lcache_admitted\@
.Lcache_unsupported\@:
    movl $1, %eax
    jmp \reject
.Lcache_disabled\@:
    movl $2, %eax
    jmp \reject
.Lcache_layout\@:
    movl $3, %eax
    jmp \reject
.Lcache_admitted\@:
.endm

// RSI/ESI points to this caller's addressable NUL-terminated rejection prefix.
// Emit the reason code with a bounded UART wait, then halt with IF clear.
.macro ZIGOS_HALT_BOOTSTRAP_CACHE bits
    cli
    movl %eax, %ebx
.Lcache_next\@:
    .if \bits == 64
    movb (%rsi), %ah
    incq %rsi
    .else
    movb (%esi), %ah
    incl %esi
    .endif
    testb %ah, %ah
    jz .Lcache_reason\@
    movl $10000, %ecx
.Lcache_wait\@:
    movw $0x3fd, %dx
    inb %dx, %al
    testb $0x20, %al
    jnz .Lcache_emit\@
    pause
    loop .Lcache_wait\@
.Lcache_emit\@:
    movw $0x3f8, %dx
    movb %ah, %al
    outb %al, %dx
    jmp .Lcache_next\@
.Lcache_reason\@:
    movw $0x3f8, %dx
    movb %bl, %al
    addb $'0', %al
    outb %al, %dx
    movb $13, %al
    outb %al, %dx
    movb $10, %al
    outb %al, %dx
.Lcache_park\@:
    hlt
    jmp .Lcache_park\@
.endm
