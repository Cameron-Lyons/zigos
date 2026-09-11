.section .text

.global smp_trampoline_start
.global smp_trampoline_end
.global smp_trampoline_cr3
.global smp_trampoline_cr4
.global smp_trampoline_efer
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

    movl (smp_trampoline_cr3 - smp_trampoline_start)(%ebx), %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT), %eax
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

.code64
smp_long_mode:
    movw $DATA64_SEL, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    movq (smp_trampoline_cr4 - smp_trampoline_start)(%rbx), %rax
    movq %rax, %cr4
    movq (smp_trampoline_stack - smp_trampoline_start)(%rbx), %rsp
    xorq %rbp, %rbp
    movq (smp_trampoline_cpu - smp_trampoline_start)(%rbx), %rdi
    movq (smp_trampoline_entry - smp_trampoline_start)(%rbx), %rax
    jmpq *%rax

.align 16
smp_trampoline_gdt:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
    .quad 0x00af92000000ffff
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
smp_trampoline_cr4:
    .quad 0
smp_trampoline_efer:
    .quad 0
smp_trampoline_entry:
    .quad 0
smp_trampoline_stack:
    .quad 0
smp_trampoline_cpu:
    .quad 0

smp_trampoline_end:

.section .note.GNU-stack,"",@progbits
