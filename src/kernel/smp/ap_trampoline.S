.section .text

.set AP_TRAMPOLINE_BASE, 0x8000
.set AP_BOOT_TARGET_STRIDE, 12

.global ap_trampoline_start
.global ap_trampoline_end
.global ap_trampoline_boot_cr3
.global ap_trampoline_target_table
.global ap_trampoline_target_count
.global ap_trampoline_local_apic_base
.global ap_trampoline_ap_main

.code16
ap_trampoline_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    lgdt AP_TRAMPOLINE_BASE + (ap_trampoline_gdt_descriptor - ap_trampoline_start)

    movl %cr0, %eax
    orl $0x1, %eax
    movl %eax, %cr0

    ljmp $0x08, $AP_TRAMPOLINE_BASE + (ap_trampoline_entry32 - ap_trampoline_start)

.code32
ap_trampoline_entry32:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movl %cr0, %eax
    andl $0xfffffffb, %eax
    orl $0x2, %eax
    movl %eax, %cr0

    movl %cr4, %eax
    orl $0x600, %eax
    movl %eax, %cr4

    fninit

    movl AP_TRAMPOLINE_BASE + (ap_trampoline_boot_cr3 - ap_trampoline_start), %eax
    testl %eax, %eax
    jz ap_trampoline_find_cpu

    movl %eax, %cr3
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0

ap_trampoline_find_cpu:
    movl $1, %eax
    cpuid
    movl %ebx, %eax
    shrl $24, %eax

    movl AP_TRAMPOLINE_BASE + (ap_trampoline_target_table - ap_trampoline_start), %esi
    movl AP_TRAMPOLINE_BASE + (ap_trampoline_target_count - ap_trampoline_start), %ecx

ap_trampoline_scan_targets:
    testl %ecx, %ecx
    jz ap_trampoline_halt

    cmpl %eax, 0(%esi)
    je ap_trampoline_target_found

    addl $AP_BOOT_TARGET_STRIDE, %esi
    decl %ecx
    jmp ap_trampoline_scan_targets

ap_trampoline_target_found:
    movl 4(%esi), %esp
    movl %esp, %ebp
    movl 8(%esi), %eax
    pushl %eax

    movl AP_TRAMPOLINE_BASE + (ap_trampoline_ap_main - ap_trampoline_start), %edx
    call *%edx

ap_trampoline_halt:
    cli
    hlt
    jmp ap_trampoline_halt

.align 8
ap_trampoline_gdt:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
ap_trampoline_gdt_descriptor:
    .word ap_trampoline_gdt_end - ap_trampoline_gdt - 1
    .long AP_TRAMPOLINE_BASE + (ap_trampoline_gdt - ap_trampoline_start)
ap_trampoline_gdt_end:

.align 4
ap_trampoline_boot_cr3:
    .long 0
ap_trampoline_target_table:
    .long 0
ap_trampoline_target_count:
    .long 0
ap_trampoline_local_apic_base:
    .long 0
ap_trampoline_ap_main:
    .long 0

ap_trampoline_end:
