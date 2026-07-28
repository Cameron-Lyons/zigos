.section .multiboot2,"a",@progbits
.align 8
.equ MULTIBOOT2_HEADER_MAGIC, 0xe85250d6
.equ MULTIBOOT2_ARCH_I386, 0
multiboot2_header_start:
    .long MULTIBOOT2_HEADER_MAGIC
    .long MULTIBOOT2_ARCH_I386
    .long multiboot2_header_end - multiboot2_header_start
    .long -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT2_ARCH_I386 + (multiboot2_header_end - multiboot2_header_start))
    .short 0
    .short 0
    .long 8
multiboot2_header_end:

.section .data
.align 4
.global long_mode_multiboot_magic
long_mode_multiboot_magic:
    .long 0
.global long_mode_multiboot_info
long_mode_multiboot_info:
    .long 0

.section .rodata
.align 8
boot_gdt:
    .quad 0x0000000000000000
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
boot_gdt_end:

boot_gdt_pointer:
    .word boot_gdt_end - boot_gdt - 1
    .long boot_gdt

.section .bss
.align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_page_directory:
    .skip 4096

.align 16
.equ BOOT_STACK_BYTES, 65536
boot_stack_bottom:
    .skip BOOT_STACK_BYTES
boot_stack_top:

.section .text.boot
.code32
.global _start
.type _start, @function
.extern long_mode_probe_main

.equ CR0_EM, (1 << 2)
.equ CR0_MP, (1 << 1)
.equ CR0_PG, (1 << 31)
.equ CR4_PAE, (1 << 5)
.equ CR4_OSFXSR, (1 << 9)
.equ CR4_OSXMMEXCPT, (1 << 10)
.equ EFER_MSR, 0xc0000080
.equ EFER_LME, (1 << 8)
.equ PAGE_PRESENT_WRITABLE, 0x3
.equ LARGE_PAGE_PRESENT_WRITABLE, 0x83
.equ IDENTITY_LARGE_PAGE_COUNT, 64
.equ LONG_MODE_CODE_SELECTOR, 0x08
.equ LONG_MODE_DATA_SELECTOR, 0x10

_start:
    cli
    movl %eax, long_mode_multiboot_magic
    movl %ebx, long_mode_multiboot_info
    movl $boot_stack_top, %esp
    xorl %ebp, %ebp

    cld
    xorl %eax, %eax
    movl $boot_pml4, %edi
    movl $((4096 * 3) / 4), %ecx
    rep stosl

    movl $boot_pdpt, %eax
    orl $PAGE_PRESENT_WRITABLE, %eax
    movl %eax, boot_pml4

    movl $boot_page_directory, %eax
    orl $PAGE_PRESENT_WRITABLE, %eax
    movl %eax, boot_pdpt

    movl $boot_page_directory, %edi
    movl $LARGE_PAGE_PRESENT_WRITABLE, %eax
    xorl %edx, %edx
    movl $IDENTITY_LARGE_PAGE_COUNT, %ecx
.map_identity_page:
    movl %eax, (%edi)
    movl %edx, 4(%edi)
    addl $0x00200000, %eax
    addl $8, %edi
    loop .map_identity_page

    movl $boot_pml4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT), %eax
    movl %eax, %cr4

    movl %cr0, %eax
    andl $~CR0_EM, %eax
    orl $CR0_MP, %eax
    movl %eax, %cr0
    fninit

    movl $EFER_MSR, %ecx
    rdmsr
    orl $EFER_LME, %eax
    wrmsr

    lgdt boot_gdt_pointer
    movl %cr0, %eax
    orl $CR0_PG, %eax
    movl %eax, %cr0
    ljmp $LONG_MODE_CODE_SELECTOR, $long_mode_start

.code64
long_mode_start:
    movw $LONG_MODE_DATA_SELECTOR, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movq $boot_stack_top, %rsp
    xorq %rbp, %rbp

    movl long_mode_multiboot_magic(%rip), %edi
    movl long_mode_multiboot_info(%rip), %esi
    call long_mode_probe_main

.halt:
    cli
    hlt
    jmp .halt

.section .note.GNU-stack,"",@progbits
