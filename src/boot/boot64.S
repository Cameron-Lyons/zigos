.section .multiboot
.align 4
multiboot_header:
    .long 0x1BADB002                # Multiboot magic number
    .long 0x00                      # Flags
    .long -(0x1BADB002 + 0x00)     # Checksum

.section .bss
.align 16
stack_bottom:
    .skip 16384                     # 16KB stack
stack_top:

.section .text
.global _start
.extern kernel_main

_start:
    mov $stack_top, %esp
    call kernel_main
    
.hang:
    cli
    hlt
    jmp .hang