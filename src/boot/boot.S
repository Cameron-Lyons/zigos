.section .multiboot
.align 4
    .long 0x1BADB002              # Magic number
    .long 0x00                    # Flags
    .long -(0x1BADB002 + 0x00)   # Checksum

.section .bss
.align 16
stack_bottom:
    .skip 16384                   # 16KB stack
stack_top:

.section .text
.global _start
.extern kernel_main

_start:
    movl $stack_top, %esp
    
    cli
    
    call kernel_main
    
.hang:
    cli
    hlt
    jmp .hang