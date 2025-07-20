; Multiboot header
section .multiboot
align 4
    dd 0x1BADB002              ; Magic number
    dd 0x00                    ; Flags
    dd -(0x1BADB002 + 0x00)   ; Checksum

section .bss
align 16
stack_bottom:
    resb 16384                 ; 16KB stack
stack_top:

section .text
global _start
extern kernel_main

_start:
    mov esp, stack_top
    
    cli
    
    call kernel_main
    
.hang:
    cli
    hlt
    jmp .hang
