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
    ; Set up the stack
    mov esp, stack_top
    
    ; Clear interrupts
    cli
    
    ; Call the kernel main function
    call kernel_main
    
    ; Halt the CPU if kernel_main returns
.hang:
    cli
    hlt
    jmp .hang