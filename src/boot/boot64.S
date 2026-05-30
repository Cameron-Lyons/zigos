.section .multiboot
.align 4
multiboot_header:
    .long 0x1BADB002
    .long 0x00
    .long -(0x1BADB002 + 0x00)

.section .bss
.align 16
.equ BOOT_STACK_SIZE, 1048576
stack_bottom:
    /* The native session bootstrap now carries substantial typed runtime and
       crypto state before the scheduler hands off to later tasks. Keep the
       BSP boot stack comfortably above the compiled session_manager frame. */
    .skip BOOT_STACK_SIZE
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
