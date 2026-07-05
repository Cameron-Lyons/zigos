.section .multiboot
.align 4
.equ MULTIBOOT_MAGIC, 0x1BADB002
.equ MULTIBOOT_FLAGS, 0x00000007
multiboot_header:
    .long MULTIBOOT_MAGIC
    .long MULTIBOOT_FLAGS
    .long -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)
    .long 0
    .long 0
    .long 0
    .long 32

.section .bss
.align 4096
.equ BOOT_STACK_SIZE, 4194304
.global stack_bottom
stack_bottom:
    /* The native session bootstrap carries substantial typed runtime and
       crypto state before the scheduler hands off to later tasks, and Debug
       builds need several times the ReleaseFast frame depth. Keep the BSP
       boot stack comfortably above the deepest compiled frame chain. The
       page at stack_bottom is kept page-aligned so paging.init can unmap it
       as a guard page: an overflow then faults immediately instead of
       silently corrupting the globals below the stack. */
    .skip BOOT_STACK_SIZE
stack_top:

.section .text
.global _start
.extern kernel_main
.extern zigos_multiboot_magic
.extern zigos_multiboot_info_addr

_start:
    mov %eax, zigos_multiboot_magic
    mov %ebx, zigos_multiboot_info_addr
    mov $stack_top, %esp
    call kernel_main
    
.hang:
    cli
    hlt
    jmp .hang
