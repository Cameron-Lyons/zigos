.section .bss,"aw",@nobits
.align 4096
# Native smoke tests require at least 25% unused watermark headroom.
.equ BOOT_STACK_SIZE, 708 * 1024
.global stack_bottom
stack_bottom:
    .skip BOOT_STACK_SIZE
.global stack_top
stack_top:

.section .text.boot,"ax",@progbits
#include "../arch/x86_64/codegen_preflight.inc"
.code64
.global zigos_efi_entry
.type zigos_efi_entry, @function
.extern kernel_main
.extern zigos_multiboot_magic
.extern zigos_multiboot_info_addr
zigos_efi_entry:
    endbr64
    cli
    cld
    # Firmware has already mapped the upper-half image and physical window.
    # The tagged handoff still carries physical addresses on the wire.
    movl %edi, zigos_multiboot_info_addr(%rip)
    movl $0x36D76289, zigos_multiboot_magic(%rip)
    leaq stack_top(%rip), %rsp
    xorq %rbp, %rbp
    ZIGOS_REQUIRE_BOOTSTRAP_CACHE .Lcache_bsp_rejected, 64
    ZIGOS_REQUIRE_NATIVE .halt
    ZIGOS_ENABLE_NATIVE_XSTATE
    call kernel_main
.halt:
    cli
    hlt
    jmp .halt
.Lcache_bsp_rejected:
    leaq .Lcache_bsp_prefix(%rip), %rsi
    ZIGOS_HALT_BOOTSTRAP_CACHE 64
.Lcache_bsp_prefix:
    .asciz "ZIGOS:BOOT:CACHE:BSP:REJECT:"
.size zigos_efi_entry, .-zigos_efi_entry

.section .note.GNU-stack,"",@progbits
