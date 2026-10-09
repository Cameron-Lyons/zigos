.section .bss,"aw",@nobits
.balign 64
.Lnative_crypto_stack_bottom:
    .skip 65536
.Lnative_crypto_stack_top:

.section .text.boot,"ax",@progbits
#include "codegen_preflight.inc"
.code64
.global zigos_efi_entry
.type zigos_efi_entry, @function
.extern native_crypto_probe_main
zigos_efi_entry:
    endbr64
    cli
    cld
    movq %rdi, %r8
    leaq .Lnative_crypto_stack_top(%rip), %rsp
    xorq %rbp, %rbp
    ZIGOS_REQUIRE_NATIVE .Lnative_crypto_rejected
    ZIGOS_ENABLE_NATIVE_XSTATE
    # Emulate firmware that leaves a non-default floating-point environment.
    pushq $0x7f80
    ldmxcsr (%rsp)
    movw $0x0f7f, (%rsp)
    fldcw (%rsp)
    addq $8, %rsp
    ZIGOS_ENABLE_NATIVE_XSTATE
    call native_crypto_probe_main

.Lnative_crypto_rejected:
    movl $0x11, %eax
    movw $0xF4, %dx
    outl %eax, %dx
.Lnative_crypto_halted:
    cli
    hlt
    jmp .Lnative_crypto_halted
.size zigos_efi_entry, .-zigos_efi_entry

.section .note.GNU-stack,"",@progbits
