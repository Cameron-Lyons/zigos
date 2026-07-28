.section .text

.global gdt_flush
.type gdt_flush, @function
gdt_flush:
    lgdtq (%rdi)

    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    pushq $0x08
    lea .reload_cs(%rip), %rax
    pushq %rax
    lretq
.reload_cs:
    ret

.global tss_flush
.type tss_flush, @function
tss_flush:
    mov $0x28, %ax
    ltr %ax
    ret

.section .note.GNU-stack,"",@progbits
