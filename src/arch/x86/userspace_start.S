.section .text

.globl _start
.type _start, @function
.extern zigos_userspace_contract_main
_start:
    mov $0x23, %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
#if defined(__x86_64__)
    and $-16, %rsp
#endif
    call zigos_userspace_contract_main
    ud2

.section .note.GNU-stack,"",@progbits
