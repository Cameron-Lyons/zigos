.section .text
.global _start
.extern main
.extern __zigos_exit

_start:
    mov $0xBFFFF000, %edx
    mov (%edx), %eax
    mov 4(%edx), %ebx
    mov 8(%edx), %ecx
    push %ecx
    push %ebx
    push %eax
    call main
    add $12, %esp
    push %eax
    call __zigos_exit

.hang:
    jmp .hang
