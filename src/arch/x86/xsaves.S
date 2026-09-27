.section .text
.code64

.global x86_write_xcr0
.type x86_write_xcr0, @function
x86_write_xcr0:
    movl %edi, %eax
    movq %rdi, %rdx
    shrq $32, %rdx
    xorl %ecx, %ecx
    .byte 0x0f, 0x01, 0xd1
    ret
.size x86_write_xcr0, . - x86_write_xcr0

.global x86_read_xcr0
.type x86_read_xcr0, @function
x86_read_xcr0:
    xorl %ecx, %ecx
    .byte 0x0f, 0x01, 0xd0
    movl %eax, %eax
    shlq $32, %rdx
    orq %rdx, %rax
    ret
.size x86_read_xcr0, . - x86_read_xcr0

.section .note.GNU-stack,"",@progbits
