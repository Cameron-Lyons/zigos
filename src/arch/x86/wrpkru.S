.section .text
.code64

.global x86_wrpkru
.type x86_wrpkru, @function
x86_wrpkru:
    xor %ecx, %ecx
    xor %edx, %edx
    .byte 0x0f, 0x01, 0xef
    ret
.size x86_wrpkru, . - x86_wrpkru

.section .note.GNU-stack,"",@progbits
