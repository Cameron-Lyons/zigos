.section .text
.code64

.global x86_invalidate_pcid
.type x86_invalidate_pcid, @function
x86_invalidate_pcid:
    mov $1, %rcx
    .byte 0x66, 0x0f, 0x38, 0x82, 0x0f
    ret
.size x86_invalidate_pcid, . - x86_invalidate_pcid

.section .note.GNU-stack,"",@progbits
