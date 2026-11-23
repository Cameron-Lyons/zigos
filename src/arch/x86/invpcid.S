.section .text
.code64

.global x86_invalidate_pcid
.type x86_invalidate_pcid, @function
x86_invalidate_pcid:
    mov $1, %rcx
    .byte 0x66, 0x0f, 0x38, 0x82, 0x0f
    ret
.size x86_invalidate_pcid, . - x86_invalidate_pcid

.global x86_invalidate_pcid_address
.type x86_invalidate_pcid_address, @function
x86_invalidate_pcid_address:
    # INVPCID type 0 retires one linear address in one process context.
    xor %ecx, %ecx
    .byte 0x66, 0x0f, 0x38, 0x82, 0x0f
    ret
.size x86_invalidate_pcid_address, . - x86_invalidate_pcid_address

.global x86_invalidate_all
.type x86_invalidate_all, @function
x86_invalidate_all:
    # INVPCID type 2 includes global translations in every process context.
    mov $2, %rcx
    .byte 0x66, 0x0f, 0x38, 0x82, 0x0f
    ret
.size x86_invalidate_all, . - x86_invalidate_all

.section .note.GNU-stack,"",@progbits
