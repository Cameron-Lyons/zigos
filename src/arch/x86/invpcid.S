.section .text
.code64

.global x86_invalidate_pcid
.type x86_invalidate_pcid, @function
x86_invalidate_pcid:
    # INVPCID type 1 invalidates every non-global translation for the PCID in
    # the descriptor. The runtime CPU baseline guarantees instruction support.
    mov $1, %rcx
    .byte 0x66, 0x0f, 0x38, 0x82, 0x0f
    ret
.size x86_invalidate_pcid, . - x86_invalidate_pcid

.section .note.GNU-stack,"",@progbits
