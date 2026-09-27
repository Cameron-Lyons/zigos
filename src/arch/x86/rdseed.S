.section .text
.code64

# RDSEED r64 uses CPUID.7.0:EBX[18]. Only CF=1 publishes a word.
# REX.W + 0F C7 /7; the pinned Zig encoder does not recognize the mnemonic.
.global x86_rdseed64
.type x86_rdseed64, @function
x86_rdseed64:
    .byte 0x48, 0x0f, 0xc7, 0xf8
    jnc .Lrdseed_unavailable
    mov %rax, (%rdi)
    mov $1, %eax
    ret
.Lrdseed_unavailable:
    xor %eax, %eax
    ret
.size x86_rdseed64, . - x86_rdseed64

.section .note.GNU-stack,"",@progbits
