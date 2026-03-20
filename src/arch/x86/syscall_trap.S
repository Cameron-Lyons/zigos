.text

.globl syscall_regcall_asm
.type syscall_regcall_asm, @function
syscall_regcall_asm:
    int $0x80
    ret

.globl syscall0_asm
.type syscall0_asm, @function
syscall0_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

.globl syscall1_asm
.type syscall1_asm, @function
syscall1_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

.globl syscall2_asm
.type syscall2_asm, @function
syscall2_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    mov 16(%ebp), %ecx
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

.globl syscall3_asm
.type syscall3_asm, @function
syscall3_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    mov 16(%ebp), %ecx
    mov 20(%ebp), %edx
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

.globl syscall4_asm
.type syscall4_asm, @function
syscall4_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    mov 16(%ebp), %ecx
    mov 20(%ebp), %edx
    mov 24(%ebp), %esi
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

.globl syscall5_asm
.type syscall5_asm, @function
syscall5_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    mov 16(%ebp), %ecx
    mov 20(%ebp), %edx
    mov 24(%ebp), %esi
    mov 28(%ebp), %edi
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret

.globl syscall6_asm
.type syscall6_asm, @function
syscall6_asm:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %esi
    push %edi

    mov 8(%ebp), %eax
    mov 12(%ebp), %ebx
    mov 16(%ebp), %ecx
    mov 20(%ebp), %edx
    mov 24(%ebp), %esi
    mov 28(%ebp), %edi
    mov 32(%ebp), %ebp
    call syscall_regcall_asm

    pop %edi
    pop %esi
    pop %ebx
    pop %ebp
    ret
