.section .text

.extern zigos_userspace_resume_esp
.extern zigos_userspace_resume_eip

.section .bss
.align 4
zigos_userspace_saved_ebx:
    .long 0
zigos_userspace_saved_esi:
    .long 0
zigos_userspace_saved_edi:
    .long 0

.section .text

.global zigos_enter_userspace
.type zigos_enter_userspace, @function
zigos_enter_userspace:
    push %ebp
    mov %esp, %ebp
    mov %ebx, zigos_userspace_saved_ebx
    mov %esi, zigos_userspace_saved_esi
    mov %edi, zigos_userspace_saved_edi

    mov %esp, zigos_userspace_resume_esp
    mov $resume_from_userspace, %eax
    mov %eax, zigos_userspace_resume_eip

    mov 8(%ebp), %eax
    mov 12(%ebp), %edx

    push $0x23
    push %edx
    pushf
    pop %ecx
    or $0x200, %ecx
    push %ecx
    push $0x1B
    push %eax
    iret

resume_from_userspace:
    mov zigos_userspace_saved_ebx, %ebx
    mov zigos_userspace_saved_esi, %esi
    mov zigos_userspace_saved_edi, %edi
    mov $1, %eax
    pop %ebp
    ret

.global zigos_resume_from_userspace_interrupt
.type zigos_resume_from_userspace_interrupt, @function
zigos_resume_from_userspace_interrupt:
    mov zigos_userspace_resume_esp, %esp
    jmp *zigos_userspace_resume_eip
