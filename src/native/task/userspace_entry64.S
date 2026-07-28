.section .text

.extern zigos_userspace_resume_esp
.extern zigos_userspace_resume_eip

.global zigos_enter_userspace
.type zigos_enter_userspace, @function
zigos_enter_userspace:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, zigos_userspace_resume_esp(%rip)
    leaq .resume_from_userspace(%rip), %rax
    movq %rax, zigos_userspace_resume_eip(%rip)

    pushq $0x23
    pushq %rsi
    pushfq
    popq %rcx
    orq $0x200, %rcx
    pushq %rcx
    pushq $0x1b
    pushq %rdi
    iretq

.resume_from_userspace:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    movl $1, %eax
    popq %rbp
    ret

.global zigos_resume_from_userspace_interrupt
.type zigos_resume_from_userspace_interrupt, @function
zigos_resume_from_userspace_interrupt:
    movq zigos_userspace_resume_esp(%rip), %rsp
    jmp *zigos_userspace_resume_eip(%rip)

.section .note.GNU-stack,"",@progbits
