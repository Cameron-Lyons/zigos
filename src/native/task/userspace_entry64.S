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

    pushq $0x1b
    pushq 136(%rdi)
    pushq 128(%rdi)
    pushq $0x23
    pushq 120(%rdi)

    movq 8(%rdi), %rbx
    movq 16(%rdi), %rcx
    movq 24(%rdi), %rdx
    movq 32(%rdi), %rbp
    movq 40(%rdi), %rsi
    movq 56(%rdi), %r8
    movq 64(%rdi), %r9
    movq 72(%rdi), %r10
    movq 80(%rdi), %r11
    movq 88(%rdi), %r12
    movq 96(%rdi), %r13
    movq 104(%rdi), %r14
    movq 112(%rdi), %r15
    movq 0(%rdi), %rax
    movq 48(%rdi), %rdi
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
