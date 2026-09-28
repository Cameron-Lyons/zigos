// SysV AMD64 call boundary: integer callee saves and FP control state survive.
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
// Supervisor shadow stacks are not enabled by this kernel. IBT stays enabled.
.text
.globl zigos_worker_swap
.type zigos_worker_swap,@function
zigos_worker_swap:
    endbr64
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
    fnstcw (%rsp)
    stmxcsr 4(%rsp)
    movq %rsp, (%rdi)
    movq (%rsi), %rsp
    fldcw (%rsp)
    ldmxcsr 4(%rsp)
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size zigos_worker_swap, .-zigos_worker_swap

.globl zigos_worker_bootstrap
.type zigos_worker_bootstrap,@function
zigos_worker_bootstrap:
    endbr64
    // Initial synthetic return leaves rsp aligned before this ordinary call.
    movq %r12, %rdi
    call *%r13
    ud2
.size zigos_worker_bootstrap, .-zigos_worker_bootstrap
.section .note.GNU-stack,"",@progbits
