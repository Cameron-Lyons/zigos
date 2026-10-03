// SysV AMD64 call boundary: integer callee saves and FP control state survive.
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
// Supervisor shadow stacks are not enabled by this kernel. IBT stays enabled.
#if defined(__APPLE__)
#define ZIGOS_WORKER_SYMBOL(name) _##name
#else
#define ZIGOS_WORKER_SYMBOL(name) name
#endif

.text
.globl ZIGOS_WORKER_SYMBOL(zigos_worker_swap)
#if !defined(__APPLE__)
.type zigos_worker_swap,@function
#endif
ZIGOS_WORKER_SYMBOL(zigos_worker_swap):
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
#if !defined(__APPLE__)
.size zigos_worker_swap, .-zigos_worker_swap
#endif

.globl ZIGOS_WORKER_SYMBOL(zigos_worker_bootstrap)
#if !defined(__APPLE__)
.type zigos_worker_bootstrap,@function
#endif
ZIGOS_WORKER_SYMBOL(zigos_worker_bootstrap):
    endbr64
    // Initial synthetic return leaves rsp aligned before this ordinary call.
    movq %r12, %rdi
    call *%r13
    ud2
#if !defined(__APPLE__)
.size zigos_worker_bootstrap, .-zigos_worker_bootstrap
.section .note.GNU-stack,"",@progbits
#endif
