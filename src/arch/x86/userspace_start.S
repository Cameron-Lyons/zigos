.section .text

.globl _start
.type _start, @function
.extern zigos_userspace_contract_main
_start:
    and $-16, %rsp
    call zigos_userspace_contract_main
    ud2

.section .text.zigos_probe_nx,"ax",@progbits
.globl zigos_probe_nx
.type zigos_probe_nx, @function
zigos_probe_nx:
    pushq %r15
    leaq .Lnx_recovery(%rip), %r15
    jmp *%rdi
.Lnx_recovery:
    popq %r15
    ret

.section .text.zigos_probe_gp,"ax",@progbits
.globl zigos_probe_gp
.type zigos_probe_gp, @function
zigos_probe_gp:
    hlt
    ret

.section .note.GNU-stack,"",@progbits
