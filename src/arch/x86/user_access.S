.section .text
.code64

.global x86_allow_supervisor_user_memory
.type x86_allow_supervisor_user_memory, @function
x86_allow_supervisor_user_memory:
    stac
    ret
.size x86_allow_supervisor_user_memory, . - x86_allow_supervisor_user_memory

.global x86_forbid_supervisor_user_memory
.type x86_forbid_supervisor_user_memory, @function
x86_forbid_supervisor_user_memory:
    clac
    ret
.size x86_forbid_supervisor_user_memory, . - x86_forbid_supervisor_user_memory

.section .note.GNU-stack,"",@progbits
