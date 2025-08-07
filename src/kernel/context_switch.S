.global context_switch
.type context_switch, @function

context_switch:
    pushl %ebp
    movl %esp, %ebp
    
    movl 8(%ebp), %eax    # old_context
    movl 12(%ebp), %ecx   # new_context
    
    movl %ebx, 4(%eax)    # ebx
    movl %esi, 24(%eax)   # esi
    movl %edi, 20(%eax)   # edi
    movl %ebp, 24(%eax)   # ebp
    movl %esp, 28(%eax)   # esp
    
    movl (%esp), %edx
    movl %edx, 32(%eax)   # eip
    
    movl 4(%ecx), %ebx    # ebx
    movl 24(%ecx), %esi   # esi
    movl 20(%ecx), %edi   # edi
    movl 24(%ecx), %ebp   # ebp
    movl 28(%ecx), %esp   # esp
    
    movl 32(%ecx), %eax   # eip
    pushl %eax
    
    ret

.global switch_to_user_mode
.type switch_to_user_mode, @function

switch_to_user_mode:
    movl 4(%esp), %eax    # entry_point
    movl 8(%esp), %edx    # user_stack
    
    cli
    
    movw $0x23, %bx       # User data segment selector
    movw %bx, %ds
    movw %bx, %es
    movw %bx, %fs
    movw %bx, %gs
    
    pushl $0x23           # User SS
    pushl %edx            # User ESP
    pushl $0x202          # EFLAGS (interrupts enabled)
    pushl $0x1B           # User CS
    pushl %eax            # User EIP
    
    iret
