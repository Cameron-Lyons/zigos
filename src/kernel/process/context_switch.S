.global context_switch
.type context_switch, @function

context_switch:
    pushl %ebp
    movl %esp, %ebp
    
    pushl %ebx
    pushl %esi
    pushl %edi
    
    movl 8(%ebp), %eax    # old_context pointer
    movl 12(%ebp), %edx   # new_context pointer
    
    movl %ebx, 4(%eax)    # ebx
    movl %ecx, 8(%eax)    # ecx  
    movl %edx, 12(%eax)   # edx
    movl %esi, 16(%eax)   # esi
    movl %edi, 20(%eax)   # edi
    movl %ebp, 24(%eax)   # ebp
    movl %esp, 28(%eax)   # esp
    
    movl 4(%esp), %ecx
    movl %ecx, 32(%eax)   # eip
    
    pushfl
    popl %ecx
    movl %ecx, 36(%eax)   # eflags
    
    movl 12(%ebp), %edx   # new_context pointer (reload)
    
    movl 36(%edx), %eax
    pushl %eax
    popfl
    
    movl 4(%edx), %ebx    # ebx
    movl 8(%edx), %ecx    # ecx
    movl 16(%edx), %esi   # esi
    movl 20(%edx), %edi   # edi
    movl 24(%edx), %ebp   # ebp
    movl 28(%edx), %esp   # esp
    
    movl 32(%edx), %eax   # eip
    movl 12(%edx), %edx   # edx (restore last)
    
    jmp *%eax

.global switch_to_user_mode
.type switch_to_user_mode, @function

switch_to_user_mode:
    movl 4(%esp), %eax    # entry_point
    movl 8(%esp), %edx    # user_stack
    
    cli
    
    movw $0x23, %bx       # User data segment selector (GDT index 4, RPL 3)
    movw %bx, %ds
    movw %bx, %es
    movw %bx, %fs
    movw %bx, %gs
    
    pushl $0x23           # User SS
    pushl %edx            # User ESP
    pushl $0x202          # EFLAGS (interrupts enabled)
    pushl $0x1B           # User CS (GDT index 3, RPL 3)
    pushl %eax            # User EIP
    
    iret

.global task_switch
.type task_switch, @function

task_switch:
    pushl %ebp
    movl %esp, %ebp
    
    call schedule
    
    testl %eax, %eax
    jz no_switch
    
    call getCurrentProcess
    testl %eax, %eax
    jz no_switch
    
    movl %eax, %ebx       # current process in ebx
    addl $8, %ebx         # offset to context structure
    
    movl 8(%ebp), %ecx    # Get interrupt frame pointer
    movl (%ecx), %edx
    movl %edx, (%ebx)     # eax
    movl 4(%ecx), %edx
    movl %edx, 8(%ebx)    # ecx
    movl 8(%ecx), %edx
    movl %edx, 12(%ebx)   # edx
    
    pushl %eax            # new process
    call switchToProcess
    addl $4, %esp
    
no_switch:
    movl %ebp, %esp
    popl %ebp
    ret

.global save_process_state
.type save_process_state, @function

save_process_state:
    pushl %ebp
    movl %esp, %ebp
    movl 8(%ebp), %eax   # context pointer
    
    movl %eax, 0(%eax)    # eax (will be overwritten, saved from parameter)
    movl %ebx, 4(%eax)
    movl %ecx, 8(%eax)
    movl %edx, 12(%eax)
    movl %esi, 16(%eax)
    movl %edi, 20(%eax)
    movl %ebp, 24(%eax)
    movl %esp, 28(%eax)
    
    movl (%esp), %ecx
    movl %ecx, 32(%eax)
    
    pushfl
    popl %ecx
    movl %ecx, 36(%eax)
    
    movl %cr3, %ecx
    movl %ecx, 40(%eax)
    
    xorl %ecx, %ecx
    movw %cs, %cx
    movl %ecx, 44(%eax)
    movw %ss, %cx
    movl %ecx, 48(%eax)
    
    movl %ebp, %esp
    popl %ebp
    ret

.global restore_process_state  
.type restore_process_state, @function

restore_process_state:
    movl 4(%esp), %eax    # context pointer
    
    movl 40(%eax), %ecx
    movl %cr3, %edx
    cmpl %ecx, %edx
    je skip_cr3
    movl %ecx, %cr3
    
skip_cr3:
    movl 48(%eax), %ecx   # ss
    movw %cx, %ss
    
    movl 28(%eax), %esp   # esp
    movl 24(%eax), %ebp   # ebp
    movl 20(%eax), %edi   # edi
    movl 16(%eax), %esi   # esi
    movl 12(%eax), %edx   # edx
    movl 8(%eax), %ecx    # ecx
    movl 4(%eax), %ebx    # ebx
    
    movl 36(%eax), %eax
    pushl %eax
    popfl
    
    movl 4(%esp), %eax
    
    movl 32(%eax), %ecx
    movl 0(%eax), %eax    # Restore eax last
    
    jmp *%ecx
