.global context_switch
.type context_switch, @function

# Context switch function
# Parameters:
#   8(%esp) - pointer to old context
#   12(%esp) - pointer to new context
context_switch:
    pushl %ebp
    movl %esp, %ebp
    
    # Save callee-saved registers
    pushl %ebx
    pushl %esi
    pushl %edi
    
    # Get parameters
    movl 8(%ebp), %eax    # old_context pointer
    movl 12(%ebp), %edx   # new_context pointer
    
    # Save old context
    movl %ebx, 4(%eax)    # ebx
    movl %ecx, 8(%eax)    # ecx  
    movl %edx, 12(%eax)   # edx
    movl %esi, 16(%eax)   # esi
    movl %edi, 20(%eax)   # edi
    movl %ebp, 24(%eax)   # ebp
    movl %esp, 28(%eax)   # esp
    
    # Save return address as next EIP
    movl 4(%esp), %ecx
    movl %ecx, 32(%eax)   # eip
    
    # Save EFLAGS
    pushfl
    popl %ecx
    movl %ecx, 36(%eax)   # eflags
    
    # Load new context
    movl 12(%ebp), %edx   # new_context pointer (reload)
    
    # Restore EFLAGS
    movl 36(%edx), %eax
    pushl %eax
    popfl
    
    # Restore registers
    movl 4(%edx), %ebx    # ebx
    movl 8(%edx), %ecx    # ecx
    movl 16(%edx), %esi   # esi
    movl 20(%edx), %edi   # edi
    movl 24(%edx), %ebp   # ebp
    movl 28(%edx), %esp   # esp
    
    # Jump to new process
    movl 32(%edx), %eax   # eip
    movl 12(%edx), %edx   # edx (restore last)
    
    jmp *%eax

.global switch_to_user_mode
.type switch_to_user_mode, @function

# Switch to user mode
# Parameters:
#   4(%esp) - entry point
#   8(%esp) - user stack pointer
switch_to_user_mode:
    movl 4(%esp), %eax    # entry_point
    movl 8(%esp), %edx    # user_stack
    
    cli
    
    # Set up user data segments
    movw $0x23, %bx       # User data segment selector (GDT index 4, RPL 3)
    movw %bx, %ds
    movw %bx, %es
    movw %bx, %fs
    movw %bx, %gs
    
    # Build interrupt return frame on kernel stack
    pushl $0x23           # User SS
    pushl %edx            # User ESP
    pushl $0x202          # EFLAGS (interrupts enabled)
    pushl $0x1B           # User CS (GDT index 3, RPL 3)
    pushl %eax            # User EIP
    
    # Return to user mode
    iret

.global task_switch
.type task_switch, @function

# Preemptive task switch from interrupt handler
# Called with registers already saved on stack
task_switch:
    pushl %ebp
    movl %esp, %ebp
    
    # Call scheduler to get next process
    call schedule
    
    # Check if we need to switch
    testl %eax, %eax
    jz no_switch
    
    # Get current process
    call getCurrentProcess
    testl %eax, %eax
    jz no_switch
    
    # Save current context from stack
    movl %eax, %ebx       # current process in ebx
    addl $8, %ebx         # offset to context structure
    
    # Copy interrupt frame to context
    movl 8(%ebp), %ecx    # Get interrupt frame pointer
    movl (%ecx), %edx
    movl %edx, (%ebx)     # eax
    movl 4(%ecx), %edx
    movl %edx, 8(%ebx)    # ecx
    movl 8(%ecx), %edx
    movl %edx, 12(%ebx)   # edx
    
    # Perform the switch
    pushl %eax            # new process
    call switchToProcess
    addl $4, %esp
    
no_switch:
    movl %ebp, %esp
    popl %ebp
    ret

.global save_process_state
.type save_process_state, @function

# Save complete process state
# Parameter: pointer to Context structure
save_process_state:
    pushl %ebp
    movl %esp, %ebp
    movl 8(%ebp), %eax   # context pointer
    
    # Save general purpose registers
    movl %eax, 0(%eax)    # eax (will be overwritten, saved from parameter)
    movl %ebx, 4(%eax)
    movl %ecx, 8(%eax)
    movl %edx, 12(%eax)
    movl %esi, 16(%eax)
    movl %edi, 20(%eax)
    movl %ebp, 24(%eax)
    movl %esp, 28(%eax)
    
    # Save instruction pointer (return address)
    movl (%esp), %ecx
    movl %ecx, 32(%eax)
    
    # Save flags
    pushfl
    popl %ecx
    movl %ecx, 36(%eax)
    
    # Save CR3 (page directory)
    movl %cr3, %ecx
    movl %ecx, 40(%eax)
    
    # Save segment selectors
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

# Restore complete process state
# Parameter: pointer to Context structure
restore_process_state:
    movl 4(%esp), %eax    # context pointer
    
    # Restore CR3 if different
    movl 40(%eax), %ecx
    movl %cr3, %edx
    cmpl %ecx, %edx
    je skip_cr3
    movl %ecx, %cr3
    
skip_cr3:
    # Restore segment selectors if needed
    movl 48(%eax), %ecx   # ss
    movw %cx, %ss
    
    # Restore general purpose registers
    movl 28(%eax), %esp   # esp
    movl 24(%eax), %ebp   # ebp
    movl 20(%eax), %edi   # edi
    movl 16(%eax), %esi   # esi
    movl 12(%eax), %edx   # edx
    movl 8(%eax), %ecx    # ecx
    movl 4(%eax), %ebx    # ebx
    
    # Restore flags
    movl 36(%eax), %eax
    pushl %eax
    popfl
    
    # Get saved context pointer again
    movl 4(%esp), %eax
    
    # Jump to saved EIP
    movl 32(%eax), %ecx
    movl 0(%eax), %eax    # Restore eax last
    
    jmp *%ecx