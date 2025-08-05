.global context_switch
.type context_switch, @function

# context_switch(old_context: *Context, new_context: *Context)
context_switch:
    # Save caller-saved registers
    pushl %ebp
    movl %esp, %ebp
    
    # Get arguments
    movl 8(%ebp), %eax    # old_context
    movl 12(%ebp), %ecx   # new_context
    
    # Save old context
    movl %ebx, 4(%eax)    # ebx
    movl %esi, 24(%eax)   # esi
    movl %edi, 20(%eax)   # edi
    movl %ebp, 24(%eax)   # ebp
    movl %esp, 28(%eax)   # esp
    
    # Save return address as eip
    movl (%esp), %edx
    movl %edx, 32(%eax)   # eip
    
    # Load new context
    movl 4(%ecx), %ebx    # ebx
    movl 24(%ecx), %esi   # esi
    movl 20(%ecx), %edi   # edi
    movl 24(%ecx), %ebp   # ebp
    movl 28(%ecx), %esp   # esp
    
    # Push return address
    movl 32(%ecx), %eax   # eip
    pushl %eax
    
    # Return to new context
    ret

.global switch_to_user_mode
.type switch_to_user_mode, @function

# switch_to_user_mode(entry_point: u32, user_stack: u32)
switch_to_user_mode:
    # Get arguments
    movl 4(%esp), %eax    # entry_point
    movl 8(%esp), %edx    # user_stack
    
    cli
    
    # Set up data segments for user mode
    movw $0x23, %bx       # User data segment selector
    movw %bx, %ds
    movw %bx, %es
    movw %bx, %fs
    movw %bx, %gs
    
    # Set up the stack for iret
    pushl $0x23           # User SS
    pushl %edx            # User ESP
    pushl $0x202          # EFLAGS (interrupts enabled)
    pushl $0x1B           # User CS
    pushl %eax            # User EIP
    
    # Return to user mode
    iret