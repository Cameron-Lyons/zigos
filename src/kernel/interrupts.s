.section .text
.extern syscall_handler

# System call entry point (int 0x80)
.global isr128
.type isr128, @function
isr128:
    cli
    pushl $0    # Dummy error code
    pushl $128  # Interrupt number
    jmp isr_common_stub

# Common interrupt stub that calls our handler
.global isr_common_stub
.type isr_common_stub, @function
isr_common_stub:
    # Save all registers
    pushal
    
    # Save data segment
    mov %ds, %ax
    push %eax
    
    # Load kernel data segment
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    
    # Push pointer to stack (registers struct)
    push %esp
    
    # Check if this is a system call
    mov 44(%esp), %eax  # Get interrupt number
    cmp $128, %eax
    je handle_syscall
    
    # Not a system call, call normal ISR handler
    call isrHandler
    jmp isr_exit
    
handle_syscall:
    # Call system call handler
    call syscall_handler
    
isr_exit:
    # Remove pushed pointer
    add $4, %esp
    
    # Restore data segment
    pop %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    
    # Restore registers
    popal
    
    # Remove interrupt number and error code
    add $8, %esp
    
    # Return from interrupt
    sti
    iret