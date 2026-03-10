.section .text
.extern syscall_handler

.global isr_common_stub
.type isr_common_stub, @function
isr_common_stub:
    pushal
    
    mov %ds, %ax
    push %eax
    
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    
    push %esp
    
    mov 40(%esp), %eax  # Get interrupt number
    cmp $128, %eax
    je handle_syscall
    
    call isrHandler
    jmp isr_exit
    
handle_syscall:
    mov (%esp), %eax
    add $4, %eax
    push %eax
    call syscall_handler
    add $4, %esp
    
isr_exit:
    add $4, %esp
    
    pop %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    
    popal
    
    add $8, %esp
    
    sti
    iret
