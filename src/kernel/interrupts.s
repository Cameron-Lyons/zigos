.section .text
.extern syscall_handler

.global isr128
.type isr128, @function
isr128:
    cli
    pushl $0    # Dummy error code
    pushl $128  # Interrupt number
    jmp isr_common_stub

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
    
    mov 44(%esp), %eax  # Get interrupt number
    cmp $128, %eax
    je handle_syscall
    
    call isrHandler
    jmp isr_exit
    
handle_syscall:
    call syscall_handler
    
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
