.section .text
.global gdt_flush
.type gdt_flush, @function

gdt_flush:
    mov 4(%esp), %eax  # Get the pointer to the GDT
    lgdt (%eax)        # Load the new GDT pointer
    
    mov $0x10, %ax     # 0x10 is the offset to our data segment
    mov %ax, %ds       # Load all data segment selectors
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    
    ljmp $0x08, $.reload_cs  # 0x08 is the offset to our code segment
.reload_cs:
    ret

.global tss_flush
.type tss_flush, @function

tss_flush:
    mov $0x2B, %ax     # Load the index of our TSS structure
    ltr %ax            # Load the task register
    ret