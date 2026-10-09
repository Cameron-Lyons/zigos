#ifndef ZIGOS_IDT_RETURN64_INC
#define ZIGOS_IDT_RETURN64_INC

#define IDT_KERNEL_CODE_SELECTOR 0x08
#define IDT_USER_DATA_SEGMENT 0x18
#define IDT_USER_DATA_SELECTOR 0x1b
#define IDT_USER_CODE_SELECTOR 0x23
#define IDT_SELECTOR_RPL_MASK 0x3
#define IDT_FRAME_RIP 152
#define IDT_FRAME_CS 160
#define IDT_FRAME_RFLAGS 168
#define IDT_FRAME_USER_RSP 176
#define IDT_FRAME_USER_SS 184
#define IDT_RFLAGS_RESERVED 0x2
#define IDT_RFLAGS_FORBIDDEN_RETURN 0x27000

// The frame's GPRs are already saved. Both macros clobber only RAX and flags.
// Kernel frames omit user RSP/SS, so branch before touching those fields.
// The caller retains its GDT descriptor checks on the user fallthrough path.
.macro ZIGOS_IDT_VALIDATE_RETURN_PREFIX frame, invalid, kernel
    movq IDT_FRAME_CS(\frame), %rax
    cmpq $IDT_KERNEL_CODE_SELECTOR, %rax
    je \kernel
    cmpq $IDT_USER_CODE_SELECTOR, %rax
    jne \invalid
    // Normalize only RPL after proving the exact user-data GDT slot.
    movq IDT_FRAME_USER_SS(\frame), %rax
    andq $~IDT_SELECTOR_RPL_MASK, %rax
    cmpq $IDT_USER_DATA_SEGMENT, %rax
    jne \invalid
    orq $IDT_SELECTOR_RPL_MASK, IDT_FRAME_USER_SS(\frame)
    movq IDT_FRAME_USER_RSP(\frame), %rax
    shrq $47, %rax
    jne \invalid
.endm

// CS has been admitted by the prefix. CPL0 may return into either canonical
// 48-bit half; CPL3 stays in the lower half. LA57 is not enabled by this ABI.
.macro ZIGOS_IDT_VALIDATE_RETURN_RIP_FLAGS frame, invalid
    movq IDT_FRAME_RIP(\frame), %rax
    cmpq $IDT_KERNEL_CODE_SELECTOR, IDT_FRAME_CS(\frame)
    jne .Lidt_user_rip\@
    sarq $47, %rax
    // A signed canonical extension is exactly 0 or -1; both become <= 1.
    addq $1, %rax
    cmpq $1, %rax
    ja \invalid
    jmp .Lidt_return_flags\@
.Lidt_user_rip\@:
    shrq $47, %rax
    jne \invalid
.Lidt_return_flags\@:
    movq IDT_FRAME_RFLAGS(\frame), %rax
    testq $IDT_RFLAGS_RESERVED, %rax
    jz \invalid
    testq $IDT_RFLAGS_FORBIDDEN_RETURN, %rax
    jnz \invalid
.endm

#endif
