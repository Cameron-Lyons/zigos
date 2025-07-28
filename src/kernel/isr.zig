const std = @import("std");
const vga = @import("vga.zig");
const idt = @import("idt.zig");
const keyboard = @import("keyboard.zig");

extern fn isr0() callconv(.Naked) void;
extern fn isr1() callconv(.Naked) void;
extern fn isr2() callconv(.Naked) void;
extern fn isr3() callconv(.Naked) void;
extern fn isr4() callconv(.Naked) void;
extern fn isr5() callconv(.Naked) void;
extern fn isr6() callconv(.Naked) void;
extern fn isr7() callconv(.Naked) void;
extern fn isr8() callconv(.Naked) void;
extern fn isr9() callconv(.Naked) void;
extern fn isr10() callconv(.Naked) void;
extern fn isr11() callconv(.Naked) void;
extern fn isr12() callconv(.Naked) void;
extern fn isr13() callconv(.Naked) void;
extern fn isr14() callconv(.Naked) void;
extern fn isr15() callconv(.Naked) void;
extern fn isr16() callconv(.Naked) void;
extern fn isr17() callconv(.Naked) void;
extern fn isr18() callconv(.Naked) void;
extern fn isr19() callconv(.Naked) void;
extern fn isr20() callconv(.Naked) void;
extern fn isr21() callconv(.Naked) void;
extern fn isr22() callconv(.Naked) void;
extern fn isr23() callconv(.Naked) void;
extern fn isr24() callconv(.Naked) void;
extern fn isr25() callconv(.Naked) void;
extern fn isr26() callconv(.Naked) void;
extern fn isr27() callconv(.Naked) void;
extern fn isr28() callconv(.Naked) void;
extern fn isr29() callconv(.Naked) void;
extern fn isr30() callconv(.Naked) void;
extern fn isr31() callconv(.Naked) void;
extern fn isr128() callconv(.Naked) void;

extern fn irq0() callconv(.Naked) void;
extern fn irq1() callconv(.Naked) void;
extern fn irq2() callconv(.Naked) void;
extern fn irq3() callconv(.Naked) void;
extern fn irq4() callconv(.Naked) void;
extern fn irq5() callconv(.Naked) void;
extern fn irq6() callconv(.Naked) void;
extern fn irq7() callconv(.Naked) void;
extern fn irq8() callconv(.Naked) void;
extern fn irq9() callconv(.Naked) void;
extern fn irq10() callconv(.Naked) void;
extern fn irq11() callconv(.Naked) void;
extern fn irq12() callconv(.Naked) void;
extern fn irq13() callconv(.Naked) void;
extern fn irq14() callconv(.Naked) void;
extern fn irq15() callconv(.Naked) void;

pub const Registers = struct {
    ds: u32,
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    int_no: u32,
    err_code: u32,
    eip: u32,
    cs: u32,
    eflags: u32,
    useresp: u32,
    ss: u32,
};

const exception_messages = [_][]const u8{
    "Division By Zero",
    "Debug",
    "Non Maskable Interrupt",
    "Breakpoint",
    "Into Detected Overflow",
    "Out of Bounds",
    "Invalid Opcode",
    "No Coprocessor",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Bad TSS",
    "Segment Not Present",
    "Stack Fault",
    "General Protection Fault",
    "Page Fault",
    "Unknown Interrupt",
    "Coprocessor Fault",
    "Alignment Check",
    "Machine Check",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
};

pub export fn isrHandler(regs: *Registers) void {
    if (regs.int_no == 14) {
        const paging = @import("paging.zig");
        paging.page_fault_handler(regs);
        return;
    }
    
    vga.print("Received interrupt: ");
    if (regs.int_no < 32) {
        vga.print(exception_messages[regs.int_no]);
        vga.print("\n");
        vga.print("System Halted!\n");
        while (true) {
            asm volatile ("hlt");
        }
    }
}

pub export fn irqHandler(regs: *Registers) void {
    if (regs.int_no >= 40) {
        outb(0xA0, 0x20);
    }
    outb(0x20, 0x20);

    if (regs.int_no == 32) {
        const timer = @import("timer.zig");
        timer.handleInterrupt();
    } else if (regs.int_no == 33) {
        keyboard.handleInterrupt();
    }
}

fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

pub fn init() void {
    idt.setGate(0, &isr0, 0x08, 0x8E);
    idt.setGate(1, &isr1, 0x08, 0x8E);
    idt.setGate(2, &isr2, 0x08, 0x8E);
    idt.setGate(3, &isr3, 0x08, 0x8E);
    idt.setGate(4, &isr4, 0x08, 0x8E);
    idt.setGate(5, &isr5, 0x08, 0x8E);
    idt.setGate(6, &isr6, 0x08, 0x8E);
    idt.setGate(7, &isr7, 0x08, 0x8E);
    idt.setGate(8, &isr8, 0x08, 0x8E);
    idt.setGate(9, &isr9, 0x08, 0x8E);
    idt.setGate(10, &isr10, 0x08, 0x8E);
    idt.setGate(11, &isr11, 0x08, 0x8E);
    idt.setGate(12, &isr12, 0x08, 0x8E);
    idt.setGate(13, &isr13, 0x08, 0x8E);
    idt.setGate(14, &isr14, 0x08, 0x8E);
    idt.setGate(15, &isr15, 0x08, 0x8E);
    idt.setGate(16, &isr16, 0x08, 0x8E);
    idt.setGate(17, &isr17, 0x08, 0x8E);
    idt.setGate(18, &isr18, 0x08, 0x8E);
    idt.setGate(19, &isr19, 0x08, 0x8E);
    idt.setGate(20, &isr20, 0x08, 0x8E);
    idt.setGate(21, &isr21, 0x08, 0x8E);
    idt.setGate(22, &isr22, 0x08, 0x8E);
    idt.setGate(23, &isr23, 0x08, 0x8E);
    idt.setGate(24, &isr24, 0x08, 0x8E);
    idt.setGate(25, &isr25, 0x08, 0x8E);
    idt.setGate(26, &isr26, 0x08, 0x8E);
    idt.setGate(27, &isr27, 0x08, 0x8E);
    idt.setGate(28, &isr28, 0x08, 0x8E);
    idt.setGate(29, &isr29, 0x08, 0x8E);
    idt.setGate(30, &isr30, 0x08, 0x8E);
    idt.setGate(31, &isr31, 0x08, 0x8E);

    remapPIC();

    idt.setGate(32, &irq0, 0x08, 0x8E);
    idt.setGate(33, &irq1, 0x08, 0x8E);
    idt.setGate(34, &irq2, 0x08, 0x8E);
    idt.setGate(35, &irq3, 0x08, 0x8E);
    idt.setGate(36, &irq4, 0x08, 0x8E);
    idt.setGate(37, &irq5, 0x08, 0x8E);
    idt.setGate(38, &irq6, 0x08, 0x8E);
    idt.setGate(39, &irq7, 0x08, 0x8E);
    idt.setGate(40, &irq8, 0x08, 0x8E);
    idt.setGate(41, &irq9, 0x08, 0x8E);
    idt.setGate(42, &irq10, 0x08, 0x8E);
    idt.setGate(43, &irq11, 0x08, 0x8E);
    idt.setGate(44, &irq12, 0x08, 0x8E);
    idt.setGate(45, &irq13, 0x08, 0x8E);
    idt.setGate(46, &irq14, 0x08, 0x8E);
    idt.setGate(47, &irq15, 0x08, 0x8E);
    
    // System call interrupt (int 0x80)
    idt.setGate(128, &isr128, 0x08, 0x8E | 0x60); // DPL=3 to allow userspace calls

    idt.init();
}

fn remapPIC() void {
    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    outb(0x21, 0x20);
    outb(0xA1, 0x28);
    outb(0x21, 0x04);
    outb(0xA1, 0x02);
    outb(0x21, 0x01);
    outb(0xA1, 0x01);
    outb(0x21, 0x0);
    outb(0xA1, 0x0);
}