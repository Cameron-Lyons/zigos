const gdt = @import("gdt.zig");
const idt = @import("idt.zig");
const io = @import("../utils/io.zig");

const GateHandler = *const fn () callconv(.c) void;

const IDT_INTERRUPT_GATE: u8 = 0x8E;
const IDT_USER_DPL: u8 = 0x60;
const EXCEPTION_VECTOR_COUNT: u32 = 32;
const DOUBLE_FAULT_VECTOR: u8 = 8;
const PAGE_FAULT_VECTOR: u32 = 14;
const IRQ_BASE_VECTOR: u8 = 32;
const IRQ_SLAVE_BASE_VECTOR: u32 = 40;
const TIMER_IRQ_VECTOR: u32 = 32;
const SYSCALL_VECTOR: u8 = 128;
const NATIVE_SYSCALL_VECTOR: u8 = 129;

const PIC_MASTER_COMMAND_PORT: u16 = 0x20;
const PIC_MASTER_DATA_PORT: u16 = 0x21;
const PIC_SLAVE_COMMAND_PORT: u16 = 0xA0;
const PIC_SLAVE_DATA_PORT: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;
const PIC_ICW1_INIT: u8 = 0x10;
const PIC_ICW1_EXPECT_ICW4: u8 = 0x01;
const PIC_ICW4_8086: u8 = 0x01;
const PIC_MASTER_OFFSET: u8 = 0x20;
const PIC_SLAVE_OFFSET: u8 = 0x28;
const PIC_MASTER_HAS_SLAVE_ON_IRQ2: u8 = 0x04;
const PIC_SLAVE_CASCADE_ID: u8 = 0x02;
const PIC_TIMER_IRQ_BIT: u8 = 1 << 0;
// Only the bootstrap PIT has a live PIC line. Every other line stays masked
// so unowned legacy IRQ sources cannot inject interrupts the dispatch table
// would drop after a blind EOI.
const PIC_MASTER_MASK: u8 = ~PIC_TIMER_IRQ_BIT;
const PIC_SLAVE_MASK_ALL: u8 = 0xFF;

extern fn isr0() void;
extern fn isr1() void;
extern fn isr2() void;
extern fn isr3() void;
extern fn isr4() void;
extern fn isr5() void;
extern fn isr6() void;
extern fn isr7() void;
extern fn isr8() void;
extern fn isr9() void;
extern fn isr10() void;
extern fn isr11() void;
extern fn isr12() void;
extern fn isr13() void;
extern fn isr14() void;
extern fn isr15() void;
extern fn isr16() void;
extern fn isr17() void;
extern fn isr18() void;
extern fn isr19() void;
extern fn isr20() void;
extern fn isr21() void;
extern fn isr22() void;
extern fn isr23() void;
extern fn isr24() void;
extern fn isr25() void;
extern fn isr26() void;
extern fn isr27() void;
extern fn isr28() void;
extern fn isr29() void;
extern fn isr30() void;
extern fn isr31() void;
extern fn isr128() void;
extern fn isr129() void;

extern fn irq0() void;
extern fn irq1() void;
extern fn irq2() void;
extern fn irq3() void;
extern fn irq4() void;
extern fn irq5() void;
extern fn irq6() void;
extern fn irq7() void;
extern fn irq8() void;
extern fn irq9() void;
extern fn irq10() void;
extern fn irq11() void;
extern fn irq12() void;
extern fn irq13() void;
extern fn irq14() void;
extern fn irq15() void;

const exception_stubs = [_]GateHandler{
    &isr0,
    &isr1,
    &isr2,
    &isr3,
    &isr4,
    &isr5,
    &isr6,
    &isr7,
    &isr8,
    &isr9,
    &isr10,
    &isr11,
    &isr12,
    &isr13,
    &isr14,
    &isr15,
    &isr16,
    &isr17,
    &isr18,
    &isr19,
    &isr20,
    &isr21,
    &isr22,
    &isr23,
    &isr24,
    &isr25,
    &isr26,
    &isr27,
    &isr28,
    &isr29,
    &isr30,
    &isr31,
};

const irq_stubs = [_]GateHandler{
    &irq0,
    &irq1,
    &irq2,
    &irq3,
    &irq4,
    &irq5,
    &irq6,
    &irq7,
    &irq8,
    &irq9,
    &irq10,
    &irq11,
    &irq12,
    &irq13,
    &irq14,
    &irq15,
};

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
    if (custom_handlers[regs.int_no]) |handler| {
        const frame: *InterruptFrame = @ptrCast(regs);
        handler(frame);
        return;
    }

    if (regs.int_no == PAGE_FAULT_VECTOR) {
        const paging = @import("../memory/paging.zig");
        paging.page_fault_handler(regs);
        return;
    }

    const console = @import("../utils/console.zig");
    console.print("Received interrupt: ");
    if (regs.int_no < EXCEPTION_VECTOR_COUNT) {
        console.print(exception_messages[regs.int_no]);
        console.print("\n");
        console.print("System Halted!\n");
        while (true) {
            asm volatile ("hlt");
        }
    }
}
pub const InterruptFrame = Registers;
pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

var custom_handlers: [idt.IDT_ENTRIES]?InterruptHandler = [_]?InterruptHandler{null} ** idt.IDT_ENTRIES;

pub fn registerHandler(vector: u8, handler: InterruptHandler) void {
    custom_handlers[vector] = handler;
}

pub export fn irqHandler(regs: *Registers) void {
    if (regs.int_no >= IRQ_SLAVE_BASE_VECTOR) {
        io.outb(PIC_SLAVE_COMMAND_PORT, PIC_EOI);
    }
    io.outb(PIC_MASTER_COMMAND_PORT, PIC_EOI);

    if (custom_handlers[regs.int_no]) |handler| {
        const frame: *InterruptFrame = @ptrCast(regs);
        handler(frame);
    } else if (regs.int_no == TIMER_IRQ_VECTOR) {
        const timer = @import("../timer/timer.zig");
        timer.handleInterrupt();
    }
}

pub fn init() void {
    for (exception_stubs, 0..) |stub, vector| {
        setKernelGate(@as(u8, @intCast(vector)), stub);
    }

    // A double fault after a stack overflow cannot push an exception frame on
    // the broken stack; without a task gate it silently escalates to a triple
    // fault and the machine resets with no output at all.
    gdt.configureDoubleFaultTask(@intFromPtr(&doubleFaultTask));
    idt.setTaskGate(DOUBLE_FAULT_VECTOR, gdt.DOUBLE_FAULT_TSS_SEG);

    remapPIC();

    for (irq_stubs, 0..) |stub, irq| {
        setKernelGate(@as(u8, @intCast(@as(usize, IRQ_BASE_VECTOR) + irq)), stub);
    }

    setUserGate(SYSCALL_VECTOR, &isr128);
    setUserGate(NATIVE_SYSCALL_VECTOR, &isr129);

    idt.init();
}

fn doubleFaultTask() callconv(.c) noreturn {
    // The hardware task switch sets CR0.TS; clear it so the panic path may
    // use SSE without raising a device-not-available fault mid-report.
    asm volatile ("clts");
    const context = gdt.interruptedContext();
    const panic_utils = @import("../utils/panic.zig");
    panic_utils.panic(
        "DOUBLE FAULT: eip=0x{x:0>8} esp=0x{x:0>8} ebp=0x{x:0>8} (likely kernel stack overflow)",
        .{ context.eip, context.esp, context.ebp },
    );
}

fn setKernelGate(vector: u8, handler: GateHandler) void {
    idt.setGate(vector, handler, gdt.KERNEL_CODE_SEG, IDT_INTERRUPT_GATE);
}

fn setUserGate(vector: u8, handler: GateHandler) void {
    idt.setGate(vector, handler, gdt.KERNEL_CODE_SEG, IDT_INTERRUPT_GATE | IDT_USER_DPL);
}

fn remapPIC() void {
    io.outb(PIC_MASTER_COMMAND_PORT, PIC_ICW1_INIT | PIC_ICW1_EXPECT_ICW4);
    io.outb(PIC_SLAVE_COMMAND_PORT, PIC_ICW1_INIT | PIC_ICW1_EXPECT_ICW4);
    io.outb(PIC_MASTER_DATA_PORT, PIC_MASTER_OFFSET);
    io.outb(PIC_SLAVE_DATA_PORT, PIC_SLAVE_OFFSET);
    io.outb(PIC_MASTER_DATA_PORT, PIC_MASTER_HAS_SLAVE_ON_IRQ2);
    io.outb(PIC_SLAVE_DATA_PORT, PIC_SLAVE_CASCADE_ID);
    io.outb(PIC_MASTER_DATA_PORT, PIC_ICW4_8086);
    io.outb(PIC_SLAVE_DATA_PORT, PIC_ICW4_8086);
    io.outb(PIC_MASTER_DATA_PORT, PIC_MASTER_MASK);
    io.outb(PIC_SLAVE_DATA_PORT, PIC_SLAVE_MASK_ALL);
}
