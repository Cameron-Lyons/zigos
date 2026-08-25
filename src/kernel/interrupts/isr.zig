const std = @import("std");
const interrupt_context = @import("context.zig");
const gdt = @import("gdt64.zig");
const idt = @import("idt64.zig");
const io = @import("../utils/io.zig");
const console = @import("../utils/console.zig");
const numfmt = @import("../utils/numfmt.zig");
const timer = @import("../timer/timer.zig");
const intel_i225_hw = @import("../drivers/intel_i225_hw.zig");
const nvme_hw = @import("../drivers/nvme_hw.zig");
const xhci_hw = @import("../drivers/xhci_hw.zig");

const GateHandler = *const fn () callconv(.c) void;

const IDT_INTERRUPT_GATE: u8 = 0x8E;
const EXCEPTION_VECTOR_COUNT: u32 = 32;
const DOUBLE_FAULT_VECTOR: u8 = 8;
const PAGE_FAULT_VECTOR: u32 = 14;
const REQUESTED_PRIVILEGE_LEVEL_MASK: usize = 0x3;
const USER_PRIVILEGE_LEVEL: usize = 0x3;

const PIC_MASTER_DATA_PORT: u16 = 0x21;
const PIC_SLAVE_DATA_PORT: u16 = 0xA1;
const PIC_MASK_ALL: u8 = 0xFF;

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
extern fn isr64() void;
extern fn isr65() void;
extern fn isr66() void;
extern fn isr67() void;
extern fn isr255() void;

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

pub const Registers = extern struct {
    ds: usize,
    r15: usize,
    r14: usize,
    r13: usize,
    r12: usize,
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    edi: usize,
    esi: usize,
    ebp: usize,
    esp: usize,
    ebx: usize,
    edx: usize,
    ecx: usize,
    eax: usize,
    int_no: usize,
    err_code: usize,
    eip: usize,
    cs: usize,
    eflags: usize,
    useresp: usize,
    ss: usize,
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
    interrupt_context.enter();
    defer interrupt_context.leave();
    const vector = interruptVector(regs);
    if (custom_handlers[vector]) |handler| {
        const frame: *InterruptFrame = @ptrCast(regs);
        handler(frame);
        return;
    }

    if (vector == PAGE_FAULT_VECTOR) {
        const paging = @import("../memory/paging64.zig");
        paging.page_fault_handler(regs);
        return;
    }

    if (vector < EXCEPTION_VECTOR_COUNT) {
        haltUnhandledException(regs);
    }
}
pub const InterruptFrame = Registers;
pub const InterruptHandler = *const fn (regs: *InterruptFrame) void;

var custom_handlers: [idt.IDT_ENTRIES]?InterruptHandler = [_]?InterruptHandler{null} ** idt.IDT_ENTRIES;

pub fn registerHandler(vector: u8, handler: InterruptHandler) void {
    custom_handlers[vector] = handler;
}

pub fn init() void {
    for (exception_stubs, 0..) |stub, vector| {
        setKernelGate(@as(u8, @intCast(vector)), stub);
    }

    gdt.configureDoubleFaultIst();
    idt.setIstGate(
        DOUBLE_FAULT_VECTOR,
        &isr8,
        gdt.KERNEL_CODE_SEG,
        IDT_INTERRUPT_GATE,
        gdt.DOUBLE_FAULT_IST_INDEX,
    );
    registerHandler(DOUBLE_FAULT_VECTOR, doubleFaultInterrupt);

    disableLegacyPic();
    setKernelGate(timer.INTERRUPT_VECTOR, &isr64);
    registerHandler(timer.INTERRUPT_VECTOR, timerInterrupt);
    setKernelGate(intel_i225_hw.INTERRUPT_VECTOR, &isr65);
    registerHandler(intel_i225_hw.INTERRUPT_VECTOR, i225Interrupt);
    setKernelGate(nvme_hw.INTERRUPT_VECTOR, &isr66);
    registerHandler(nvme_hw.INTERRUPT_VECTOR, nvmeInterrupt);
    setKernelGate(xhci_hw.INTERRUPT_VECTOR, &isr67);
    registerHandler(xhci_hw.INTERRUPT_VECTOR, xhciInterrupt);
    setKernelGate(timer.SPURIOUS_VECTOR, &isr255);
    registerHandler(timer.SPURIOUS_VECTOR, spuriousInterrupt);

    idt.init();
}

fn doubleFaultInterrupt(frame: *InterruptFrame) void {
    const panic_utils = @import("../utils/panic.zig");
    panic_utils.panic(
        "DOUBLE FAULT: instruction=0x{x} stack=0x{x} frame=0x{x}",
        .{ frame.eip, frame.useresp, frame.ebp },
    );
}

fn timerInterrupt(_: *InterruptFrame) void {
    timer.handleInterrupt();
}

fn i225Interrupt(_: *InterruptFrame) void {
    intel_i225_hw.handleInterrupt();
}

fn nvmeInterrupt(_: *InterruptFrame) void {
    nvme_hw.handleInterrupt();
}

fn xhciInterrupt(_: *InterruptFrame) void {
    xhci_hw.handleInterrupt();
}

fn spuriousInterrupt(_: *InterruptFrame) void {
    timer.handleSpuriousInterrupt();
}

fn interruptVector(regs: *const Registers) usize {
    const vector = std.math.cast(usize, regs.int_no) orelse unreachable;
    if (vector >= idt.IDT_ENTRIES) unreachable;
    return vector;
}

pub fn haltUnhandledException(regs: *const Registers) noreturn {
    const vector = interruptVector(regs);
    @call(.never_inline, console.print, .{"Received interrupt: "});
    if (vector < EXCEPTION_VECTOR_COUNT) {
        @call(.never_inline, console.print, .{exception_messages[vector]});
    } else {
        @call(.never_inline, console.print, .{"Unknown Interrupt"});
    }
    @call(.never_inline, console.print, .{"\nException context: vector=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, vector)});
    @call(.never_inline, console.print, .{" error=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.err_code)});
    @call(.never_inline, console.print, .{" rip=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eip)});
    @call(.never_inline, console.print, .{" cs=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.cs)});
    @call(.never_inline, console.print, .{" rflags=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eflags)});
    if (frameOriginatesFromUserspace(regs.cs)) {
        @call(.never_inline, console.print, .{" rsp=0x"});
        @call(.never_inline, numfmt.printHex, .{@as(u64, regs.useresp)});
        @call(.never_inline, console.print, .{" ss=0x"});
        @call(.never_inline, numfmt.printHex, .{@as(u64, regs.ss)});
    }
    @call(.never_inline, console.print, .{"\nSystem Halted!\n"});
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn reportInvalidInterruptReturn(regs: *const Registers) void {
    @call(.never_inline, console.print, .{"Rejected interrupt return: rip=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eip)});
    @call(.never_inline, console.print, .{" cs=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.cs)});
    @call(.never_inline, console.print, .{" rflags=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.eflags)});
    @call(.never_inline, console.print, .{" rsp=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.useresp)});
    @call(.never_inline, console.print, .{" ss=0x"});
    @call(.never_inline, numfmt.printHex, .{@as(u64, regs.ss)});
    @call(.never_inline, console.print, .{" user_data=0x"});
    @call(.never_inline, numfmt.printHex, .{gdt.userDataDescriptor()});
    @call(.never_inline, console.print, .{" user_code=0x"});
    @call(.never_inline, numfmt.printHex, .{gdt.userCodeDescriptor()});
    @call(.never_inline, console.print, .{"\n"});
}

fn frameOriginatesFromUserspace(code_selector: usize) bool {
    return code_selector & REQUESTED_PRIVILEGE_LEVEL_MASK == USER_PRIVILEGE_LEVEL;
}

fn setKernelGate(vector: u8, handler: GateHandler) void {
    idt.setGate(vector, handler, gdt.KERNEL_CODE_SEG, IDT_INTERRUPT_GATE);
}

fn disableLegacyPic() void {
    io.outb(PIC_MASTER_DATA_PORT, PIC_MASK_ALL);
    io.outb(PIC_SLAVE_DATA_PORT, PIC_MASK_ALL);
}

comptime {
    if (@offsetOf(Registers, "int_no") != 136) {
        @compileError("x86-64 interrupt frame layout diverged from interrupt64.S");
    }
    if (@sizeOf(Registers) != 192) {
        @compileError("x86-64 interrupt frame size diverged from interrupt64.S");
    }
    if (frameOriginatesFromUserspace(gdt.KERNEL_CODE_SEG) or
        !frameOriginatesFromUserspace(gdt.USER_CODE_SEG | USER_PRIVILEGE_LEVEL))
    {
        @compileError("x86-64 interrupt privilege-origin decoding diverged from the GDT selectors");
    }
}
