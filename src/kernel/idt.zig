const std = @import("std");

pub const IDT_ENTRIES = 256;

pub const IdtEntry = packed struct {
    offset_low: u16,
    selector: u16,
    zero: u8 = 0,
    type_attr: u8,
    offset_high: u16,
};

pub const IdtPtr = packed struct {
    limit: u16,
    base: u32,
};

pub const InterruptFrame = struct {
    instruction_pointer: u64,
    code_segment: u64,
    cpu_flags: u64,
    stack_pointer: u64,
    stack_segment: u64,
};

pub const InterruptRegisters = packed struct {
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

const IDT_TYPE_INTERRUPT = 0x8E;
const IDT_TYPE_TRAP = 0x8F;

pub var idt: [IDT_ENTRIES]IdtEntry = [_]IdtEntry{IdtEntry{
    .offset_low = 0,
    .selector = 0,
    .type_attr = 0,
    .offset_high = 0,
}} ** IDT_ENTRIES;

pub fn setGate(n: u8, handler: *const fn () callconv(.Naked) void, selector: u16, type_attr: u8) void {
    const addr = @intFromPtr(handler);
    idt[n] = IdtEntry{
        .offset_low = @truncate(addr & 0xFFFF),
        .selector = selector,
        .type_attr = type_attr,
        .offset_high = @truncate((addr >> 16) & 0xFFFF),
    };
}

pub var interrupt_handlers: [IDT_ENTRIES]?*const fn (*InterruptRegisters) callconv(.C) void = [_]?*const fn (*InterruptRegisters) callconv(.C) void{null} ** IDT_ENTRIES;

pub fn register_interrupt_handler(n: u8, handler: *const fn (*InterruptRegisters) callconv(.C) void) void {
    interrupt_handlers[n] = handler;
}

pub fn set_gate_flags(n: u8, flags: u8) void {
    idt[n].type_attr = flags;
}

pub fn init() void {
    const idtr = IdtPtr{
        .limit = @sizeOf(@TypeOf(idt)) - 1,
        .base = @intFromPtr(&idt),
    };

    asm volatile ("lidt %[idtr]"
        :
        : [idtr] "*m" (&idtr),
    );
}

