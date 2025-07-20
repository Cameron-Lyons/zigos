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

pub fn init() void {
    const idtr = IdtPtr{
        .limit = @sizeOf(@TypeOf(idt)) - 1,
        .base = @intFromPtr(&idt),
    };

    asm volatile ("lidt %[idtr]"
        :
        : [idtr] "*m" (&idtr)
    );
}