const x86 = @import("../../arch/x86.zig");

pub const IDT_ENTRIES = 256;

pub const IdtEntry = packed struct {
    offset_low: u16 = 0,
    selector: u16 = 0,
    ist: u8 = 0,
    type_attr: u8 = 0,
    offset_middle: u16 = 0,
    offset_high: u32 = 0,
    reserved: u32 = 0,
};

pub const IdtPtr = extern struct {
    limit: u16,
    base: usize align(1),
};

pub var idt: [IDT_ENTRIES]IdtEntry align(16) = [_]IdtEntry{.{}} ** IDT_ENTRIES;

pub fn setGate(n: u8, handler: *const fn () callconv(.c) void, selector: u16, type_attr: u8) void {
    setIstGate(n, handler, selector, type_attr, 0);
}

pub fn setIstGate(
    n: u8,
    handler: *const fn () callconv(.c) void,
    selector: u16,
    type_attr: u8,
    ist: u3,
) void {
    const address = @intFromPtr(handler);
    idt[n] = .{
        .offset_low = @truncate(address),
        .selector = selector,
        .ist = ist,
        .type_attr = type_attr,
        .offset_middle = @truncate(address >> 16),
        .offset_high = @truncate(address >> 32),
    };
}

pub fn init() void {
    const idtr = IdtPtr{
        .limit = @sizeOf(@TypeOf(idt)) - 1,
        .base = @intFromPtr(&idt),
    };
    x86.loadIdt(&idtr);
}

comptime {
    if (@sizeOf(IdtEntry) != 16) @compileError("x86-64 IDT entries must be 16 bytes");
    if (@sizeOf(IdtPtr) != 10) @compileError("x86-64 IDTR operand must be 10 bytes");
}
