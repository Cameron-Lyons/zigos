pub const IDT_ENTRIES = 256;
const OFFSET_LOW_MASK = 0xFFFF;
const OFFSET_HIGH_SHIFT = 16;

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

pub var idt: [IDT_ENTRIES]IdtEntry = [_]IdtEntry{IdtEntry{
    .offset_low = 0,
    .selector = 0,
    .type_attr = 0,
    .offset_high = 0,
}} ** IDT_ENTRIES;

pub fn setGate(n: u8, handler: *const fn () callconv(.c) void, selector: u16, type_attr: u8) void {
    const addr = @intFromPtr(handler);
    idt[n] = IdtEntry{
        .offset_low = @truncate(addr & OFFSET_LOW_MASK),
        .selector = selector,
        .type_attr = type_attr,
        .offset_high = @truncate((addr >> OFFSET_HIGH_SHIFT) & OFFSET_LOW_MASK),
    };
}

const TASK_GATE_PRESENT_32: u8 = 0x85;

/// Route a vector through a hardware task switch. The offset fields are
/// ignored for task gates; the target context comes from the TSS the
/// selector names.
pub fn setTaskGate(n: u8, tss_selector: u16) void {
    idt[n] = IdtEntry{
        .offset_low = 0,
        .selector = tss_selector,
        .type_attr = TASK_GATE_PRESENT_32,
        .offset_high = 0,
    };
}

pub fn init() void {
    const idtr = IdtPtr{
        .limit = @sizeOf(@TypeOf(idt)) - 1,
        .base = @intFromPtr(&idt),
    };

    asm volatile ("lidt (%[idtr])"
        :
        : [idtr] "r" (&idtr),
        : .{ .memory = true });
}
