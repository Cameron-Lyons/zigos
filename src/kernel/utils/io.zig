const x86 = @import("../../arch/x86.zig");

pub const outb = x86.outb;
pub const inb = x86.inb;
pub const outw = x86.outw;
pub const inw = x86.inw;
pub const outl = x86.outl;
pub const inl = x86.inl;

pub inline fn io_wait() void {
    x86.outb(0x80, 0);
}
