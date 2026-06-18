const builtin = @import("builtin");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn outb(_: u16, _: u8) void {}

        pub fn inb(_: u16) u8 {
            return 0;
        }

        pub fn outw(_: u16, _: u16) void {}

        pub fn inw(_: u16) u16 {
            return 0;
        }

        pub fn outl(_: u16, _: u32) void {}

        pub fn inl(_: u16) u32 {
            return 0;
        }
    };

pub const outb = x86.outb;
pub const inb = x86.inb;
pub const outw = x86.outw;
pub const inw = x86.inw;
pub const outl = x86.outl;
pub const inl = x86.inl;

pub inline fn io_wait() void {
    x86.outb(0x80, 0);
}
