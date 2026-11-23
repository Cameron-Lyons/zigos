const builtin = @import("builtin");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn outb(_: u16, _: u8) void {}

        pub fn inb(_: u16) u8 {
            return 0;
        }
    };

pub const outb = x86.outb;
pub const inb = x86.inb;
