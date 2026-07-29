const builtin = @import("builtin");

pub inline fn hint() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        asm volatile ("pause");
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}
