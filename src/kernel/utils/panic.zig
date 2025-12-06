const vga = @import("../drivers/vga.zig");
const builtin = @import("builtin");

var panic_message: [256]u8 = undefined;
var panic_occurred: bool = false;

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    asm volatile ("cli");

    if (panic_occurred) {
        while (true) {
            asm volatile ("hlt");
        }
    }
    panic_occurred = true;

    vga.clearWithColor(0x4F);

    vga.printWithColor("\n", 0x4F);
    vga.printWithColor("============================ KERNEL PANIC ============================\n", 0x4F);
    vga.printWithColor("\n", 0x4F);

    var buf: [256]u8 = undefined;
    const message = std.fmt.bufPrint(&buf, format, args) catch "Failed to format panic message";
    vga.printWithColor(message, 0x4F);
    vga.printWithColor("\n\n", 0x4F);

    vga.printWithColor("Stack trace:\n", 0x4F);
    var it = std.debug.StackIterator.init(@returnAddress(), @frameAddress());
    var i: usize = 0;
    while (it.next()) |addr| : (i += 1) {
        var addr_buf: [32]u8 = undefined;
        const addr_str = std.fmt.bufPrint(&addr_buf, "  [{d}] 0x{x}\n", .{ i, addr }) catch break;
        vga.printWithColor(addr_str, 0x4F);
        if (i >= 10) break;
    }

    vga.printWithColor("\n", 0x4F);
    vga.printWithColor("System halted. Please restart your computer.\n", 0x4F);
    vga.printWithColor("======================================================================\n", 0x4F);

    while (true) {
        asm volatile ("hlt");
    }
}

pub fn assert(condition: bool, comptime message: []const u8) void {
    if (!condition) {
        panic("Assertion failed: {s}", .{message});
    }
}

pub fn todo(comptime message: []const u8) noreturn {
    panic("TODO: {s}", .{message});
}

pub fn unreachable_panic(comptime message: []const u8) noreturn {
    panic("Unreachable code reached: {s}", .{message});
}

const std = @import("std");

