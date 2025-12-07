const std = @import("std");
const vga = @import("../drivers/vga.zig");
const console = @import("console.zig");
const builtin = @import("builtin");

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

    console.printWithColor("\n", 0x4F);
    console.printWithColor("============================ KERNEL PANIC ============================\n", 0x4F);
    console.printWithColor("\n", 0x4F);

    var buf: [256]u8 = undefined;
    const message = std.fmt.bufPrint(&buf, format, args) catch "Failed to format panic message";
    console.printWithColor(message, 0x4F);
    console.printWithColor("\n\n", 0x4F);

    // Stack trace not available in freestanding environment
    console.printWithColor("Stack trace: Not available in freestanding mode\n", 0x4F);
    console.printWithColor("\n", 0x4F);
    console.printWithColor("System halted. Please restart your computer.\n", 0x4F);
    console.printWithColor("======================================================================\n", 0x4F);

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

