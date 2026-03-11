const std = @import("std");
const vga = @import("../drivers/vga.zig");
const config = @import("../config.zig");
const console = @import("console.zig");
const qemu_exit = @import("qemu_exit.zig");

var panic_occurred: bool = false;
const panic_color: u8 = 0x4F;
const panic_message_buffer_size = 256;

fn printPanic(text: []const u8) void {
    console.printWithColor(text, panic_color);
}

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    asm volatile ("cli");

    if (panic_occurred) {
        while (true) {
            asm volatile ("hlt");
        }
    }
    panic_occurred = true;

    vga.clearWithColor(panic_color);

    printPanic("\n");
    printPanic("============================ KERNEL PANIC ============================\n");
    printPanic("\n");

    // SAFETY: filled by the subsequent std.fmt.bufPrint call
    var buf: [panic_message_buffer_size]u8 = undefined;
    const message = std.fmt.bufPrint(&buf, format, args) catch "Failed to format panic message";
    printPanic(message);
    printPanic("\n\n");

    // Stack trace not available in freestanding environment
    printPanic("Stack trace: Not available in freestanding mode\n");
    printPanic("\n");
    printPanic("System halted. Please restart your computer.\n");
    printPanic("======================================================================\n");

    if (config.shouldExitOnPanic()) {
        qemu_exit.failure();
    }

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
