const std = @import("std");
const config = @import("../config.zig");
const console = @import("console.zig");
const qemu_exit = @import("qemu_exit.zig");

var panic_occurred: bool = false;
const panic_message_buffer_size = 256;
const max_stack_frames = 24;
// Frame pointers must stay inside physical memory the boot identity map
// covers; a clobbered chain would otherwise fault inside the panic handler.
const stack_walk_lowest_frame = 0x1000;
const stack_walk_highest_frame = 0x0800_0000;

extern const __kernel_start: u8;
extern const __kernel_end: u8;

fn printPanic(text: []const u8) void {
    console.print(text);
}

fn printStackTrace() void {
    const text_start = @intFromPtr(&__kernel_start);
    const text_end = @intFromPtr(&__kernel_end);
    var frame_pointer = @frameAddress();
    var depth: usize = 0;

    printPanic("Return addresses (symbolize with llvm-addr2line -e <kernel.elf>):\n");
    while (depth < max_stack_frames) : (depth += 1) {
        if (frame_pointer < stack_walk_lowest_frame or frame_pointer >= stack_walk_highest_frame) break;
        if (frame_pointer % @alignOf(usize) != 0) break;

        const frame: *const [2]usize = @ptrFromInt(frame_pointer);
        const caller_frame_pointer = frame[0];
        const return_address = frame[1];
        if (return_address < text_start or return_address >= text_end) break;

        // SAFETY: filled by the subsequent std.fmt.bufPrint call
        var line_buffer: [48]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buffer, "  [{d}] 0x{x:0>8}\n", .{ depth, return_address }) catch break;
        printPanic(line);

        // The stack grows down, so each saved frame must be strictly higher.
        if (caller_frame_pointer <= frame_pointer) break;
        frame_pointer = caller_frame_pointer;
    }
    if (depth == 0) {
        printPanic("  (no frames captured; frame pointers may be omitted in this build)\n");
    }
}

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    asm volatile ("cli");

    if (panic_occurred) {
        while (true) {
            asm volatile ("hlt");
        }
    }
    panic_occurred = true;

    printPanic("\n");
    printPanic("============================ KERNEL PANIC ============================\n");
    printPanic("\n");

    // SAFETY: filled by the subsequent std.fmt.bufPrint call
    var buf: [panic_message_buffer_size]u8 = undefined;
    const message = std.fmt.bufPrint(&buf, format, args) catch "Failed to format panic message";
    printPanic(message);
    printPanic("\n\n");

    printStackTrace();
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
