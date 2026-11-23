const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const console = @import("console.zig");
const qemu_exit = @import("qemu_exit.zig");

var panic_occurred: bool = false;
const panic_message_buffer_size = 256;
const max_stack_frames = 24;

// Every kernel stack lives in the upper half and is far smaller than this
// window above the panicking frame.
const stack_walk_window_bytes = 64 * 1024;
const upper_half_base: usize = 0xffff_8000_0000_0000;

extern const __kernel_text_start: u8;
extern const __kernel_text_end: u8;

fn printPanic(text: []const u8) void {
    console.print(text);
}

/// An NMI that arrives after the first panic parks its CPU.
pub fn panicking() bool {
    return @atomicLoad(bool, &panic_occurred, .acquire);
}

fn printStackTrace() void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    const text_start = @intFromPtr(&__kernel_text_start);
    const text_end = @intFromPtr(&__kernel_text_end);
    const lowest = @frameAddress();
    const highest = lowest +| stack_walk_window_bytes;
    var frame_pointer = lowest;
    var depth: usize = 0;

    printPanic("Return addresses (symbolize with llvm-addr2line -e <full-debug-kernel.elf>):\n");
    while (depth < max_stack_frames) : (depth += 1) {
        if (frame_pointer < upper_half_base or frame_pointer < lowest or frame_pointer >= highest) break;
        if (frame_pointer % @alignOf(usize) != 0) break;

        const frame: *const [2]usize = @ptrFromInt(frame_pointer);
        const caller_frame_pointer = frame[0];
        const return_address = frame[1];
        if (return_address < text_start or return_address >= text_end) break;

        var line_buffer: [48]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buffer, "  [{d}] 0x{x:0>16}\n", .{ depth, return_address }) catch break;
        printPanic(line);

        if (caller_frame_pointer <= frame_pointer) break;
        frame_pointer = caller_frame_pointer;
    }
    if (depth == 0) {
        printPanic("  (no frames captured; frame pointers may be omitted in this build)\n");
    }
}

fn stopOtherCpus() void {
    if (comptime builtin.target.os.tag != .freestanding) return;
    @import("../smp.zig").stopOtherCpus();
}

pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    asm volatile ("cli");

    if (@atomicRmw(bool, &panic_occurred, .Xchg, true, .acq_rel)) {
        while (true) {
            asm volatile ("hlt");
        }
    }

    printPanic("\n");
    printPanic("============================ KERNEL PANIC ============================\n");
    printPanic("\n");

    var buf: [panic_message_buffer_size]u8 = undefined;
    const message = std.fmt.bufPrint(&buf, format, args) catch "Failed to format panic message";
    printPanic(message);
    printPanic("\n\n");

    // The message is out before any remote CPU is disturbed.
    stopOtherCpus();
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
