const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const console = @import("console.zig");

extern var stack_bottom: u8;
extern var stack_top: u8;

const GUARD_PAGE_BYTES: usize = 4096;

const PAINT_PATTERN: u32 = 0x57ACC0DE;

const PAINT_MARGIN_BYTES: usize = 512;

fn paintableBase() usize {
    return @intFromPtr(&stack_bottom) + GUARD_PAGE_BYTES;
}

pub fn paint() void {
    const base = paintableBase();
    const stack_pointer = x86.stackPointer();
    if (stack_pointer <= base + PAINT_MARGIN_BYTES) return;

    const words: [*]u32 = @ptrFromInt(base);
    const count = (stack_pointer - PAINT_MARGIN_BYTES - base) / @sizeOf(u32);
    var index: usize = 0;
    while (index < count) : (index += 1) {
        words[index] = PAINT_PATTERN;
    }
}

pub fn peakBytes() usize {
    const base = paintableBase();
    const top = @intFromPtr(&stack_top);
    var addr = base;
    var untouched: usize = 0;
    while (addr < top) : (addr += @sizeOf(u32)) {
        const word: *const u32 = @ptrFromInt(addr);
        if (word.* != PAINT_PATTERN) break;
        untouched += @sizeOf(u32);
    }
    if (untouched == 0) return 0;
    return (top - base) - untouched;
}

pub fn capacityBytes() usize {
    return @intFromPtr(&stack_top) - paintableBase();
}

pub fn reportPeak() void {
    var line_buffer: [96]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "ZIGOS:PLATFORM:BOOT_STACK:PEAK used_bytes={d} capacity_bytes={d}\n",
        .{ peakBytes(), capacityBytes() },
    ) catch return;
    console.print(line);
}
