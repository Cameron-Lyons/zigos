const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const console = @import("console.zig");

// Symbols from the architecture entry assembly bounding the BSP boot stack.
// The page at stack_bottom is the unmapped overflow guard, so painting and
// scanning both start one page above it.
extern var stack_bottom: u8;
extern var stack_top: u8;

const GUARD_PAGE_BYTES: usize = 4096;
// Distinctive word unlikely to appear as live stack data.
const PAINT_PATTERN: u32 = 0x57ACC0DE;
// Keep well clear of the frames live while paint() itself runs.
const PAINT_MARGIN_BYTES: usize = 512;

fn paintableBase() usize {
    return @intFromPtr(&stack_bottom) + GUARD_PAGE_BYTES;
}

/// Fill the unused portion of the boot stack with a recognizable pattern.
/// Call once, early in boot, while the call chain is still shallow.
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

/// Deepest stack use since paint(), measured from stack_top down to the
/// lowest overwritten paint word. Returns 0 if the stack was never painted.
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

/// Emit the boot-stack high-water mark so QEMU logs track headroom over
/// time; creep toward capacity is visible long before the guard page trips.
pub fn reportPeak() void {
    // SAFETY: filled by the subsequent std.fmt.bufPrint call
    var line_buffer: [96]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "ZIGOS:PLATFORM:BOOT_STACK:PEAK used_bytes={d} capacity_bytes={d}\n",
        .{ peakBytes(), capacityBytes() },
    ) catch return;
    console.print(line);
}
