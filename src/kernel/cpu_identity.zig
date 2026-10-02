const builtin = @import("builtin");
const std = @import("std");

pub const MAX_CPUS: usize = 8;
pub const USES_RDPID = true;
var test_cpu_index: u8 = 0;

pub fn indexFromSignature(signature: u32) ?u8 {
    return if (signature < MAX_CPUS) @intCast(signature) else null;
}

// Every CPU publishes its logical number before enabling native entry or
// entering the allocator. Only privileged code can replace IA32_TSC_AUX;
// changing a userspace GS selector or base cannot change this identity.
pub fn initialize(index: u8) void {
    if (indexFromSignature(index) == null) @panic("invalid logical CPU index");
    if (comptime builtin.target.os.tag == .freestanding) {
        const x86 = @import("../arch/x86.zig");
        x86.writeMsr(x86.IA32_TSC_AUX_MSR, index);
        if (x86.readMsr(x86.IA32_TSC_AUX_MSR) != index or x86.readProcessorId() != index) {
            @panic("logical CPU identity publication failed");
        }
    } else {
        @compileError("hardware CPU identity initialization is freestanding-only");
    }
}

pub inline fn currentIndex() u8 {
    const signature = if (comptime builtin.target.os.tag == .freestanding)
        @import("../arch/x86.zig").readProcessorId()
    else if (builtin.is_test)
        test_cpu_index
    else
        0;
    // Keep the hot read scalar: constructing ?u8 here spills its tag and
    // payload to the stack at every allocator and syscall identity lookup.
    if (signature >= MAX_CPUS) @panic("invalid logical CPU signature");
    return @intCast(signature);
}

pub fn setIndexForTest(index: u8) void {
    if (!builtin.is_test) @compileError("CPU identity override is test-only");
    test_cpu_index = indexFromSignature(index) orelse @panic("invalid test CPU index");
}

test "CPU identity accepts every logical CPU and rejects an unbounded signature" {
    for (0..MAX_CPUS) |index| {
        try std.testing.expectEqual(@as(?u8, @intCast(index)), indexFromSignature(@intCast(index)));
    }
    for ([_]u32{ MAX_CPUS, 256, 0x10000, std.math.maxInt(u32) }) |signature| {
        try std.testing.expect(indexFromSignature(signature) == null);
    }
}

test "modeled CPU identity follows a bounded logical processor override" {
    const previous = currentIndex();
    defer setIndexForTest(previous);
    for (0..MAX_CPUS) |index| {
        setIndexForTest(@intCast(index));
        try std.testing.expectEqual(@as(u8, @intCast(index)), currentIndex());
    }
}
