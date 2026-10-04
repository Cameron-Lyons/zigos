const std = @import("std");
const cpu_identity = @import("../cpu_identity.zig");

const CpuDepth = extern struct {
    depth: u32 = 0,
    padding: [60]u8 = @splat(0),
};

// Interrupts on application processors must not change the runtime owner's
// context. Separate cache lines also keep remote TLB IPIs off its hot counter.
var local_depths: [cpu_identity.MAX_CPUS]CpuDepth align(64) = @splat(.{});

fn depthSlot() *volatile u32 {
    // IA32_TSC_AUX is published before native interrupt entry is enabled.
    // Each CPU alone updates its slot; volatile preserves asynchronous nesting.
    return &local_depths[cpu_identity.currentIndex()].depth;
}

pub fn enter() void {
    const depth = depthSlot();
    const previous = depth.*;
    if (previous == std.math.maxInt(u32)) @panic("interrupt nesting exhausted");
    depth.* = previous + 1;
}

pub fn leave() void {
    const depth = depthSlot();
    const previous = depth.*;
    if (previous == 0) unreachable;
    depth.* = previous - 1;
}

pub fn active() bool {
    return depthSlot().* != 0;
}

test "interrupt nesting stays local during interleaved CPU entries and exits" {
    const previous_cpu = cpu_identity.currentIndex();
    const previous_depths = local_depths;
    defer cpu_identity.setIndexForTest(previous_cpu);
    defer local_depths = previous_depths;
    local_depths = @splat(.{});

    // Keep each CPU nested while visiting every other CPU. With one shared
    // counter, the second CPU would already appear to be in an interrupt.
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        try std.testing.expect(!active());
        for (0..index + 1) |_| enter();
    }
    for (0..cpu_identity.MAX_CPUS) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        for (0..index + 1) |_| {
            try std.testing.expect(active());
            leave();
        }
        try std.testing.expect(!active());
    }
}
