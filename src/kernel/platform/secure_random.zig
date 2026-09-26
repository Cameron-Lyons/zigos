const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const random = @import("../../native/core/secure_random.zig");

var generator: random.Generator = .{};
var entropy: HardwareEntropy = .{};
var boot_instance: [16]u8 = @splat(0);

const HardwareEntropy = struct {
    supported: bool = false,
    collector: random.SeedCollector = .{},

    pub fn readWord(_: *HardwareEntropy) ?u64 {
        return x86.rdseed64();
    }
    pub fn pause(_: *HardwareEntropy) void {
        asm volatile ("pause");
    }
    pub fn readSeed(self: *HardwareEntropy, out: *random.Seed) random.Error!void {
        if (!self.supported) return error.Unsupported;
        try self.collector.collect(self, out);
    }
};

// Boot initializes this once, before interrupts or user services can consume it.
pub fn initialize(rdseed_supported: bool) random.Error!void {
    if (generator.initialized) return error.AlreadyInitialized;
    entropy.supported = rdseed_supported;
    try generator.initialize(&entropy);
    try fill(&boot_instance);
}

// The current kernel runs one CPU. Keep interrupt handlers from consuming or
// reseeding the same state while a request is in progress. Requests are <=4 KiB.
pub fn fill(out: []u8) random.Error!void {
    const interrupts_enabled = x86.interruptsEnabled();
    asm volatile ("cli" ::: .{ .memory = true });
    defer if (interrupts_enabled) asm volatile ("sti" ::: .{ .memory = true });
    try generator.fill(&entropy, out);
}

// Public correlation identifier; neither the seed nor secret generator state.
pub fn bootInstanceId() [16]u8 {
    std.debug.assert(generator.initialized);
    return boot_instance;
}
