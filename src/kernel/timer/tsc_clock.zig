const x86 = @import("../../arch/x86.zig");
const tsc_deadline = @import("tsc_deadline.zig");

var frequency_hz: u64 = 0;

pub const Deadline = struct {
    value: tsc_deadline.Deadline,

    pub fn expired(self: Deadline) bool {
        return self.value.expiredAt(x86.rdtsc());
    }
};

pub fn init(tsc_frequency_hz: u64) void {
    if (tsc_frequency_hz == 0) @panic("invariant TSC frequency is required");
    frequency_hz = tsc_frequency_hz;
}

pub fn initialized() bool {
    return frequency_hz != 0;
}

// Hardware-driver host fixtures must restore the prior clock, including its
// uninitialized state, after exercising the real deadline path.
pub fn swapTestFrequency(tsc_frequency_hz: u64) u64 {
    if (!@import("builtin").is_test) @compileError("test clock state is host-test-only");
    const previous = frequency_hz;
    frequency_hz = tsc_frequency_hz;
    return previous;
}

pub fn afterMilliseconds(milliseconds: u64) Deadline {
    const interval = tsc_deadline.intervalTicks(frequency_hz, milliseconds) orelse
        @panic("invalid invariant TSC deadline");
    return .{ .value = .{ .start_ticks = x86.rdtsc(), .interval_ticks = interval } };
}
