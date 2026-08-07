const std = @import("std");

const MILLISECONDS_PER_SECOND: u64 = 1000;
const MAX_INTERVAL_TICKS: u64 = std.math.maxInt(u63);

pub const Deadline = struct {
    start_ticks: u64,
    interval_ticks: u64,

    pub fn expiredAt(self: Deadline, current_ticks: u64) bool {
        return current_ticks -% self.start_ticks >= self.interval_ticks;
    }
};

pub fn intervalTicks(tsc_frequency_hz: u64, milliseconds: u64) ?u64 {
    if (tsc_frequency_hz == 0 or milliseconds == 0) return null;
    const product = std.math.mul(u64, tsc_frequency_hz, milliseconds) catch return null;
    const rounded = std.math.add(u64, product, MILLISECONDS_PER_SECOND - 1) catch return null;
    const interval = rounded / MILLISECONDS_PER_SECOND;
    if (interval == 0 or interval > MAX_INTERVAL_TICKS) return null;
    return interval;
}

test "invariant TSC deadlines use elapsed wrapping ticks" {
    const interval = intervalTicks(2_400_000_000, 500).?;
    try std.testing.expectEqual(@as(u64, 1_200_000_000), interval);
    const deadline = Deadline{
        .start_ticks = std.math.maxInt(u64) - 100,
        .interval_ticks = 200,
    };
    try std.testing.expect(!deadline.expiredAt(98));
    try std.testing.expect(deadline.expiredAt(99));
}

test "invariant TSC interval conversion rejects invalid spans" {
    try std.testing.expect(intervalTicks(0, 1) == null);
    try std.testing.expect(intervalTicks(1, 0) == null);
    try std.testing.expect(intervalTicks(std.math.maxInt(u64), 2) == null);
}
