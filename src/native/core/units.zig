const std = @import("std");

// One clock domain for native service deadlines and the hardware timer.
pub const TIMER_FREQUENCY_HZ: u64 = 100;

pub fn millisecondsToTimerTicksCeil(milliseconds: u64) u64 {
    const scaled = @as(u128, milliseconds) * TIMER_FREQUENCY_HZ;
    const ticks = (scaled + 999) / 1000;
    return @intCast(@min(ticks, std.math.maxInt(u64)));
}

pub const bytes_per_kib = 1024;
pub const bytes_per_mib = bytes_per_kib * bytes_per_kib;
pub const bytes_per_gib = bytes_per_kib * bytes_per_mib;

pub fn kibibytes(comptime amount: comptime_int) comptime_int {
    return amount * bytes_per_kib;
}

pub fn mebibytes(comptime amount: comptime_int) comptime_int {
    return amount * bytes_per_mib;
}

pub fn gibibytes(comptime amount: comptime_int) comptime_int {
    return amount * bytes_per_gib;
}

test "native timer units round deadlines up without overflow" {
    try std.testing.expectEqual(@as(u64, 100), TIMER_FREQUENCY_HZ);
    try std.testing.expectEqual(@as(u64, 0), millisecondsToTimerTicksCeil(0));
    try std.testing.expectEqual(@as(u64, 1), millisecondsToTimerTicksCeil(1));
    try std.testing.expectEqual(@as(u64, 1), millisecondsToTimerTicksCeil(10));
    try std.testing.expectEqual(@as(u64, 2), millisecondsToTimerTicksCeil(11));
    try std.testing.expectEqual(@as(u64, 50), millisecondsToTimerTicksCeil(500));
    try std.testing.expectEqual(@as(u64, 100), millisecondsToTimerTicksCeil(1000));
    try std.testing.expectEqual(@as(u64, 1_844_674_407_370_955_162), millisecondsToTimerTicksCeil(std.math.maxInt(u64)));
}
