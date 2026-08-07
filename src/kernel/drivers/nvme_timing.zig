const std = @import("std");

const CAP_TIMEOUT_SHIFT: u6 = 24;
const CAP_TIMEOUT_MASK: u64 = 0xFF;
const CAP_READY_WITH_MEDIA_SUPPORTED: u64 = 1 << 59;
const CRTO_READY_WITH_MEDIA_MASK: u32 = 0xFFFF;
const TIMEOUT_UNIT_MILLISECONDS: u64 = 500;

pub const COMMAND_TIMEOUT_MILLISECONDS: u64 = 5000;

pub fn readyTimeoutMilliseconds(capabilities: u64, controller_ready_timeouts: u32) u64 {
    const modern_units = controller_ready_timeouts & CRTO_READY_WITH_MEDIA_MASK;
    const legacy_units = (capabilities >> CAP_TIMEOUT_SHIFT) & CAP_TIMEOUT_MASK;
    const units = if ((capabilities & CAP_READY_WITH_MEDIA_SUPPORTED) != 0 and modern_units != 0)
        modern_units
    else
        @max(@as(u64, 1), legacy_units);
    return @as(u64, units) * TIMEOUT_UNIT_MILLISECONDS;
}

test "NVMe timing uses ready-with-media timeout on modern controllers" {
    try std.testing.expectEqual(
        @as(u64, 2500),
        readyTimeoutMilliseconds(CAP_READY_WITH_MEDIA_SUPPORTED | (@as(u64, 2) << 24), 5),
    );
}

test "NVMe timing falls back to bounded CAP timeout units" {
    try std.testing.expectEqual(
        @as(u64, 1500),
        readyTimeoutMilliseconds(@as(u64, 3) << 24, 100),
    );
    try std.testing.expectEqual(@as(u64, 500), readyTimeoutMilliseconds(0, 0));
    try std.testing.expectEqual(@as(u64, 5000), COMMAND_TIMEOUT_MILLISECONDS);
}
