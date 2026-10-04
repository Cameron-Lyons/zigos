const std = @import("std");

pub const QEMU_TSC_FREQUENCY_HZ: u64 = 2_400_000_000;

// The fixed emulator clock belongs to the same explicit model request as its
// software CPU mode. Architectural frequency always takes precedence.
pub const ModelRequest = struct {
    model_inventory: bool = false,
    software_cpu_fallback: bool = false,
    tsc_frequency_hz: ?u64 = null,

    pub fn enabled(self: ModelRequest) bool {
        return self.model_inventory and self.software_cpu_fallback and
            self.tsc_frequency_hz == QEMU_TSC_FREQUENCY_HZ;
    }

    pub fn resolveTscFrequency(self: ModelRequest, architectural_frequency_hz: u64) u64 {
        if (architectural_frequency_hz != 0) return architectural_frequency_hz;
        if (self.enabled()) {
            return QEMU_TSC_FREQUENCY_HZ;
        }
        return 0;
    }
};

test "fixed model clock requires the complete explicit software CPU request" {
    for (0..8) |flags| {
        const request = ModelRequest{
            .model_inventory = flags & 1 != 0,
            .software_cpu_fallback = flags & 2 != 0,
            .tsc_frequency_hz = if (flags & 4 != 0) QEMU_TSC_FREQUENCY_HZ else null,
        };
        try std.testing.expectEqual(flags == 7, request.enabled());
        try std.testing.expectEqual(
            @as(u64, if (flags == 7) QEMU_TSC_FREQUENCY_HZ else 0),
            request.resolveTscFrequency(0),
        );
    }
}

test "normal boot frequency override cannot authorize the model clock" {
    const request = ModelRequest{
        .model_inventory = true,
        .tsc_frequency_hz = QEMU_TSC_FREQUENCY_HZ,
    };
    try std.testing.expect(!request.enabled());
    try std.testing.expectEqual(@as(u64, 0), request.resolveTscFrequency(0));
}

test "explicit model clock rejects missing and arbitrary frequencies" {
    for ([_]?u64{ null, 0, 1, QEMU_TSC_FREQUENCY_HZ - 1, QEMU_TSC_FREQUENCY_HZ + 1, std.math.maxInt(u64) }) |frequency| {
        const request = ModelRequest{
            .model_inventory = true,
            .software_cpu_fallback = true,
            .tsc_frequency_hz = frequency,
        };
        try std.testing.expect(!request.enabled());
        try std.testing.expectEqual(@as(u64, 0), request.resolveTscFrequency(0));
    }
}

test "architectural TSC frequency wins over every model clock request" {
    for (0..8) |flags| {
        const request = ModelRequest{
            .model_inventory = flags & 1 != 0,
            .software_cpu_fallback = flags & 2 != 0,
            .tsc_frequency_hz = if (flags & 4 != 0) QEMU_TSC_FREQUENCY_HZ else null,
        };
        try std.testing.expectEqual(@as(u64, 3_200_000_000), request.resolveTscFrequency(3_200_000_000));
    }
}
