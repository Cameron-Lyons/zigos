const builtin = @import("builtin");

const RuntimeClock = struct {
    fn synchronize(_: @This()) void {
        @import("../../kernel/timer/timer.zig").synchronize();
    }

    fn getTicks(_: @This()) u64 {
        return @import("../../kernel/timer/timer.zig").getTicks();
    }
};

// Boot/proof ordinals describe event order. They are not the runtime clock that
// authorizes a driver submission or establishes a capability lease.
pub inline fn at(hosted_ticks: u64) u64 {
    return select(builtin.target.os.tag == .freestanding, RuntimeClock{}, hosted_ticks);
}

inline fn select(comptime use_runtime_clock: bool, clock: anytype, hosted_ticks: u64) u64 {
    if (use_runtime_clock) {
        clock.synchronize();
        return clock.getTicks();
    }
    return hosted_ticks;
}

test "driver authorization clock uses synchronized time without weakening leases" {
    const std = @import("std");
    const capability = @import("../kernel_api/capability.zig");
    const driver_service = @import("../drivers/driver_service.zig");
    const Clock = struct {
        ticks: u64,
        synchronizations: usize = 0,

        fn synchronize(self: *@This()) void {
            self.synchronizations += 1;
        }

        fn getTicks(self: *const @This()) u64 {
            return self.ticks;
        }
    };
    var clock = Clock{ .ticks = 3 };
    var table = capability.CapabilityTable.init();
    const ordinal_grant = try driver_service.mintDriverAuthority(&table, .{
        .holder = .{ .kind = .service, .serial = 3 },
        .task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .issued_at_ticks = 800,
    });
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(ordinal_grant.id, clock.ticks));

    const current_ticks = select(true, &clock, 800);
    try std.testing.expectEqual(@as(u64, 3), current_ticks);
    try std.testing.expectEqual(@as(usize, 1), clock.synchronizations);
    const current_grant = try driver_service.mintDriverAuthority(&table, .{
        .holder = ordinal_grant.holder,
        .task_id = 9,
        .device_id = 200,
        .device_class = .storage_controller,
        .issued_at_ticks = current_ticks,
        .expires_at_ticks = 4,
        .renewable = false,
    });
    _ = try table.requireUsable(current_grant.id, current_ticks);
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(current_grant.id, 2));
    _ = try table.requireUsable(current_grant.id, 4);
    clock.ticks = 5;
    const later_ticks = select(true, &clock, 802);
    try std.testing.expectEqual(@as(u64, 5), later_ticks);
    try std.testing.expectEqual(@as(usize, 2), clock.synchronizations);
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(current_grant.id, later_ticks));
}

test "driver authorization clock preserves hosted ordinal time without reading runtime" {
    const std = @import("std");
    const UnavailableRuntime = struct {};
    for ([_]u64{ 0, 56, 800, 820, std.math.maxInt(u64) }) |ticks| {
        try std.testing.expectEqual(ticks, select(false, UnavailableRuntime{}, ticks));
        if (builtin.target.os.tag != .freestanding) try std.testing.expectEqual(ticks, at(ticks));
    }
}
