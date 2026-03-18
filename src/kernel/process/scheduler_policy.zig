const std = @import("std");

pub const SchedulerType = enum {
    RoundRobin,
    Priority,
    MultiLevelFeedback,
};

pub const Priority = enum(u8) {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    RealTime = 4,
};

pub const RUN_QUEUE_INDEX: i8 = 5;
pub const NO_QUEUE_INDEX: i8 = -1;
pub const MLFQ_BOOST_INTERVAL: u32 = 50;

pub fn getQuantumForPriority(priority: Priority) u32 {
    return switch (priority) {
        .Idle => 1,
        .Low => 5,
        .Normal => 10,
        .High => 15,
        .RealTime => 20,
    };
}

pub fn chooseCPUForNewProcess(next_cpu_rr: *u32, cpu_count: u32) u32 {
    const safe_cpu_count = @max(@as(u32, 1), cpu_count);
    const target = next_cpu_rr.* % safe_cpu_count;
    next_cpu_rr.* = (next_cpu_rr.* + 1) % safe_cpu_count;
    return target;
}

pub fn targetQueueIndex(scheduler_type: SchedulerType, priority: Priority) i8 {
    return switch (scheduler_type) {
        .RoundRobin => RUN_QUEUE_INDEX,
        .Priority, .MultiLevelFeedback => @as(i8, @intCast(@intFromEnum(priority))),
    };
}

test "priority quantums follow scheduler tiers" {
    try std.testing.expectEqual(@as(u32, 1), getQuantumForPriority(.Idle));
    try std.testing.expectEqual(@as(u32, 5), getQuantumForPriority(.Low));
    try std.testing.expectEqual(@as(u32, 10), getQuantumForPriority(.Normal));
    try std.testing.expectEqual(@as(u32, 15), getQuantumForPriority(.High));
    try std.testing.expectEqual(@as(u32, 20), getQuantumForPriority(.RealTime));
}

test "targetQueueIndex matches scheduler mode" {
    try std.testing.expectEqual(RUN_QUEUE_INDEX, targetQueueIndex(.RoundRobin, .Low));
    try std.testing.expectEqual(@as(i8, 1), targetQueueIndex(.Priority, .Low));
    try std.testing.expectEqual(@as(i8, 4), targetQueueIndex(.MultiLevelFeedback, .RealTime));
}

test "chooseCPUForNewProcess round-robins across active CPUs" {
    var next_cpu_rr: u32 = 0;
    try std.testing.expectEqual(@as(u32, 0), chooseCPUForNewProcess(&next_cpu_rr, 3));
    try std.testing.expectEqual(@as(u32, 1), chooseCPUForNewProcess(&next_cpu_rr, 3));
    try std.testing.expectEqual(@as(u32, 2), chooseCPUForNewProcess(&next_cpu_rr, 3));
    try std.testing.expectEqual(@as(u32, 0), chooseCPUForNewProcess(&next_cpu_rr, 3));
}

test "chooseCPUForNewProcess tolerates zero cpu count" {
    var next_cpu_rr: u32 = 9;
    try std.testing.expectEqual(@as(u32, 0), chooseCPUForNewProcess(&next_cpu_rr, 0));
    try std.testing.expectEqual(@as(u32, 0), next_cpu_rr);
}
