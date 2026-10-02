//! Serialize complete cooperative TPM jobs, including cleanup, without keeping
//! a spinlock across a yield. A queued job can cancel without touching hardware.
const std = @import("std");
const cooperative = @import("cooperative_worker.zig");
var owner = std.atomic.Value(usize).init(0);

pub fn tryAcquire() !bool {
    const worker = cooperative.current() orelse return error.WorkerRequired;
    if (worker.cancel_requested) return error.Cancelled;
    const identity = @intFromPtr(worker);
    const existing = owner.cmpxchgStrong(0, identity, .acquire, .monotonic) orelse return true;
    if (existing == identity) return error.NestedTpmOperation;
    return false;
}

pub fn release() void {
    const worker = cooperative.current() orelse @panic("TPM lease released outside a worker");
    if (owner.cmpxchgStrong(@intFromPtr(worker), 0, .release, .monotonic) != null) @panic("TPM lease released by another worker");
}

pub fn allowsCurrent() bool {
    const holder = owner.load(.acquire);
    return holder == 0 or holder == (if (cooperative.current()) |worker| @intFromPtr(worker) else @as(usize, 0));
}
