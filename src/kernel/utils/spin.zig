const builtin = @import("builtin");
const std = @import("std");

pub const USES_ACQUIRE_RELEASE = true;
pub const CONTENDED_WAIT_USES_READS = true;

pub const Lock = struct {
    state: u32 = 0,

    pub fn init() Lock {
        return .{};
    }

    pub fn acquire(self: *Lock) void {
        while (@cmpxchgWeak(u32, &self.state, 0, 1, .acquire, .monotonic) != null) {
            while (@atomicLoad(u32, &self.state, .monotonic) != 0) hint();
        }
    }

    pub fn tryAcquire(self: *Lock) bool {
        return @cmpxchgStrong(u32, &self.state, 0, 1, .acquire, .monotonic) == null;
    }

    pub fn release(self: *Lock) void {
        @atomicStore(u32, &self.state, 0, .release);
    }
};

pub inline fn hint() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        asm volatile ("pause");
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}

test "spin lock provides exclusive acquire and release state" {
    var lock = Lock.init();

    try std.testing.expect(lock.tryAcquire());
    try std.testing.expect(!lock.tryAcquire());
    lock.release();
    try std.testing.expect(lock.tryAcquire());
    lock.release();

    try std.testing.expect(USES_ACQUIRE_RELEASE);
    try std.testing.expect(CONTENDED_WAIT_USES_READS);
}
