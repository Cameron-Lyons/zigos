//! Exclusively own the physical queue, bounce buffers and PRP lists across
//! suspension. Acquisition never waits while holding a CPU spinlock.
const std = @import("std");

pub const Lease = struct {
    owner: std.atomic.Value(usize) = .init(0),

    pub fn acquire(self: *Lease, identity: usize) bool {
        if (identity == 0) return false;
        return self.owner.cmpxchgStrong(0, identity, .acquire, .monotonic) == null;
    }

    pub fn release(self: *Lease, identity: usize) void {
        if (identity == 0 or self.owner.cmpxchgStrong(identity, 0, .release, .monotonic) != null)
            @panic("NVMe operation released by a foreign owner");
    }

    pub fn busy(self: *const Lease) bool {
        return self.owner.load(.acquire) != 0;
    }

    pub fn execute(self: *Lease, identity: usize, io: anytype) bool {
        if (!self.acquire(identity)) return false;
        defer self.release(identity);
        io.perform() catch |err| {
            // The physical operation remains owned until terminal error
            // containment has disabled/revoked DMA, not merely until poll fails.
            io.contain(err);
            return false;
        };
        return true;
    }
};

comptime {
    if (@sizeOf(Lease) != @sizeOf(usize)) @compileError("NVMe operation lease must remain one atomic word");
}
