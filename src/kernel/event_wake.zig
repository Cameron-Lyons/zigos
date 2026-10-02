const std = @import("std");

pub const INTERRUPT_DRIVEN_IDLE = true;
pub const WAKES_RUNTIME_OWNER = true;

pub const Kind = enum(u3) {
    timer = 0,
    xhci = 1,
    network = 2,
    nvme = 3,
    scheduler = 4,
};

pub const Pending = packed struct(u8) {
    timer: bool = false,
    xhci: bool = false,
    network: bool = false,
    nvme: bool = false,
    scheduler: bool = false,
    _reserved: u3 = 0,

    pub fn any(self: Pending) bool {
        return @as(u8, @bitCast(self)) != 0;
    }
};

// Device IRQs and the scheduler timer target the runtime owner. A single
// atomic latch mirrors the one service loop that consumes these notifications;
// application processors handle their own TLB IPIs without entering that loop.
var pending_bits: u8 = 0;

pub fn raise(kind: Kind) void {
    const bit = @as(u8, 1) << @intFromEnum(kind);
    _ = @atomicRmw(u8, &pending_bits, .Or, bit, .release);
}

pub fn peek() Pending {
    return @bitCast(@atomicLoad(u8, &pending_bits, .acquire));
}

pub fn any() bool {
    return peek().any();
}

pub fn take() Pending {
    return @bitCast(@atomicRmw(u8, &pending_bits, .Xchg, 0, .acq_rel));
}

test "event wake coalesces every work kind and drains the runtime latch" {
    _ = take();
    try std.testing.expect(!any());
    inline for (std.meta.tags(Kind)) |kind| {
        raise(kind);
        raise(kind);
    }
    const pending = peek();
    try std.testing.expect(pending.timer and pending.xhci and pending.network and
        pending.nvme and pending.scheduler);
    try std.testing.expectEqual(@as(u3, 0), pending._reserved);
    try std.testing.expectEqual(pending, take());
    try std.testing.expect(!any());
}

test "event wake preserves notifications published after a drain" {
    _ = take();
    raise(.network);
    const first = take();
    raise(.nvme);
    try std.testing.expect(first.network);
    try std.testing.expect(!first.nvme);
    const second = take();
    try std.testing.expect(second.nvme);
    try std.testing.expect(!second.network);
    try std.testing.expect(!any());
}
