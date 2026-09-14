const builtin = @import("builtin");
const std = @import("std");

pub const INTERRUPT_DRIVEN_IDLE = true;
pub const WAKES_PER_CPU = true;
pub const MAX_CPUS: usize = 8;

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

var pending_bits: [MAX_CPUS]u8 = [_]u8{0} ** MAX_CPUS;
var current_cpu: u8 = 0;

pub fn bindCpu(cpu: u8) void {
    current_cpu = if (cpu < MAX_CPUS) cpu else 0;
}

fn currentCpu() u8 {
    if (comptime builtin.target.os.tag != .freestanding) return current_cpu;
    const x86 = @import("../arch/x86.zig");
    const gs_base = x86.readMsr(x86.IA32_GS_BASE_MSR);
    if (gs_base < 4096) {
        return if (gs_base < MAX_CPUS) @truncate(gs_base) else current_cpu;
    }
    const cpu_index: *const usize = @ptrFromInt(gs_base + 16);
    const index: u8 = @truncate(cpu_index.*);
    return if (index < MAX_CPUS) index else current_cpu;
}

pub fn raise(kind: Kind) void {
    raiseOn(currentCpu(), kind);
}

pub fn raiseOn(cpu: u8, kind: Kind) void {
    const index: usize = if (cpu < MAX_CPUS) cpu else 0;
    const bit = @as(u8, 1) << @intFromEnum(kind);
    _ = @atomicRmw(u8, &pending_bits[index], .Or, bit, .release);
}

pub fn peek() Pending {
    return peekOn(currentCpu());
}

pub fn peekOn(cpu: u8) Pending {
    const index: usize = if (cpu < MAX_CPUS) cpu else 0;
    return @bitCast(@atomicLoad(u8, &pending_bits[index], .acquire));
}

pub fn any() bool {
    for (&pending_bits) |*slot| {
        if (@atomicLoad(u8, slot, .acquire) != 0) return true;
    }
    return false;
}

pub fn take() Pending {
    return takeOn(currentCpu());
}

pub fn takeOn(cpu: u8) Pending {
    const index: usize = if (cpu < MAX_CPUS) cpu else 0;
    return @bitCast(@atomicRmw(u8, &pending_bits[index], .Xchg, 0, .acq_rel));
}

pub fn takeAll() Pending {
    var combined: u8 = 0;
    for (&pending_bits) |*slot| {
        combined |= @atomicRmw(u8, slot, .Xchg, 0, .acq_rel);
    }
    return @bitCast(combined);
}

test "event wake latches and drains pending work bits" {
    bindCpu(0);
    _ = takeAll();
    try std.testing.expect(!any());
    raise(.xhci);
    raiseOn(1, .network);
    const pending = takeAll();
    try std.testing.expect(pending.xhci);
    try std.testing.expect(pending.network);
    try std.testing.expect(!pending.nvme);
    try std.testing.expect(!any());
}

test "event wake keeps per-cpu pending bits" {
    bindCpu(0);
    _ = takeAll();
    raiseOn(0, .timer);
    raiseOn(2, .nvme);
    try std.testing.expect(peekOn(0).timer);
    try std.testing.expect(!peekOn(0).nvme);
    try std.testing.expect(peekOn(2).nvme);
    try std.testing.expect(takeOn(0).timer);
    try std.testing.expect(takeOn(2).nvme);
    try std.testing.expect(!any());
}
