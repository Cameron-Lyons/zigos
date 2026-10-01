const builtin = @import("builtin");
const std = @import("std");

pub const PRESENTS_BY_HANDLE = true;
pub const ARC_SCANOUT_PREFERRED = true;
pub const USERSPACE_GOP_DATAPLANE = true;
pub const KERNEL_LATCHES_ONLY = true;

const display_hw = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/drivers/display_hw.zig")
else
    struct {
        pub fn programScanoutRevision(_: u64, _: u32, _: u32, _: u64) bool {
            return true;
        }
    };

pub const Scanout = struct {
    object_id: u64 = 0,
    offset: u32 = 0,
    bytes: u32 = 0,
    revision: u64 = 0,
};

var active: Scanout = .{};

pub fn reset() void {
    active = .{};
}

pub fn presentHandle(scanout: Scanout) bool {
    return submitHandle(scanout, display_hw.programScanoutRevision);
}

// The compositor orders revisions per surface before submitting. Revisions
// from different surfaces are independent; only successful submissions latch.
fn submitHandle(scanout: Scanout, comptime program: fn (u64, u32, u32, u64) bool) bool {
    if (scanout.object_id == 0 or scanout.bytes == 0 or scanout.revision == 0) return false;
    if (!program(
        scanout.object_id,
        scanout.offset,
        scanout.bytes,
        scanout.revision,
    )) return false;
    active = scanout;
    return true;
}

pub fn activeScanout() Scanout {
    return active;
}

test "display driver presents by shared-memory handle" {
    reset();
    try std.testing.expect(presentHandle(.{
        .object_id = 42,
        .offset = 0,
        .bytes = 4096,
        .revision = 1,
    }));
    try std.testing.expectEqual(@as(u64, 42), activeScanout().object_id);
    try std.testing.expect(!presentHandle(.{
        .object_id = 42,
        .offset = 0,
        .bytes = 4096,
        .revision = 0,
    }));
    reset();
}

test "display driver accepts independent surface revisions in submission order" {
    reset();
    defer reset();
    try std.testing.expect(presentHandle(.{ .object_id = 41, .bytes = 4096, .revision = 100 }));
    const next = Scanout{ .object_id = 42, .offset = 64, .bytes = 8192, .revision = 1 };
    try std.testing.expect(presentHandle(next));
    try std.testing.expectEqual(next, activeScanout());
}

test "display driver preserves its active scanout after failed hardware submission" {
    const FailedHardware = struct {
        fn program(_: u64, _: u32, _: u32, _: u64) bool {
            return false;
        }
    };
    reset();
    defer reset();
    const previous = Scanout{ .object_id = 41, .bytes = 4096, .revision = 100 };
    try std.testing.expect(presentHandle(previous));
    try std.testing.expect(!submitHandle(.{ .object_id = 42, .offset = 64, .bytes = 8192, .revision = 1 }, FailedHardware.program));
    try std.testing.expectEqual(previous, activeScanout());
    try std.testing.expect(!presentHandle(.{ .object_id = 42, .bytes = 8192 }));
    try std.testing.expectEqual(previous, activeScanout());
}
