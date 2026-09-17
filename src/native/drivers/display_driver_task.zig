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
    if (scanout.object_id == 0 or scanout.bytes == 0 or scanout.revision == 0) return false;
    if (scanout.revision < active.revision) return false;
    active = scanout;
    _ = display_hw.programScanoutRevision(
        scanout.object_id,
        scanout.offset,
        scanout.bytes,
        scanout.revision,
    );
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
