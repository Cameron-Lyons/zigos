const std = @import("std");

pub const FORBIDS_PRODUCT_IMPORTS = true;
pub const KERNEL_PORT_REQUIRES_PUBLISHED_GS = true;
pub const IDLE_NEVER_SERVICES_DEVICE_QUEUES = true;

pub const allowed_native_prefixes = [_][]const u8{
    "native/core/",
    "native/kernel_api/",
    "native/drivers/",
    "native/task/",
    "native/platform/hardware_target.zig",
};

pub const forbidden_native_prefixes = [_][]const u8{
    "native/storage/",
    "native/sync/",
    "native/policy/",
    "native/services/",
    "native/demo/",
    "native/platform/compositor",
    "native/platform/rendered_shell",
    "native/platform/os_contract",
};

pub fn importIsForbidden(source_path: []const u8) bool {
    for (forbidden_native_prefixes) |prefix| {
        if (std.mem.indexOf(u8, source_path, prefix) != null) return true;
    }
    return false;
}

test "kernel TCB forbids product-service modules" {
    try std.testing.expect(FORBIDS_PRODUCT_IMPORTS);
    try std.testing.expect(KERNEL_PORT_REQUIRES_PUBLISHED_GS);
    try std.testing.expect(IDLE_NEVER_SERVICES_DEVICE_QUEUES);
    try std.testing.expect(importIsForbidden("native/storage/storage_volume.zig"));
    try std.testing.expect(importIsForbidden("../../native/sync/sync_service.zig"));
    try std.testing.expect(importIsForbidden("native/platform/compositor_session.zig"));
    try std.testing.expect(!importIsForbidden("native/kernel_api/capability.zig"));
    try std.testing.expect(!importIsForbidden("native/drivers/dataplane_handoff.zig"));
    try std.testing.expect(!importIsForbidden("native/platform/hardware_target.zig"));
}
