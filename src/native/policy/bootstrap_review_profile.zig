const manifest = @import("manifest.zig");
const permission_review_service = @import("permission_review_service.zig");

pub const rules = [_]permission_review_service.ProfileRule{
    .{
        .bundle_id = "app.notes",
        .kind = .object_access,
        .resource = "workspace:notes",
        .allow = true,
        .local_only = true,
        .lease_mode = .requested,
    },
    .{
        .bundle_id = "app.notes",
        .kind = .network_egress,
        .resource = "lan.sync",
        .allow = true,
        .local_only = true,
        .lease_mode = .requested,
    },
    .{
        .bundle_id = "app.notes",
        .kind = .clipboard,
        .resource = "clipboard",
        .allow = false,
    },
    .{
        .bundle_id = "app.sync",
        .kind = .background_execution,
        .resource = "sync",
        .allow = true,
        .lease_mode = .fixed,
        .fixed_lease_ticks = 10,
    },
    .{
        .bundle_id = "app.capture",
        .kind = .device_access,
        .resource = "capture.card0",
        .allow = true,
        .local_only = true,
        .lease_mode = .requested,
    },
    .{
        .bundle_id = "app.capture",
        .kind = .camera,
        .resource = "camera.front",
        .allow = true,
        .local_only = true,
        .lease_mode = .requested,
    },
    .{
        .bundle_id = "app.capture",
        .kind = .mic,
        .resource = "mic.array",
        .allow = false,
    },
    .{
        .bundle_id = "app.capture",
        .kind = .sensor,
        .resource = "sensor.lid",
        .allow = true,
        .local_only = true,
        .lease_mode = .requested,
    },
    .{
        .bundle_id = "app.capture",
        .kind = .peer_ipc,
        .resource = "zigos.peer.share",
        .allow = true,
        .local_only = true,
        .lease_mode = .requested,
    },
};

test "bootstrap review profile keeps the boot demo decisions explicit and typed" {
    try @import("std").testing.expectEqual(@as(usize, 9), rules.len);
    try @import("std").testing.expectEqual(manifest.PermissionKind.object_access, rules[0].kind);
    try @import("std").testing.expect(rules[0].allow);
    try @import("std").testing.expectEqual(permission_review_service.ProfileLeaseMode.fixed, rules[3].lease_mode);
}
