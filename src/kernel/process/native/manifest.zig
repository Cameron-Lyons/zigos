const std = @import("std");
const capability = @import("capability.zig");

pub const InterfaceDecl = struct {
    name: []const u8,
    version_major: u16 = 1,
    version_minor: u16 = 0,
};

pub const PermissionKind = enum(u8) {
    object_access,
    network_egress,
    device_access,
    clipboard,
    camera,
    mic,
    sensor,
    location,
    contacts,
    screen_capture,
    notification_post,
    background_execution,
    peer_ipc,
};

pub const PermissionRequest = struct {
    kind: PermissionKind,
    resource: []const u8,
    rights: capability.CapabilityRights,
    required: bool = true,
    local_only: bool = false,
    max_lease_ticks: u64 = 0,
    target_id: u64 = 0,
};

pub const BackgroundTrigger = enum(u8) {
    workspace_open,
    scheduled_sync,
    notification,
    share_target,
};

pub const AiLocality = enum(u8) {
    inherit_task,
    local_only,
    remote_allowed,
};

pub const AiMetadata = struct {
    model_family: []const u8 = "",
    locality: AiLocality = .inherit_task,
    offline_required: bool = false,
};

pub const UpdateChannel = enum(u8) {
    stable,
    beta,
    dev,
    pinned,
};

pub const Signature = struct {
    format: []const u8 = "ed25519",
    signer: []const u8 = "",
    public_key_len: usize = 0,
    public_key: [32]u8 = [_]u8{0} ** 32,
    value_len: usize = 0,
    value: [64]u8 = [_]u8{0} ** 64,

    pub fn publicKeySlice(self: *const Signature) []const u8 {
        return self.public_key[0..self.public_key_len];
    }

    pub fn valueSlice(self: *const Signature) []const u8 {
        return self.value[0..self.value_len];
    }

    pub fn isPresent(self: *const Signature) bool {
        return self.signer.len != 0;
    }

    pub fn isComplete(self: *const Signature) bool {
        return self.isPresent() and
            std.mem.eql(u8, self.format, "ed25519") and
            self.public_key_len == self.public_key.len and
            self.value_len == self.value.len;
    }
};

pub const BundleManifest = struct {
    bundle_id: []const u8,
    display_name: []const u8,
    publisher: []const u8,
    version_major: u16 = 1,
    version_minor: u16 = 0,
    provided_interfaces: []const InterfaceDecl = &.{},
    consumed_interfaces: []const InterfaceDecl = &.{},
    requested_permissions: []const PermissionRequest = &.{},
    background_triggers: []const BackgroundTrigger = &.{},
    ai_metadata: AiMetadata = .{},
    update_channel: UpdateChannel = .stable,
    signature: Signature = .{},
};

pub const ValidationError = error{
    EmptyBundleId,
    EmptyDisplayName,
    EmptyPublisher,
    MissingBackgroundPermission,
    LocalOnlyAiRequiresLocalNetwork,
};

pub fn validate(bundle: BundleManifest) ValidationError!void {
    if (bundle.bundle_id.len == 0) return error.EmptyBundleId;
    if (bundle.display_name.len == 0) return error.EmptyDisplayName;
    if (bundle.publisher.len == 0) return error.EmptyPublisher;

    if (bundle.background_triggers.len > 0 and !hasPermission(bundle, .background_execution)) {
        return error.MissingBackgroundPermission;
    }

    if (bundle.ai_metadata.locality == .local_only) {
        for (bundle.requested_permissions) |request| {
            if (request.kind != .network_egress) continue;
            if (!request.local_only or request.rights.network_remote) {
                return error.LocalOnlyAiRequiresLocalNetwork;
            }
        }
    }
}

pub fn hasPermission(bundle: BundleManifest, kind: PermissionKind) bool {
    for (bundle.requested_permissions) |request| {
        if (request.kind == kind) return true;
    }
    return false;
}

pub fn requiredPermissionCount(bundle: BundleManifest) usize {
    var count: usize = 0;
    for (bundle.requested_permissions) |request| {
        if (request.required) count += 1;
    }
    return count;
}

test "validate rejects background triggers without explicit background permission" {
    const bundle = BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .background_triggers = &.{.scheduled_sync},
    };

    try std.testing.expectError(error.MissingBackgroundPermission, validate(bundle));
}

test "validate requires local-only AI manifests to keep network requests local" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "internet",
            .rights = .{ .network_remote = true },
            .local_only = false,
        },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.assistant",
        .display_name = "Assistant",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
    };

    try std.testing.expectError(error.LocalOnlyAiRequiresLocalNetwork, validate(bundle));
}

test "validate accepts a signed local-first bundle manifest" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
        },
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
            .required = false,
        },
    };
    const interfaces = [_]InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .provided_interfaces = &interfaces,
        .consumed_interfaces = &interfaces,
        .requested_permissions = &requests,
        .background_triggers = &.{.workspace_open},
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
        .update_channel = .beta,
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-dev-key",
        },
    };

    try validate(bundle);
    try std.testing.expectEqual(@as(usize, 1), requiredPermissionCount(bundle));
}
