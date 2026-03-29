const std = @import("std");
const capability = @import("../kernel_api/capability.zig");

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
    user_approved_scheduled_job,
    push_event,
    local_object_change,
    device_proximity,
    sensor_rule,
    sync_completion,
    media_export_completion,
    organization_policy_task,
};

pub const BackgroundNetworkMode = enum(u8) {
    none,
    local_network_only,
    named_service_identities,
    named_domains,
    unrestricted_internet,
};

pub const BackgroundVisibility = enum(u8) {
    hidden,
    status_only,
    user_visible,
    audit_only,
};

pub const BackgroundResourceBudget = struct {
    cpu_time_ticks: u64 = 0,
    memory_bytes: usize = 0,
    shared_memory_bytes: usize = 0,

    pub fn declared(self: BackgroundResourceBudget) bool {
        return self.cpu_time_ticks != 0 or
            self.memory_bytes != 0 or
            self.shared_memory_bytes != 0;
    }
};

pub const BackgroundTaskDecl = struct {
    id: []const u8,
    trigger: BackgroundTrigger,
    expected_duration_seconds: u32,
    budget: BackgroundResourceBudget = .{},
    network: BackgroundNetworkMode = .none,
    visibility: BackgroundVisibility = .status_only,
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

pub const ComponentAbi = enum(u8) {
    typed_component_v1,
    native_sandbox,
};

pub const ExecutionComponentDecl = struct {
    id: []const u8,
    entry: []const u8,
    abi: ComponentAbi = .typed_component_v1,
};

pub const AssetDecl = struct {
    path: []const u8,
    content_type: []const u8,
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
        return self.public_key[0..@min(self.public_key_len, self.public_key.len)];
    }

    pub fn valueSlice(self: *const Signature) []const u8 {
        return self.value[0..@min(self.value_len, self.value.len)];
    }

    pub fn isPresent(self: *const Signature) bool {
        return self.signer.len != 0 or
            (self.public_key_len != 0 and self.value_len != 0);
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
    components: []const ExecutionComponentDecl = &.{},
    assets: []const AssetDecl = &.{},
    requested_permissions: []const PermissionRequest = &.{},
    background_tasks: []const BackgroundTaskDecl = &.{},
    ai_metadata: AiMetadata = .{},
    update_channel: UpdateChannel = .stable,
    signature: Signature = .{},
};

pub const ValidationError = error{
    EmptyBundleId,
    EmptyDisplayName,
    EmptyPublisher,
    ComponentIdEmpty,
    ComponentEntryEmpty,
    DuplicateComponentId,
    MissingBackgroundPermission,
    MissingBackgroundTask,
    BackgroundTaskIdEmpty,
    BackgroundTaskDurationMissing,
    BackgroundTaskBudgetMissing,
    BackgroundTaskMissingPermission,
    BackgroundPermissionMissingTask,
    DuplicateBackgroundTaskId,
    LocalOnlyAiRequiresLocalNetwork,
};

pub fn validate(bundle: BundleManifest) ValidationError!void {
    if (bundle.bundle_id.len == 0) return error.EmptyBundleId;
    if (bundle.display_name.len == 0) return error.EmptyDisplayName;
    if (bundle.publisher.len == 0) return error.EmptyPublisher;

    if (bundle.background_tasks.len > 0 and !hasPermission(bundle, .background_execution)) {
        return error.MissingBackgroundPermission;
    }
    if (hasPermission(bundle, .background_execution) and bundle.background_tasks.len == 0) {
        return error.MissingBackgroundTask;
    }
    try validateComponents(bundle);
    try validateBackgroundTasks(bundle);

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

pub fn findBackgroundTask(bundle: BundleManifest, id: []const u8) ?BackgroundTaskDecl {
    for (bundle.background_tasks) |task| {
        if (std.mem.eql(u8, task.id, id)) return task;
    }
    return null;
}

pub fn requiredPermissionCount(bundle: BundleManifest) usize {
    var count: usize = 0;
    for (bundle.requested_permissions) |request| {
        if (request.required) count += 1;
    }
    return count;
}

fn validateBackgroundTasks(bundle: BundleManifest) ValidationError!void {
    for (bundle.background_tasks, 0..) |task, index| {
        if (task.id.len == 0) return error.BackgroundTaskIdEmpty;
        if (task.expected_duration_seconds == 0) return error.BackgroundTaskDurationMissing;
        if (!task.budget.declared()) return error.BackgroundTaskBudgetMissing;
        if (!hasBackgroundPermission(bundle, task.id)) return error.BackgroundTaskMissingPermission;

        var duplicate_index: usize = 0;
        while (duplicate_index < index) : (duplicate_index += 1) {
            if (std.mem.eql(u8, bundle.background_tasks[duplicate_index].id, task.id)) {
                return error.DuplicateBackgroundTaskId;
            }
        }
    }

    for (bundle.requested_permissions) |request| {
        if (request.kind != .background_execution) continue;
        if (findBackgroundTask(bundle, request.resource) == null) {
            return error.BackgroundPermissionMissingTask;
        }
    }
}

fn validateComponents(bundle: BundleManifest) ValidationError!void {
    for (bundle.components, 0..) |component, index| {
        if (component.id.len == 0) return error.ComponentIdEmpty;
        if (component.entry.len == 0) return error.ComponentEntryEmpty;

        var duplicate_index: usize = 0;
        while (duplicate_index < index) : (duplicate_index += 1) {
            if (std.mem.eql(u8, bundle.components[duplicate_index].id, component.id)) {
                return error.DuplicateComponentId;
            }
        }
    }
}

fn hasBackgroundPermission(bundle: BundleManifest, id: []const u8) bool {
    for (bundle.requested_permissions) |request| {
        if (request.kind != .background_execution) continue;
        if (std.mem.eql(u8, request.resource, id)) return true;
    }
    return false;
}

test "validate rejects background tasks without explicit background permission" {
    const background_tasks = [_]BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .background_tasks = &background_tasks,
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
    const background_tasks = [_]BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 64 * 1024,
                .shared_memory_bytes = 8 * 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .components = &[_]ExecutionComponentDecl{
            .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        },
        .provided_interfaces = &interfaces,
        .consumed_interfaces = &interfaces,
        .requested_permissions = &requests,
        .background_tasks = &background_tasks,
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

test "validate rejects background execution permissions without task metadata" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
            .required = false,
        },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    };

    try std.testing.expectError(error.MissingBackgroundTask, validate(bundle));
}

test "validate rejects incomplete background task declarations" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
            .required = false,
        },
    };
    const background_tasks = [_]BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .push_event,
            .expected_duration_seconds = 0,
        },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_tasks = &background_tasks,
    };

    try std.testing.expectError(error.BackgroundTaskDurationMissing, validate(bundle));
}

test "validate rejects incomplete or duplicate component declarations" {
    const invalid = BundleManifest{
        .bundle_id = "app.invalid",
        .display_name = "Invalid",
        .publisher = "zigos.dev",
        .components = &[_]ExecutionComponentDecl{
            .{ .id = "", .entry = "zigos.invalid.main" },
        },
    };
    try std.testing.expectError(error.ComponentIdEmpty, validate(invalid));

    const duplicate = BundleManifest{
        .bundle_id = "app.duplicate",
        .display_name = "Duplicate",
        .publisher = "zigos.dev",
        .components = &[_]ExecutionComponentDecl{
            .{ .id = "main", .entry = "zigos.duplicate.main" },
            .{ .id = "main", .entry = "zigos.duplicate.worker" },
        },
    };
    try std.testing.expectError(error.DuplicateComponentId, validate(duplicate));
}
