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
    unspecified,
    none,
    local_network_only,
    named_service_identities,
    named_domains,
    unrestricted_internet,
};

pub const BackgroundVisibility = enum(u8) {
    unspecified,
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
    network: BackgroundNetworkMode = .unspecified,
    visibility: BackgroundVisibility = .unspecified,
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
    BundleIdTooLong,
    DisplayNameTooLong,
    PublisherTooLong,
    MissingExecutableComponent,
    MissingInterfaceDefinition,
    MissingAsset,
    TooManyProvidedInterfaces,
    TooManyConsumedInterfaces,
    InterfaceNameTooLong,
    TooManyComponents,
    ComponentIdEmpty,
    ComponentEntryEmpty,
    ComponentIdTooLong,
    ComponentEntryTooLong,
    DuplicateComponentId,
    TooManyAssets,
    AssetPathTooLong,
    AssetContentTypeTooLong,
    TooManyPermissions,
    PermissionResourceTooLong,
    MissingBackgroundPermission,
    MissingBackgroundTask,
    TooManyBackgroundTasks,
    BackgroundTaskIdEmpty,
    BackgroundTaskIdTooLong,
    BackgroundTaskDurationMissing,
    BackgroundTaskBudgetMissing,
    BackgroundTaskNetworkMissing,
    BackgroundTaskVisibilityMissing,
    BackgroundTaskMissingPermission,
    BackgroundPermissionMissingRunRight,
    BackgroundPermissionMissingTask,
    DuplicateBackgroundTaskId,
    AiModelFamilyTooLong,
    LocalOnlyAiRequiresLocalNetwork,
    SignatureFormatTooLong,
    SignatureSignerTooLong,
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

pub fn validateApplicationPackaging(bundle: BundleManifest) ValidationError!void {
    if (!requiresApplicationPackaging(bundle.bundle_id)) return;
    if (bundle.components.len == 0) return error.MissingExecutableComponent;
    if (bundle.provided_interfaces.len == 0 and bundle.consumed_interfaces.len == 0) {
        return error.MissingInterfaceDefinition;
    }
    if (bundle.assets.len == 0) return error.MissingAsset;
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

pub fn findBackgroundPermission(bundle: BundleManifest, id: []const u8) ?PermissionRequest {
    for (bundle.requested_permissions) |request| {
        if (request.kind != .background_execution) continue;
        if (std.mem.eql(u8, request.resource, id)) return request;
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
        if (task.network == .unspecified) return error.BackgroundTaskNetworkMissing;
        if (task.visibility == .unspecified) return error.BackgroundTaskVisibilityMissing;
        const permission = findBackgroundPermission(bundle, task.id) orelse return error.BackgroundTaskMissingPermission;
        if (!permission.rights.background_run) return error.BackgroundPermissionMissingRunRight;

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

pub fn requiresApplicationPackaging(bundle_id: []const u8) bool {
    return !isReservedPlatformBundle(bundle_id);
}

pub fn isApplicationBundle(bundle_id: []const u8) bool {
    return requiresApplicationPackaging(bundle_id);
}

pub fn isReservedPlatformBundle(bundle_id: []const u8) bool {
    return std.mem.startsWith(u8, bundle_id, "zigos.") or
        std.mem.startsWith(u8, bundle_id, "svc.") or
        std.mem.startsWith(u8, bundle_id, "compat.");
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
    const assets = [_]AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
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
        .assets = &assets,
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
    try validateApplicationPackaging(bundle);
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
            .network = .local_network_only,
            .visibility = .status_only,
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

test "validate rejects background tasks that omit network and visibility declarations" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
            .required = false,
        },
    };

    try std.testing.expectError(error.BackgroundTaskNetworkMissing, validate(.{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_tasks = &[_]BackgroundTaskDecl{
            .{
                .id = "sync",
                .trigger = .push_event,
                .expected_duration_seconds = 10,
                .budget = .{
                    .cpu_time_ticks = 100,
                    .memory_bytes = 1024,
                },
                .visibility = .status_only,
            },
        },
    }));

    try std.testing.expectError(error.BackgroundTaskVisibilityMissing, validate(.{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_tasks = &[_]BackgroundTaskDecl{
            .{
                .id = "sync",
                .trigger = .push_event,
                .expected_duration_seconds = 10,
                .budget = .{
                    .cpu_time_ticks = 100,
                    .memory_bytes = 1024,
                },
                .network = .local_network_only,
            },
        },
    }));
}

test "validate rejects background task declarations without background run rights" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{},
            .required = false,
        },
    };
    const background_tasks = [_]BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .push_event,
            .expected_duration_seconds = 10,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const bundle = BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_tasks = &background_tasks,
    };

    try std.testing.expectError(error.BackgroundPermissionMissingRunRight, validate(bundle));
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

test "validateApplicationPackaging requires app bundles to declare components interfaces and assets" {
    const interfaces = [_]InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const assets = [_]AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };

    try std.testing.expectError(error.MissingExecutableComponent, validateApplicationPackaging(.{
        .bundle_id = "app.empty",
        .display_name = "Empty",
        .publisher = "zigos.dev",
    }));

    try std.testing.expectError(error.MissingInterfaceDefinition, validateApplicationPackaging(.{
        .bundle_id = "app.no-interfaces",
        .display_name = "No Interfaces",
        .publisher = "zigos.dev",
        .components = &[_]ExecutionComponentDecl{
            .{ .id = "main", .entry = "app.no-interfaces" },
        },
        .assets = &assets,
    }));

    try std.testing.expectError(error.MissingAsset, validateApplicationPackaging(.{
        .bundle_id = "app.no-assets",
        .display_name = "No Assets",
        .publisher = "zigos.dev",
        .components = &[_]ExecutionComponentDecl{
            .{ .id = "main", .entry = "app.no-assets" },
        },
        .provided_interfaces = &interfaces,
    }));

    try validateApplicationPackaging(.{
        .bundle_id = "zigos.system.storage",
        .display_name = "Storage",
        .publisher = "zigos.system",
        .components = &[_]ExecutionComponentDecl{
            .{ .id = "storage", .entry = "zigos.object.storage" },
        },
    });

    try std.testing.expectError(error.MissingExecutableComponent, validateApplicationPackaging(.{
        .bundle_id = "com.example.writer",
        .display_name = "Writer",
        .publisher = "Example Software",
    }));
}
