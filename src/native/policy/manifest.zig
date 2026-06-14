const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const units = @import("../core/units.zig");

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

pub const DataEgressIntentKind = enum(u8) {
    unspecified,
    sync_object,
    call_service,
    publish_event,
};

pub const DataSensitivity = enum(u8) {
    public_data,
    internal_data,
    private_user_data,
    secret_user_data,
};

pub const PermissionPurpose = enum(u8) {
    unspecified,
    user_requested_action,
    document_editing,
    communication,
    media_capture,
    accessibility,
    health,
    finance,
    security,
    development,
};

pub const DataEgressIntent = struct {
    kind: DataEgressIntentKind = .unspecified,
    object: []const u8 = "",
    principal: []const u8 = "",
    service: []const u8 = "",
    event_type: []const u8 = "",

    pub fn declared(self: DataEgressIntent) bool {
        return self.kind != .unspecified;
    }

    pub fn complete(self: DataEgressIntent) bool {
        return switch (self.kind) {
            .unspecified => false,
            .sync_object => self.object.len != 0 and self.principal.len != 0,
            .call_service => self.service.len != 0,
            .publish_event => self.event_type.len != 0,
        };
    }
};

pub const PermissionRequest = struct {
    kind: PermissionKind,
    resource: []const u8,
    rights: capability.CapabilityRights,
    required: bool = true,
    local_only: bool = false,
    max_lease_ticks: u64 = 0,
    target_id: u64 = 0,
    egress_intent: DataEgressIntent = .{},
    sensitivity: DataSensitivity = .internal_data,
    user_visible_reason: []const u8 = "",
    purpose: PermissionPurpose = .unspecified,
    retention_days: u16 = 0,
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
    private_context: bool = false,
    training_allowed: bool = false,
    max_context_bytes: usize = 0,
    audit_prompt_use: bool = false,
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

pub const SIGNATURE_FORMAT_ED25519 = "ed25519";
pub const SIGNATURE_FORMAT_ED25519_ML_DSA65 = "ed25519+ml-dsa65";
pub const SIGNATURE_FORMAT_ML_DSA65 = "ml-dsa-65";
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA65_PREVIEW_PUBLIC_COMMITMENT_BYTES: usize = 32;
pub const ML_DSA65_PREVIEW_SIGNATURE_BINDING_BYTES: usize = 32;
pub const ML_DSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA65_SIGNATURE_BYTES: usize = 3309;
pub const HYBRID_PUBLIC_KEY_BYTES: usize = ED25519_PUBLIC_KEY_BYTES + ML_DSA65_PREVIEW_PUBLIC_COMMITMENT_BYTES;
pub const HYBRID_SIGNATURE_BYTES: usize = ED25519_SIGNATURE_BYTES + ML_DSA65_PREVIEW_SIGNATURE_BINDING_BYTES;
pub const MAX_SIGNATURE_PUBLIC_KEY_BYTES: usize = HYBRID_PUBLIC_KEY_BYTES;
pub const MAX_SIGNATURE_VALUE_BYTES: usize = HYBRID_SIGNATURE_BYTES;

pub const Signature = struct {
    format: []const u8 = SIGNATURE_FORMAT_ED25519,
    signer: []const u8 = "",
    public_key_len: usize = 0,
    public_key: [MAX_SIGNATURE_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** MAX_SIGNATURE_PUBLIC_KEY_BYTES,
    value_len: usize = 0,
    value: [MAX_SIGNATURE_VALUE_BYTES]u8 = [_]u8{0} ** MAX_SIGNATURE_VALUE_BYTES,

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
        const layout = layoutForFormat(self.format) orelse return false;
        return self.isPresent() and
            self.public_key_len == layout.public_key_bytes and
            self.value_len == layout.value_bytes and
            self.public_key_len <= self.public_key.len and
            self.value_len <= self.value.len;
    }

    pub fn ed25519PublicKeySlice(self: *const Signature) []const u8 {
        if (self.public_key_len < ED25519_PUBLIC_KEY_BYTES) return self.public_key[0..0];
        return self.public_key[0..ED25519_PUBLIC_KEY_BYTES];
    }

    pub fn ed25519SignatureSlice(self: *const Signature) []const u8 {
        if (self.value_len < ED25519_SIGNATURE_BYTES) return self.value[0..0];
        return self.value[0..ED25519_SIGNATURE_BYTES];
    }

    pub fn hybridPostQuantumCommitmentSlice(self: *const Signature) []const u8 {
        if (self.public_key_len < HYBRID_PUBLIC_KEY_BYTES) return self.public_key[0..0];
        return self.public_key[ED25519_PUBLIC_KEY_BYTES..HYBRID_PUBLIC_KEY_BYTES];
    }

    pub fn hybridPostQuantumBindingSlice(self: *const Signature) []const u8 {
        if (self.value_len < HYBRID_SIGNATURE_BYTES) return self.value[0..0];
        return self.value[ED25519_SIGNATURE_BYTES..HYBRID_SIGNATURE_BYTES];
    }

    pub fn usesHybridPostQuantumProfile(self: *const Signature) bool {
        return std.mem.eql(u8, self.format, SIGNATURE_FORMAT_ED25519_ML_DSA65);
    }
};

pub const SignatureLayout = struct {
    public_key_bytes: usize,
    value_bytes: usize,
};

pub fn layoutForFormat(format: []const u8) ?SignatureLayout {
    if (std.mem.eql(u8, format, SIGNATURE_FORMAT_ED25519)) {
        return .{
            .public_key_bytes = ED25519_PUBLIC_KEY_BYTES,
            .value_bytes = ED25519_SIGNATURE_BYTES,
        };
    }
    if (std.mem.eql(u8, format, SIGNATURE_FORMAT_ED25519_ML_DSA65)) {
        return .{
            .public_key_bytes = HYBRID_PUBLIC_KEY_BYTES,
            .value_bytes = HYBRID_SIGNATURE_BYTES,
        };
    }
    return null;
}

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
    UntypedApplicationComponent,
    ComponentIdTooLong,
    ComponentEntryTooLong,
    DuplicateComponentId,
    TooManyAssets,
    AssetPathTooLong,
    AssetContentTypeTooLong,
    TooManyPermissions,
    PermissionResourceTooLong,
    PermissionReasonTooLong,
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
    MissingDataEgressIntent,
    IncompleteDataEgressIntent,
    PermissionRightsTargetMismatch,
    LocalOnlyPermissionRequestsRemoteNetwork,
    DuplicatePermissionRequest,
    SensitiveRemoteEgressRequiresIntent,
    SecretPermissionMustStayLocal,
    SensitivePermissionRequiresReason,
    SensitivePermissionRequiresPurpose,
    SensitivePermissionRequiresRetention,
    SensitiveRetentionTooLong,
    SecretRetentionTooLong,
    SensitivePermissionRequiresLease,
    AiModelFamilyTooLong,
    LocalOnlyAiRequiresLocalNetwork,
    OfflineAiRequiresLocalModel,
    AiTrainingRequiresAudit,
    AiContextTooLarge,
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
    try validatePermissionRights(bundle);
    try validateDuplicatePermissions(bundle);
    try validatePermissionPrivacy(bundle);
    try validateBackgroundTasks(bundle);
    try validateDataEgressRequests(bundle);
    try validateAiMetadata(bundle);
}

fn validateAiMetadata(bundle: BundleManifest) ValidationError!void {
    if (bundle.ai_metadata.locality == .local_only) {
        for (bundle.requested_permissions) |request| {
            if (request.kind != .network_egress) continue;
            if (!request.local_only or request.rights.has(.network_remote)) {
                return error.LocalOnlyAiRequiresLocalNetwork;
            }
        }
    }
    if (bundle.ai_metadata.offline_required and
        (bundle.ai_metadata.model_family.len == 0 or bundle.ai_metadata.locality != .local_only))
    {
        return error.OfflineAiRequiresLocalModel;
    }
    if (bundle.ai_metadata.training_allowed and !bundle.ai_metadata.audit_prompt_use) {
        return error.AiTrainingRequiresAudit;
    }
    if (bundle.ai_metadata.max_context_bytes > units.mebibytes(64)) {
        return error.AiContextTooLarge;
    }
}

fn validateDataEgressRequests(bundle: BundleManifest) ValidationError!void {
    if (!requiresApplicationPackaging(bundle.bundle_id)) return;

    for (bundle.requested_permissions) |request| {
        if (request.kind != .network_egress) continue;
        if (!request.egress_intent.declared()) return error.MissingDataEgressIntent;
        if (!request.egress_intent.complete()) return error.IncompleteDataEgressIntent;
    }
}

fn validatePermissionRights(bundle: BundleManifest) ValidationError!void {
    for (bundle.requested_permissions) |request| {
        if (!permissionRightsTargetCompatible(request)) return error.PermissionRightsTargetMismatch;
        if (request.local_only and request.rights.has(.network_remote)) {
            return error.LocalOnlyPermissionRequestsRemoteNetwork;
        }
    }
}

fn validateDuplicatePermissions(bundle: BundleManifest) ValidationError!void {
    for (bundle.requested_permissions, 0..) |request, index| {
        var previous_index: usize = 0;
        while (previous_index < index) : (previous_index += 1) {
            const previous = bundle.requested_permissions[previous_index];
            if (previous.kind == request.kind and std.mem.eql(u8, previous.resource, request.resource)) {
                return error.DuplicatePermissionRequest;
            }
        }
    }
}

fn validatePermissionPrivacy(bundle: BundleManifest) ValidationError!void {
    for (bundle.requested_permissions) |request| {
        if (request.sensitivity == .secret_user_data and !request.local_only) {
            return error.SecretPermissionMustStayLocal;
        }
        if (isSensitive(request.sensitivity) and dangerousPermissionKind(request.kind) and request.user_visible_reason.len == 0) {
            return error.SensitivePermissionRequiresReason;
        }
        if (isSensitive(request.sensitivity) and
            request.kind == .network_egress and
            request.rights.has(.network_remote) and
            (!request.egress_intent.declared() or !request.egress_intent.complete()))
        {
            return error.SensitiveRemoteEgressRequiresIntent;
        }
        if (isSensitive(request.sensitivity) and request.purpose == .unspecified) {
            return error.SensitivePermissionRequiresPurpose;
        }
        if (isSensitive(request.sensitivity) and request.retention_days == 0) {
            return error.SensitivePermissionRequiresRetention;
        }
        if (isSensitive(request.sensitivity) and request.retention_days > 365) {
            return error.SensitiveRetentionTooLong;
        }
        if (request.sensitivity == .secret_user_data and request.retention_days > 30) {
            return error.SecretRetentionTooLong;
        }
        if (isSensitive(request.sensitivity) and dangerousPermissionKind(request.kind) and request.max_lease_ticks == 0) {
            return error.SensitivePermissionRequiresLease;
        }
    }
}

fn permissionRightsTargetCompatible(request: PermissionRequest) bool {
    const target_kind = std.meta.activeTag(request.rights);
    return switch (request.kind) {
        .object_access, .contacts => target_kind == .object,
        .network_egress => target_kind == .network_policy,
        .device_access, .camera, .mic, .sensor, .location => target_kind == .device,
        .clipboard => target_kind == .service or target_kind == .workspace or target_kind == .policy,
        .screen_capture => target_kind == .service or target_kind == .workspace or target_kind == .policy or target_kind == .device,
        .notification_post => target_kind == .service or target_kind == .workspace or target_kind == .policy or target_kind == .task,
        .background_execution => target_kind == .task or target_kind == .policy,
        .peer_ipc => target_kind == .endpoint or target_kind == .service,
    };
}

pub fn isSensitive(sensitivity: DataSensitivity) bool {
    return switch (sensitivity) {
        .public_data, .internal_data => false,
        .private_user_data, .secret_user_data => true,
    };
}

pub fn dangerousPermissionKind(kind: PermissionKind) bool {
    return switch (kind) {
        .camera,
        .mic,
        .sensor,
        .location,
        .contacts,
        .screen_capture,
        .clipboard,
        .peer_ipc,
        => true,
        else => false,
    };
}

pub fn validateApplicationPackaging(bundle: BundleManifest) ValidationError!void {
    if (!requiresApplicationPackaging(bundle.bundle_id)) return;
    if (bundle.components.len == 0) return error.MissingExecutableComponent;
    if (bundle.provided_interfaces.len == 0 and bundle.consumed_interfaces.len == 0) {
        return error.MissingInterfaceDefinition;
    }
    if (bundle.assets.len == 0) return error.MissingAsset;
    for (bundle.components) |component| {
        if (component.abi != .typed_component_v1) return error.UntypedApplicationComponent;
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
        if (!permission.rights.has(.background_run)) return error.BackgroundPermissionMissingRunRight;

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
        std.mem.startsWith(u8, bundle_id, "svc.");
}

test "validate rejects background tasks without explicit background permission" {
    const background_tasks = [_]BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = units.kibibytes(1),
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
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .local_only = false,
            .egress_intent = .{
                .kind = .call_service,
                .service = "remote.model",
            },
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

test "validate requires offline AI manifests to name a local model" {
    try std.testing.expectError(error.OfflineAiRequiresLocalModel, validate(.{
        .bundle_id = "app.offline-ai",
        .display_name = "Offline AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .offline_required = true,
        },
    }));

    try std.testing.expectError(error.OfflineAiRequiresLocalModel, validate(.{
        .bundle_id = "app.remote-offline-ai",
        .display_name = "Remote Offline AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .locality = .remote_allowed,
            .offline_required = true,
        },
    }));
}

test "validate requires AI training audit and bounded context" {
    try std.testing.expectError(error.AiTrainingRequiresAudit, validate(.{
        .bundle_id = "app.training-ai",
        .display_name = "Training AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .locality = .local_only,
            .training_allowed = true,
        },
    }));

    try std.testing.expectError(error.AiContextTooLarge, validate(.{
        .bundle_id = "app.huge-context-ai",
        .display_name = "Huge Context AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .locality = .local_only,
            .private_context = true,
            .max_context_bytes = units.mebibytes(65),
        },
    }));
}

test "validate requires app data egress to declare sync call or publish intent" {
    const raw_network_requests = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "internet",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
        },
    };
    try std.testing.expectError(error.MissingDataEgressIntent, validate(.{
        .bundle_id = "app.raw-network",
        .display_name = "Raw Network",
        .publisher = "zigos.dev",
        .requested_permissions = &raw_network_requests,
    }));

    const incomplete_sync_requests = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_policy = .{ .network_local = true } },
            .required = false,
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace:notes",
            },
        },
    };
    try std.testing.expectError(error.IncompleteDataEgressIntent, validate(.{
        .bundle_id = "app.incomplete-sync",
        .display_name = "Incomplete Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &incomplete_sync_requests,
    }));
}

test "validate rejects permission rights with incompatible target kinds" {
    const camera_with_object_rights = [_]PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .object = .{ .object_read = true } },
            .required = false,
        },
    };
    try std.testing.expectError(error.PermissionRightsTargetMismatch, validate(.{
        .bundle_id = "app.bad-camera-rights",
        .display_name = "Bad Camera Rights",
        .publisher = "zigos.dev",
        .requested_permissions = &camera_with_object_rights,
    }));

    const object_with_network_rights = [_]PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
        },
    };
    try std.testing.expectError(error.PermissionRightsTargetMismatch, validate(.{
        .bundle_id = "app.bad-object-rights",
        .display_name = "Bad Object Rights",
        .publisher = "zigos.dev",
        .requested_permissions = &object_with_network_rights,
    }));
}

test "validate rejects local-only requests that ask for remote network authority" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "internet",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
            .local_only = true,
            .egress_intent = .{
                .kind = .call_service,
                .service = "remote.sync",
            },
        },
    };

    try std.testing.expectError(error.LocalOnlyPermissionRequestsRemoteNetwork, validate(.{
        .bundle_id = "app.local-remote-smuggle",
        .display_name = "Local Remote Smuggle",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    }));
}

test "validate requires sensitive permissions to declare reason and egress shape" {
    const secret_camera = [_]PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .sensitivity = .secret_user_data,
        },
    };
    try std.testing.expectError(error.SecretPermissionMustStayLocal, validate(.{
        .bundle_id = "app.secret-camera",
        .display_name = "Secret Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &secret_camera,
    }));

    const private_camera_without_reason = [_]PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
        },
    };
    try std.testing.expectError(error.SensitivePermissionRequiresReason, validate(.{
        .bundle_id = "app.private-camera",
        .display_name = "Private Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &private_camera_without_reason,
    }));

    const private_remote_without_intent = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
        },
    };
    try std.testing.expectError(error.SensitiveRemoteEgressRequiresIntent, validate(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &private_remote_without_intent,
    }));

    const private_remote_with_intent = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .user_visible_reason = "Sync private notes with trusted relay",
            .purpose = .document_editing,
            .retention_days = 30,
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace:notes",
                .principal = "trusted-relay",
            },
        },
    };
    try validate(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &private_remote_with_intent,
    });
}

test "validate requires sensitive permission purpose retention and bounded leases" {
    const missing_purpose = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .retention_days = 30,
            .egress_intent = .{
                .kind = .call_service,
                .service = "private.relay",
            },
        },
    };
    try std.testing.expectError(error.SensitivePermissionRequiresPurpose, validate(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &missing_purpose,
    }));

    const missing_retention = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .purpose = .document_editing,
            .egress_intent = .{
                .kind = .call_service,
                .service = "private.relay",
            },
        },
    };
    try std.testing.expectError(error.SensitivePermissionRequiresRetention, validate(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &missing_retention,
    }));

    const long_retention = [_]PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "relay.private",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .sensitivity = .private_user_data,
            .purpose = .document_editing,
            .retention_days = 366,
            .egress_intent = .{
                .kind = .call_service,
                .service = "private.relay",
            },
        },
    };
    try std.testing.expectError(error.SensitiveRetentionTooLong, validate(.{
        .bundle_id = "zigos.private-relay",
        .display_name = "Private Relay",
        .publisher = "zigos.dev",
        .requested_permissions = &long_retention,
    }));

    const secret_too_long = [_]PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:secrets",
            .rights = .{ .object = .{ .object_read = true } },
            .local_only = true,
            .sensitivity = .secret_user_data,
            .purpose = .security,
            .retention_days = 31,
        },
    };
    try std.testing.expectError(error.SecretRetentionTooLong, validate(.{
        .bundle_id = "zigos.secret-vault",
        .display_name = "Secret Vault",
        .publisher = "zigos.dev",
        .requested_permissions = &secret_too_long,
    }));

    const camera_without_lease = [_]PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{} },
            .local_only = true,
            .sensitivity = .private_user_data,
            .user_visible_reason = "Join a local video call",
            .purpose = .communication,
            .retention_days = 1,
        },
    };
    try std.testing.expectError(error.SensitivePermissionRequiresLease, validate(.{
        .bundle_id = "app.camera",
        .display_name = "Camera",
        .publisher = "zigos.dev",
        .requested_permissions = &camera_without_lease,
    }));
}

test "validate rejects duplicate permission requests" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
            .required = false,
            .local_only = true,
        },
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_write = true } },
            .required = false,
            .local_only = true,
        },
    };

    try std.testing.expectError(error.DuplicatePermissionRequest, validate(.{
        .bundle_id = "app.duplicate-permissions",
        .display_name = "Duplicate Permissions",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    }));
}

test "validate accepts a signed local-first bundle manifest" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_policy = .{ .network_local = true } },
            .required = false,
            .local_only = true,
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace:notes",
                .principal = "trusted-devices",
            },
        },
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .task = .{ .background_run = true } },
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
                .memory_bytes = units.kibibytes(64),
                .shared_memory_bytes = units.kibibytes(8),
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
            .private_context = true,
            .max_context_bytes = units.mebibytes(2),
            .audit_prompt_use = true,
        },
        .update_channel = .beta,
        .signature = .{
            .format = SIGNATURE_FORMAT_ED25519,
            .signer = "zigos-dev-key",
        },
    };

    try validate(bundle);
    try std.testing.expectEqual(@as(usize, 1), requiredPermissionCount(bundle));
    try validateApplicationPackaging(bundle);
}

test "compatibility namespaces are not reserved platform packages" {
    try std.testing.expect(!isReservedPlatformBundle("compat.posix"));
    try std.testing.expect(requiresApplicationPackaging("compat.posix"));
    try std.testing.expectError(error.MissingExecutableComponent, validateApplicationPackaging(.{
        .bundle_id = "compat.posix",
        .display_name = "Compat POSIX",
        .publisher = "zigos.dev",
    }));
}

test "example app packaging requires typed components" {
    const bundle = BundleManifest{
        .bundle_id = "app.untyped",
        .display_name = "Untyped",
        .publisher = "zigos.dev",
        .provided_interfaces = &.{.{ .name = "zigos.untyped.example" }},
        .components = &.{.{ .id = "untyped-main", .entry = "app.untyped.main", .abi = .native_sandbox }},
        .assets = &.{.{ .path = "assets/untyped/icon.svg", .content_type = "image/svg+xml" }},
    };

    try std.testing.expectError(error.UntypedApplicationComponent, validateApplicationPackaging(bundle));
}

test "validate rejects background execution permissions without task metadata" {
    const requests = [_]PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .task = .{ .background_run = true } },
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
            .rights = .{ .task = .{ .background_run = true } },
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
            .rights = .{ .task = .{ .background_run = true } },
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
                    .memory_bytes = units.kibibytes(1),
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
                    .memory_bytes = units.kibibytes(1),
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
            .rights = .{ .policy = .{} },
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
                .memory_bytes = units.kibibytes(1),
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
