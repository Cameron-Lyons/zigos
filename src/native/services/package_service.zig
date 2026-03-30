const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const signing = @import("../core/signing.zig");
const copyText = native_util.copyText;

pub const MAX_INSTALLED_BUNDLES: usize = 16;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_COMPONENTS_PER_BUNDLE: usize = 8;
pub const MAX_ASSETS_PER_BUNDLE: usize = 8;
pub const MAX_COMPONENT_ID_BYTES: usize = 48;
pub const MAX_COMPONENT_ENTRY_BYTES: usize = 64;
pub const MAX_ASSET_PATH_BYTES: usize = 64;
pub const MAX_CONTENT_TYPE_BYTES: usize = 32;
pub const MAX_INTERFACES_PER_BUNDLE: usize = 8;
pub const MAX_INTERFACE_NAME_BYTES: usize = 64;
pub const MAX_PERMISSIONS_PER_BUNDLE: usize = 16;
pub const MAX_PERMISSION_RESOURCE_BYTES: usize = 96;
pub const MAX_BACKGROUND_TASKS_PER_BUNDLE: usize = 8;
pub const MAX_BACKGROUND_TASK_ID_BYTES: usize = 48;
pub const MAX_MODEL_FAMILY_BYTES: usize = 48;
pub const MAX_SIGNATURE_FORMAT_BYTES: usize = 16;
pub const MAX_SIGNATURE_SIGNER_BYTES: usize = 64;

pub const InstallRequest = struct {
    bundle: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32 = 1,
    migration_manifest: []const u8 = "",
    declared_permission_change: bool = false,
};

pub const InstallResult = struct {
    installed_new: bool,
    updated_existing: bool,
    permissions_changed: bool,
    rollback_available: bool,
    migration_applied: bool,
};

pub const StoredComponent = struct {
    id_len: usize = 0,
    id: [MAX_COMPONENT_ID_BYTES]u8 = [_]u8{0} ** MAX_COMPONENT_ID_BYTES,
    entry_len: usize = 0,
    entry: [MAX_COMPONENT_ENTRY_BYTES]u8 = [_]u8{0} ** MAX_COMPONENT_ENTRY_BYTES,
    abi: manifest.ComponentAbi = .typed_component_v1,

    pub fn idSlice(self: *const StoredComponent) []const u8 {
        return self.id[0..self.id_len];
    }

    pub fn entrySlice(self: *const StoredComponent) []const u8 {
        return self.entry[0..self.entry_len];
    }
};

pub const StoredAsset = struct {
    path_len: usize = 0,
    path: [MAX_ASSET_PATH_BYTES]u8 = [_]u8{0} ** MAX_ASSET_PATH_BYTES,
    content_type_len: usize = 0,
    content_type: [MAX_CONTENT_TYPE_BYTES]u8 = [_]u8{0} ** MAX_CONTENT_TYPE_BYTES,

    pub fn pathSlice(self: *const StoredAsset) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn contentTypeSlice(self: *const StoredAsset) []const u8 {
        return self.content_type[0..self.content_type_len];
    }
};

pub const LaunchPlan = struct {
    component_count: usize,
    components: [MAX_COMPONENTS_PER_BUNDLE]StoredComponent,
    asset_count: usize,
    assets: [MAX_ASSETS_PER_BUNDLE]StoredAsset,
};

pub const StoredInterface = struct {
    name_len: usize = 0,
    name: [MAX_INTERFACE_NAME_BYTES]u8 = [_]u8{0} ** MAX_INTERFACE_NAME_BYTES,
    version_major: u16 = 1,
    version_minor: u16 = 0,

    pub fn nameSlice(self: *const StoredInterface) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const StoredPermission = struct {
    kind: manifest.PermissionKind = .object_access,
    resource_len: usize = 0,
    resource: [MAX_PERMISSION_RESOURCE_BYTES]u8 = [_]u8{0} ** MAX_PERMISSION_RESOURCE_BYTES,
    rights: @FieldType(manifest.PermissionRequest, "rights") = .{},
    required: bool = true,
    local_only: bool = false,
    max_lease_ticks: u64 = 0,
    target_id: u64 = 0,

    pub fn resourceSlice(self: *const StoredPermission) []const u8 {
        return self.resource[0..self.resource_len];
    }
};

pub const StoredBackgroundTask = struct {
    id_len: usize = 0,
    id: [MAX_BACKGROUND_TASK_ID_BYTES]u8 = [_]u8{0} ** MAX_BACKGROUND_TASK_ID_BYTES,
    trigger: manifest.BackgroundTrigger = .user_approved_scheduled_job,
    expected_duration_seconds: u32 = 0,
    budget: manifest.BackgroundResourceBudget = .{},
    network: manifest.BackgroundNetworkMode = .none,
    visibility: manifest.BackgroundVisibility = .status_only,

    pub fn idSlice(self: *const StoredBackgroundTask) []const u8 {
        return self.id[0..self.id_len];
    }
};

pub const StoredAiMetadata = struct {
    model_family_len: usize = 0,
    model_family: [MAX_MODEL_FAMILY_BYTES]u8 = [_]u8{0} ** MAX_MODEL_FAMILY_BYTES,
    locality: manifest.AiLocality = .inherit_task,
    offline_required: bool = false,

    pub fn modelFamilySlice(self: *const StoredAiMetadata) []const u8 {
        return self.model_family[0..self.model_family_len];
    }
};

pub const StoredSignature = struct {
    format_len: usize = 0,
    format: [MAX_SIGNATURE_FORMAT_BYTES]u8 = [_]u8{0} ** MAX_SIGNATURE_FORMAT_BYTES,
    signer_len: usize = 0,
    signer: [MAX_SIGNATURE_SIGNER_BYTES]u8 = [_]u8{0} ** MAX_SIGNATURE_SIGNER_BYTES,
    public_key_len: usize = 0,
    public_key: [32]u8 = [_]u8{0} ** 32,
    value_len: usize = 0,
    value: [64]u8 = [_]u8{0} ** 64,

    pub fn formatSlice(self: *const StoredSignature) []const u8 {
        return self.format[0..self.format_len];
    }

    pub fn signerSlice(self: *const StoredSignature) []const u8 {
        return self.signer[0..self.signer_len];
    }
};

pub const ResolvedManifest = struct {
    provided_interfaces: [MAX_INTERFACES_PER_BUNDLE]manifest.InterfaceDecl,
    consumed_interfaces: [MAX_INTERFACES_PER_BUNDLE]manifest.InterfaceDecl,
    components: [MAX_COMPONENTS_PER_BUNDLE]manifest.ExecutionComponentDecl,
    assets: [MAX_ASSETS_PER_BUNDLE]manifest.AssetDecl,
    requested_permissions: [MAX_PERMISSIONS_PER_BUNDLE]manifest.PermissionRequest,
    background_tasks: [MAX_BACKGROUND_TASKS_PER_BUNDLE]manifest.BackgroundTaskDecl,
    ai_metadata: manifest.AiMetadata,
    signature: manifest.Signature,
};

pub const InstalledBundle = struct {
    bundle_id_len: usize,
    bundle_id: [MAX_LABEL_BYTES]u8,
    display_name_len: usize,
    display_name: [MAX_LABEL_BYTES]u8,
    publisher_len: usize,
    publisher: [MAX_LABEL_BYTES]u8,
    current_version_major: u16,
    current_version_minor: u16,
    current_channel: manifest.UpdateChannel,
    current_permission_digest: [32]u8,
    current_schema_version: u32,
    current_component_count: usize,
    current_components: [MAX_COMPONENTS_PER_BUNDLE]StoredComponent,
    current_asset_count: usize,
    current_assets: [MAX_ASSETS_PER_BUNDLE]StoredAsset,
    current_provided_interface_count: usize,
    current_provided_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface,
    current_consumed_interface_count: usize,
    current_consumed_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface,
    current_requested_permission_count: usize,
    current_requested_permissions: [MAX_PERMISSIONS_PER_BUNDLE]StoredPermission,
    current_background_task_count: usize,
    current_background_tasks: [MAX_BACKGROUND_TASKS_PER_BUNDLE]StoredBackgroundTask,
    current_ai_metadata: StoredAiMetadata,
    current_signature: StoredSignature,
    previous_version_major: u16,
    previous_version_minor: u16,
    previous_channel: manifest.UpdateChannel,
    previous_permission_digest: [32]u8,
    previous_schema_version: u32,
    previous_component_count: usize,
    previous_components: [MAX_COMPONENTS_PER_BUNDLE]StoredComponent,
    previous_asset_count: usize,
    previous_assets: [MAX_ASSETS_PER_BUNDLE]StoredAsset,
    previous_provided_interface_count: usize,
    previous_provided_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface,
    previous_consumed_interface_count: usize,
    previous_consumed_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface,
    previous_requested_permission_count: usize,
    previous_requested_permissions: [MAX_PERMISSIONS_PER_BUNDLE]StoredPermission,
    previous_background_task_count: usize,
    previous_background_tasks: [MAX_BACKGROUND_TASKS_PER_BUNDLE]StoredBackgroundTask,
    previous_ai_metadata: StoredAiMetadata,
    previous_signature: StoredSignature,
    rollback_available: bool,
    last_migration_manifest_len: usize,
    last_migration_manifest: [MAX_LABEL_BYTES]u8,

    pub fn bundleIdSlice(self: *const InstalledBundle) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn displayNameSlice(self: *const InstalledBundle) []const u8 {
        return self.display_name[0..self.display_name_len];
    }

    pub fn publisherSlice(self: *const InstalledBundle) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const Error = manifest.ValidationError || error{
    BundleNotFound,
    BundleTableFull,
    InstallSourceDenied,
    InvalidManifestSignature,
    MigrationManifestRequired,
    NoRollbackVersion,
    PermissionChangeUndeclared,
};

const BundleSlot = struct {
    in_use: bool = false,
    bundle: InstalledBundle = zeroBundle(),
};

pub const Service = struct {
    slots: [MAX_INSTALLED_BUNDLES]BundleSlot = [_]BundleSlot{BundleSlot{}} ** MAX_INSTALLED_BUNDLES,

    pub fn init() Service {
        return .{};
    }

    pub fn install(
        self: *Service,
        request: InstallRequest,
        policy: ?*const policy_object.PolicyObject,
    ) Error!InstallResult {
        try manifest.validate(request.bundle);
        const digest = digestBundle(request.bundle);
        if (!signing.verify(request.bundle.signature, &digest)) {
            return error.InvalidManifestSignature;
        }
        if (policy) |active_policy| {
            if (!active_policy.allowsInstallSource(request.source_identity)) {
                return error.InstallSourceDenied;
            }
        }

        const permission_digest = permissionDigest(request.bundle.requested_permissions);
        const existing = self.find(request.bundle.bundle_id);
        if (existing) |bundle| {
            const permissions_changed = !std.mem.eql(u8, &bundle.current_permission_digest, &permission_digest);
            if (permissions_changed and !request.declared_permission_change) {
                return error.PermissionChangeUndeclared;
            }
            if (request.data_schema_version > bundle.current_schema_version and request.migration_manifest.len == 0) {
                return error.MigrationManifestRequired;
            }

            bundle.previous_version_major = bundle.current_version_major;
            bundle.previous_version_minor = bundle.current_version_minor;
            bundle.previous_channel = bundle.current_channel;
            bundle.previous_permission_digest = bundle.current_permission_digest;
            bundle.previous_schema_version = bundle.current_schema_version;
            bundle.previous_component_count = bundle.current_component_count;
            bundle.previous_components = bundle.current_components;
            bundle.previous_asset_count = bundle.current_asset_count;
            bundle.previous_assets = bundle.current_assets;
            bundle.previous_provided_interface_count = bundle.current_provided_interface_count;
            bundle.previous_provided_interfaces = bundle.current_provided_interfaces;
            bundle.previous_consumed_interface_count = bundle.current_consumed_interface_count;
            bundle.previous_consumed_interfaces = bundle.current_consumed_interfaces;
            bundle.previous_requested_permission_count = bundle.current_requested_permission_count;
            bundle.previous_requested_permissions = bundle.current_requested_permissions;
            bundle.previous_background_task_count = bundle.current_background_task_count;
            bundle.previous_background_tasks = bundle.current_background_tasks;
            bundle.previous_ai_metadata = bundle.current_ai_metadata;
            bundle.previous_signature = bundle.current_signature;
            bundle.rollback_available = true;

            bundle.display_name_len = copyText(&bundle.display_name, request.bundle.display_name);
            bundle.publisher_len = copyText(&bundle.publisher, request.bundle.publisher);
            bundle.current_version_major = request.bundle.version_major;
            bundle.current_version_minor = request.bundle.version_minor;
            bundle.current_channel = request.bundle.update_channel;
            bundle.current_permission_digest = permission_digest;
            bundle.current_schema_version = request.data_schema_version;
            writeLaunchMetadata(bundle, request.bundle);
            writeManifestMetadata(bundle, request.bundle);
            bundle.last_migration_manifest_len = copyText(&bundle.last_migration_manifest, request.migration_manifest);

            return .{
                .installed_new = false,
                .updated_existing = true,
                .permissions_changed = permissions_changed,
                .rollback_available = bundle.rollback_available,
                .migration_applied = request.migration_manifest.len != 0,
            };
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.bundle = zeroBundle();
            slot.bundle.bundle_id_len = copyText(&slot.bundle.bundle_id, request.bundle.bundle_id);
            slot.bundle.display_name_len = copyText(&slot.bundle.display_name, request.bundle.display_name);
            slot.bundle.publisher_len = copyText(&slot.bundle.publisher, request.bundle.publisher);
            slot.bundle.current_version_major = request.bundle.version_major;
            slot.bundle.current_version_minor = request.bundle.version_minor;
            slot.bundle.current_channel = request.bundle.update_channel;
            slot.bundle.current_permission_digest = permission_digest;
            slot.bundle.current_schema_version = request.data_schema_version;
            writeLaunchMetadata(&slot.bundle, request.bundle);
            writeManifestMetadata(&slot.bundle, request.bundle);
            slot.bundle.last_migration_manifest_len = copyText(&slot.bundle.last_migration_manifest, request.migration_manifest);
            return .{
                .installed_new = true,
                .updated_existing = false,
                .permissions_changed = false,
                .rollback_available = false,
                .migration_applied = request.migration_manifest.len != 0,
            };
        }

        return error.BundleTableFull;
    }

    pub fn rollback(self: *Service, bundle_id: []const u8) Error!InstallResult {
        const bundle = self.find(bundle_id) orelse return error.BundleNotFound;
        if (!bundle.rollback_available) return error.NoRollbackVersion;

        const current_major = bundle.current_version_major;
        const current_minor = bundle.current_version_minor;
        const current_channel = bundle.current_channel;
        const current_permission_digest = bundle.current_permission_digest;
        const current_schema_version = bundle.current_schema_version;
        const current_component_count = bundle.current_component_count;
        const current_components = bundle.current_components;
        const current_asset_count = bundle.current_asset_count;
        const current_assets = bundle.current_assets;
        const current_provided_interface_count = bundle.current_provided_interface_count;
        const current_provided_interfaces = bundle.current_provided_interfaces;
        const current_consumed_interface_count = bundle.current_consumed_interface_count;
        const current_consumed_interfaces = bundle.current_consumed_interfaces;
        const current_requested_permission_count = bundle.current_requested_permission_count;
        const current_requested_permissions = bundle.current_requested_permissions;
        const current_background_task_count = bundle.current_background_task_count;
        const current_background_tasks = bundle.current_background_tasks;
        const current_ai_metadata = bundle.current_ai_metadata;
        const current_signature = bundle.current_signature;

        bundle.current_version_major = bundle.previous_version_major;
        bundle.current_version_minor = bundle.previous_version_minor;
        bundle.current_channel = bundle.previous_channel;
        bundle.current_permission_digest = bundle.previous_permission_digest;
        bundle.current_schema_version = bundle.previous_schema_version;
        bundle.current_component_count = bundle.previous_component_count;
        bundle.current_components = bundle.previous_components;
        bundle.current_asset_count = bundle.previous_asset_count;
        bundle.current_assets = bundle.previous_assets;
        bundle.current_provided_interface_count = bundle.previous_provided_interface_count;
        bundle.current_provided_interfaces = bundle.previous_provided_interfaces;
        bundle.current_consumed_interface_count = bundle.previous_consumed_interface_count;
        bundle.current_consumed_interfaces = bundle.previous_consumed_interfaces;
        bundle.current_requested_permission_count = bundle.previous_requested_permission_count;
        bundle.current_requested_permissions = bundle.previous_requested_permissions;
        bundle.current_background_task_count = bundle.previous_background_task_count;
        bundle.current_background_tasks = bundle.previous_background_tasks;
        bundle.current_ai_metadata = bundle.previous_ai_metadata;
        bundle.current_signature = bundle.previous_signature;

        bundle.previous_version_major = current_major;
        bundle.previous_version_minor = current_minor;
        bundle.previous_channel = current_channel;
        bundle.previous_permission_digest = current_permission_digest;
        bundle.previous_schema_version = current_schema_version;
        bundle.previous_component_count = current_component_count;
        bundle.previous_components = current_components;
        bundle.previous_asset_count = current_asset_count;
        bundle.previous_assets = current_assets;
        bundle.previous_provided_interface_count = current_provided_interface_count;
        bundle.previous_provided_interfaces = current_provided_interfaces;
        bundle.previous_consumed_interface_count = current_consumed_interface_count;
        bundle.previous_consumed_interfaces = current_consumed_interfaces;
        bundle.previous_requested_permission_count = current_requested_permission_count;
        bundle.previous_requested_permissions = current_requested_permissions;
        bundle.previous_background_task_count = current_background_task_count;
        bundle.previous_background_tasks = current_background_tasks;
        bundle.previous_ai_metadata = current_ai_metadata;
        bundle.previous_signature = current_signature;

        return .{
            .installed_new = false,
            .updated_existing = true,
            .permissions_changed = true,
            .rollback_available = true,
            .migration_applied = false,
        };
    }

    pub fn find(self: *Service, bundle_id: []const u8) ?*InstalledBundle {
        for (&self.slots) |*slot| {
            if (slot.in_use and std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return &slot.bundle;
        }
        return null;
    }

    pub fn buildLaunchPlan(self: *const Service, bundle_id: []const u8) Error!LaunchPlan {
        const bundle = self.findConst(bundle_id) orelse return error.BundleNotFound;
        return .{
            .component_count = bundle.current_component_count,
            .components = bundle.current_components,
            .asset_count = bundle.current_asset_count,
            .assets = bundle.current_assets,
        };
    }

    pub fn resolveCurrentManifest(
        self: *const Service,
        bundle_id: []const u8,
        resolved: *ResolvedManifest,
    ) Error!manifest.BundleManifest {
        const bundle = self.findConst(bundle_id) orelse return error.BundleNotFound;

        var index: usize = 0;
        while (index < bundle.current_provided_interface_count) : (index += 1) {
            const stored = &bundle.current_provided_interfaces[index];
            resolved.provided_interfaces[index] = .{
                .name = stored.nameSlice(),
                .version_major = stored.version_major,
                .version_minor = stored.version_minor,
            };
        }

        index = 0;
        while (index < bundle.current_consumed_interface_count) : (index += 1) {
            const stored = &bundle.current_consumed_interfaces[index];
            resolved.consumed_interfaces[index] = .{
                .name = stored.nameSlice(),
                .version_major = stored.version_major,
                .version_minor = stored.version_minor,
            };
        }

        index = 0;
        while (index < bundle.current_component_count) : (index += 1) {
            const stored = &bundle.current_components[index];
            resolved.components[index] = .{
                .id = stored.idSlice(),
                .entry = stored.entrySlice(),
                .abi = stored.abi,
            };
        }

        index = 0;
        while (index < bundle.current_asset_count) : (index += 1) {
            const stored = &bundle.current_assets[index];
            resolved.assets[index] = .{
                .path = stored.pathSlice(),
                .content_type = stored.contentTypeSlice(),
            };
        }

        index = 0;
        while (index < bundle.current_requested_permission_count) : (index += 1) {
            const stored = &bundle.current_requested_permissions[index];
            resolved.requested_permissions[index] = .{
                .kind = stored.kind,
                .resource = stored.resourceSlice(),
                .rights = stored.rights,
                .required = stored.required,
                .local_only = stored.local_only,
                .max_lease_ticks = stored.max_lease_ticks,
                .target_id = stored.target_id,
            };
        }

        index = 0;
        while (index < bundle.current_background_task_count) : (index += 1) {
            const stored = &bundle.current_background_tasks[index];
            resolved.background_tasks[index] = .{
                .id = stored.idSlice(),
                .trigger = stored.trigger,
                .expected_duration_seconds = stored.expected_duration_seconds,
                .budget = stored.budget,
                .network = stored.network,
                .visibility = stored.visibility,
            };
        }

        resolved.ai_metadata = .{
            .model_family = bundle.current_ai_metadata.modelFamilySlice(),
            .locality = bundle.current_ai_metadata.locality,
            .offline_required = bundle.current_ai_metadata.offline_required,
        };
        resolved.signature = .{
            .format = bundle.current_signature.formatSlice(),
            .signer = bundle.current_signature.signerSlice(),
            .public_key_len = bundle.current_signature.public_key_len,
            .public_key = bundle.current_signature.public_key,
            .value_len = bundle.current_signature.value_len,
            .value = bundle.current_signature.value,
        };

        return .{
            .bundle_id = bundle.bundleIdSlice(),
            .display_name = bundle.displayNameSlice(),
            .publisher = bundle.publisherSlice(),
            .version_major = bundle.current_version_major,
            .version_minor = bundle.current_version_minor,
            .provided_interfaces = resolved.provided_interfaces[0..bundle.current_provided_interface_count],
            .consumed_interfaces = resolved.consumed_interfaces[0..bundle.current_consumed_interface_count],
            .components = resolved.components[0..bundle.current_component_count],
            .assets = resolved.assets[0..bundle.current_asset_count],
            .requested_permissions = resolved.requested_permissions[0..bundle.current_requested_permission_count],
            .background_tasks = resolved.background_tasks[0..bundle.current_background_task_count],
            .ai_metadata = resolved.ai_metadata,
            .update_channel = bundle.current_channel,
            .signature = resolved.signature,
        };
    }

    fn findConst(self: *const Service, bundle_id: []const u8) ?*const InstalledBundle {
        for (&self.slots) |*slot| {
            if (slot.in_use and std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return &slot.bundle;
        }
        return null;
    }
};

pub fn digestBundle(bundle: manifest.BundleManifest) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "bundle-id", bundle.bundle_id);
    crypto_hash.updateBytes(&hasher, "display-name", bundle.display_name);
    crypto_hash.updateBytes(&hasher, "publisher", bundle.publisher);
    crypto_hash.updateInt(&hasher, "version-major", bundle.version_major);
    crypto_hash.updateInt(&hasher, "version-minor", bundle.version_minor);
    crypto_hash.updateEnum(&hasher, "update-channel", bundle.update_channel);
    crypto_hash.updateBytes(&hasher, "ai-model-family", bundle.ai_metadata.model_family);
    crypto_hash.updateEnum(&hasher, "ai-locality", bundle.ai_metadata.locality);
    crypto_hash.updateBool(&hasher, "ai-offline-required", bundle.ai_metadata.offline_required);

    for (bundle.provided_interfaces, 0..) |interface, index| {
        crypto_hash.updateInt(&hasher, "provided-index", index);
        crypto_hash.updateBytes(&hasher, "provided-name", interface.name);
        crypto_hash.updateInt(&hasher, "provided-version-major", interface.version_major);
        crypto_hash.updateInt(&hasher, "provided-version-minor", interface.version_minor);
    }
    for (bundle.consumed_interfaces, 0..) |interface, index| {
        crypto_hash.updateInt(&hasher, "consumed-index", index);
        crypto_hash.updateBytes(&hasher, "consumed-name", interface.name);
        crypto_hash.updateInt(&hasher, "consumed-version-major", interface.version_major);
        crypto_hash.updateInt(&hasher, "consumed-version-minor", interface.version_minor);
    }
    for (bundle.components, 0..) |component, index| {
        crypto_hash.updateInt(&hasher, "component-index", index);
        crypto_hash.updateBytes(&hasher, "component-id", component.id);
        crypto_hash.updateBytes(&hasher, "component-entry", component.entry);
        crypto_hash.updateEnum(&hasher, "component-abi", component.abi);
    }
    for (bundle.assets, 0..) |asset, index| {
        crypto_hash.updateInt(&hasher, "asset-index", index);
        crypto_hash.updateBytes(&hasher, "asset-path", asset.path);
        crypto_hash.updateBytes(&hasher, "asset-content-type", asset.content_type);
    }
    for (bundle.requested_permissions, 0..) |permission, index| {
        const rights_bits: u32 = @bitCast(permission.rights);
        crypto_hash.updateInt(&hasher, "permission-index", index);
        crypto_hash.updateEnum(&hasher, "permission-kind", permission.kind);
        crypto_hash.updateBytes(&hasher, "permission-resource", permission.resource);
        crypto_hash.updateInt(&hasher, "permission-rights", rights_bits);
        crypto_hash.updateBool(&hasher, "permission-required", permission.required);
        crypto_hash.updateBool(&hasher, "permission-local-only", permission.local_only);
        crypto_hash.updateInt(&hasher, "permission-max-lease", permission.max_lease_ticks);
        crypto_hash.updateInt(&hasher, "permission-target-id", permission.target_id);
    }
    for (bundle.background_tasks, 0..) |task, index| {
        crypto_hash.updateInt(&hasher, "background-index", index);
        crypto_hash.updateBytes(&hasher, "background-id", task.id);
        crypto_hash.updateEnum(&hasher, "background-trigger", task.trigger);
        crypto_hash.updateInt(&hasher, "background-duration", task.expected_duration_seconds);
        crypto_hash.updateInt(&hasher, "background-budget-cpu", task.budget.cpu_time_ticks);
        crypto_hash.updateInt(&hasher, "background-budget-memory", task.budget.memory_bytes);
        crypto_hash.updateInt(&hasher, "background-budget-shared-memory", task.budget.shared_memory_bytes);
        crypto_hash.updateEnum(&hasher, "background-network", task.network);
        crypto_hash.updateEnum(&hasher, "background-visibility", task.visibility);
    }

    return crypto_hash.finalize(&hasher);
}

fn permissionDigest(requests: []const manifest.PermissionRequest) [32]u8 {
    var hasher = crypto_hash.init();
    for (requests, 0..) |request, index| {
        const rights_bits: u32 = @bitCast(request.rights);
        crypto_hash.updateInt(&hasher, "permission-index", index);
        crypto_hash.updateEnum(&hasher, "permission-kind", request.kind);
        crypto_hash.updateBytes(&hasher, "permission-resource", request.resource);
        crypto_hash.updateInt(&hasher, "permission-rights", rights_bits);
        crypto_hash.updateBool(&hasher, "permission-required", request.required);
        crypto_hash.updateBool(&hasher, "permission-local-only", request.local_only);
    }
    return crypto_hash.finalize(&hasher);
}

fn zeroBundle() InstalledBundle {
    return .{
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_LABEL_BYTES,
        .display_name_len = 0,
        .display_name = [_]u8{0} ** MAX_LABEL_BYTES,
        .publisher_len = 0,
        .publisher = [_]u8{0} ** MAX_LABEL_BYTES,
        .current_version_major = 0,
        .current_version_minor = 0,
        .current_channel = .stable,
        .current_permission_digest = [_]u8{0} ** 32,
        .current_schema_version = 0,
        .current_component_count = 0,
        .current_components = [_]StoredComponent{zeroStoredComponent()} ** MAX_COMPONENTS_PER_BUNDLE,
        .current_asset_count = 0,
        .current_assets = [_]StoredAsset{zeroStoredAsset()} ** MAX_ASSETS_PER_BUNDLE,
        .current_provided_interface_count = 0,
        .current_provided_interfaces = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
        .current_consumed_interface_count = 0,
        .current_consumed_interfaces = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
        .current_requested_permission_count = 0,
        .current_requested_permissions = [_]StoredPermission{zeroStoredPermission()} ** MAX_PERMISSIONS_PER_BUNDLE,
        .current_background_task_count = 0,
        .current_background_tasks = [_]StoredBackgroundTask{zeroStoredBackgroundTask()} ** MAX_BACKGROUND_TASKS_PER_BUNDLE,
        .current_ai_metadata = zeroStoredAiMetadata(),
        .current_signature = zeroStoredSignature(),
        .previous_version_major = 0,
        .previous_version_minor = 0,
        .previous_channel = .stable,
        .previous_permission_digest = [_]u8{0} ** 32,
        .previous_schema_version = 0,
        .previous_component_count = 0,
        .previous_components = [_]StoredComponent{zeroStoredComponent()} ** MAX_COMPONENTS_PER_BUNDLE,
        .previous_asset_count = 0,
        .previous_assets = [_]StoredAsset{zeroStoredAsset()} ** MAX_ASSETS_PER_BUNDLE,
        .previous_provided_interface_count = 0,
        .previous_provided_interfaces = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
        .previous_consumed_interface_count = 0,
        .previous_consumed_interfaces = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
        .previous_requested_permission_count = 0,
        .previous_requested_permissions = [_]StoredPermission{zeroStoredPermission()} ** MAX_PERMISSIONS_PER_BUNDLE,
        .previous_background_task_count = 0,
        .previous_background_tasks = [_]StoredBackgroundTask{zeroStoredBackgroundTask()} ** MAX_BACKGROUND_TASKS_PER_BUNDLE,
        .previous_ai_metadata = zeroStoredAiMetadata(),
        .previous_signature = zeroStoredSignature(),
        .rollback_available = false,
        .last_migration_manifest_len = 0,
        .last_migration_manifest = [_]u8{0} ** MAX_LABEL_BYTES,
    };
}


fn writeLaunchMetadata(bundle: *InstalledBundle, source: manifest.BundleManifest) void {
    bundle.current_component_count = @min(source.components.len, bundle.current_components.len);
    var component_index: usize = 0;
    while (component_index < bundle.current_components.len) : (component_index += 1) {
        bundle.current_components[component_index] = zeroStoredComponent();
        if (component_index >= bundle.current_component_count) continue;
        const component = source.components[component_index];
        bundle.current_components[component_index].id_len = copyText(&bundle.current_components[component_index].id, component.id);
        bundle.current_components[component_index].entry_len = copyText(&bundle.current_components[component_index].entry, component.entry);
        bundle.current_components[component_index].abi = component.abi;
    }

    bundle.current_asset_count = @min(source.assets.len, bundle.current_assets.len);
    var asset_index: usize = 0;
    while (asset_index < bundle.current_assets.len) : (asset_index += 1) {
        bundle.current_assets[asset_index] = zeroStoredAsset();
        if (asset_index >= bundle.current_asset_count) continue;
        const asset = source.assets[asset_index];
        bundle.current_assets[asset_index].path_len = copyText(&bundle.current_assets[asset_index].path, asset.path);
        bundle.current_assets[asset_index].content_type_len = copyText(&bundle.current_assets[asset_index].content_type, asset.content_type);
    }
}

fn writeManifestMetadata(bundle: *InstalledBundle, source: manifest.BundleManifest) void {
    bundle.current_provided_interface_count = @min(source.provided_interfaces.len, bundle.current_provided_interfaces.len);
    var interface_index: usize = 0;
    while (interface_index < bundle.current_provided_interfaces.len) : (interface_index += 1) {
        bundle.current_provided_interfaces[interface_index] = zeroStoredInterface();
        if (interface_index >= bundle.current_provided_interface_count) continue;
        const interface = source.provided_interfaces[interface_index];
        bundle.current_provided_interfaces[interface_index].name_len = copyText(&bundle.current_provided_interfaces[interface_index].name, interface.name);
        bundle.current_provided_interfaces[interface_index].version_major = interface.version_major;
        bundle.current_provided_interfaces[interface_index].version_minor = interface.version_minor;
    }

    bundle.current_consumed_interface_count = @min(source.consumed_interfaces.len, bundle.current_consumed_interfaces.len);
    interface_index = 0;
    while (interface_index < bundle.current_consumed_interfaces.len) : (interface_index += 1) {
        bundle.current_consumed_interfaces[interface_index] = zeroStoredInterface();
        if (interface_index >= bundle.current_consumed_interface_count) continue;
        const interface = source.consumed_interfaces[interface_index];
        bundle.current_consumed_interfaces[interface_index].name_len = copyText(&bundle.current_consumed_interfaces[interface_index].name, interface.name);
        bundle.current_consumed_interfaces[interface_index].version_major = interface.version_major;
        bundle.current_consumed_interfaces[interface_index].version_minor = interface.version_minor;
    }

    bundle.current_requested_permission_count = @min(source.requested_permissions.len, bundle.current_requested_permissions.len);
    var permission_index: usize = 0;
    while (permission_index < bundle.current_requested_permissions.len) : (permission_index += 1) {
        bundle.current_requested_permissions[permission_index] = zeroStoredPermission();
        if (permission_index >= bundle.current_requested_permission_count) continue;
        const permission = source.requested_permissions[permission_index];
        bundle.current_requested_permissions[permission_index].kind = permission.kind;
        bundle.current_requested_permissions[permission_index].resource_len = copyText(&bundle.current_requested_permissions[permission_index].resource, permission.resource);
        bundle.current_requested_permissions[permission_index].rights = permission.rights;
        bundle.current_requested_permissions[permission_index].required = permission.required;
        bundle.current_requested_permissions[permission_index].local_only = permission.local_only;
        bundle.current_requested_permissions[permission_index].max_lease_ticks = permission.max_lease_ticks;
        bundle.current_requested_permissions[permission_index].target_id = permission.target_id;
    }

    bundle.current_background_task_count = @min(source.background_tasks.len, bundle.current_background_tasks.len);
    var background_index: usize = 0;
    while (background_index < bundle.current_background_tasks.len) : (background_index += 1) {
        bundle.current_background_tasks[background_index] = zeroStoredBackgroundTask();
        if (background_index >= bundle.current_background_task_count) continue;
        const task = source.background_tasks[background_index];
        bundle.current_background_tasks[background_index].id_len = copyText(&bundle.current_background_tasks[background_index].id, task.id);
        bundle.current_background_tasks[background_index].trigger = task.trigger;
        bundle.current_background_tasks[background_index].expected_duration_seconds = task.expected_duration_seconds;
        bundle.current_background_tasks[background_index].budget = task.budget;
        bundle.current_background_tasks[background_index].network = task.network;
        bundle.current_background_tasks[background_index].visibility = task.visibility;
    }

    bundle.current_ai_metadata = zeroStoredAiMetadata();
    bundle.current_ai_metadata.model_family_len = copyText(&bundle.current_ai_metadata.model_family, source.ai_metadata.model_family);
    bundle.current_ai_metadata.locality = source.ai_metadata.locality;
    bundle.current_ai_metadata.offline_required = source.ai_metadata.offline_required;

    bundle.current_signature = zeroStoredSignature();
    bundle.current_signature.format_len = copyText(&bundle.current_signature.format, source.signature.format);
    bundle.current_signature.signer_len = copyText(&bundle.current_signature.signer, source.signature.signer);
    bundle.current_signature.public_key_len = @min(source.signature.public_key_len, bundle.current_signature.public_key.len);
    @memcpy(
        bundle.current_signature.public_key[0..bundle.current_signature.public_key_len],
        source.signature.public_key[0..bundle.current_signature.public_key_len],
    );
    bundle.current_signature.value_len = @min(source.signature.value_len, bundle.current_signature.value.len);
    @memcpy(
        bundle.current_signature.value[0..bundle.current_signature.value_len],
        source.signature.value[0..bundle.current_signature.value_len],
    );
}

fn zeroStoredComponent() StoredComponent {
    return .{};
}

fn zeroStoredAsset() StoredAsset {
    return .{};
}

fn zeroStoredInterface() StoredInterface {
    return .{};
}

fn zeroStoredPermission() StoredPermission {
    return .{};
}

fn zeroStoredBackgroundTask() StoredBackgroundTask {
    return .{};
}

fn zeroStoredAiMetadata() StoredAiMetadata {
    return .{};
}

fn zeroStoredSignature() StoredSignature {
    return .{};
}

test "package service enforces signed manifests policy gated sources updates and rollback" {
    var policies = policy_object.Directory.init();
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 1,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "org-app-sources",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
    }, .{
        .label = "policy-key",
        .seed = [_]u8{0x22} ** 32,
    });

    const bundle_key = signing.SignerIdentity{
        .label = "bundle-key",
        .seed = [_]u8{0x23} ** 32,
    };
    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
    };
    const v1_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 0,
        .components = &v1_components,
        .assets = &v1_assets,
        .requested_permissions = &v1_permissions,
        .update_channel = .stable,
    };
    v1.signature = try signing.sign(bundle_key, &digestBundle(v1));

    var service = Service.init();
    const first = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, org_policy);
    try std.testing.expect(first.installed_new);
    try std.testing.expect(!first.rollback_available);

    try std.testing.expectError(error.InstallSourceDenied, service.install(.{
        .bundle = v1,
        .source_identity = "repo:personal",
        .data_schema_version = 1,
    }, org_policy));

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "relay.notes.example",
            .rights = .{ .network_remote = true },
            .required = false,
        },
    };
    const v2_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        .{ .id = "notes-sync", .entry = "zigos.notes.sync", .abi = .native_sandbox },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/editor.css", .content_type = "text/css" },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .components = &v2_components,
        .assets = &v2_assets,
        .requested_permissions = &v2_permissions,
        .update_channel = .stable,
    };
    v2.signature = try signing.sign(bundle_key, &digestBundle(v2));

    try std.testing.expectError(error.PermissionChangeUndeclared, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
    }, org_policy));

    try std.testing.expectError(error.MigrationManifestRequired, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .declared_permission_change = true,
    }, org_policy));

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "notes-v2-migration",
        .declared_permission_change = true,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);
    try std.testing.expect(updated.migration_applied);

    const installed = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_major);
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_minor);
    try std.testing.expectEqual(@as(u32, 2), installed.current_schema_version);
    try std.testing.expectEqual(@as(usize, 2), installed.current_component_count);
    try std.testing.expectEqualStrings("zigos.notes.sync", installed.current_components[1].entrySlice());

    const launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 2), launch_plan.component_count);
    try std.testing.expectEqual(@as(usize, 2), launch_plan.asset_count);
    try std.testing.expectEqualStrings("notes-ui", launch_plan.components[0].idSlice());
    try std.testing.expectEqualStrings("assets/editor.css", launch_plan.assets[1].pathSlice());

    _ = try service.rollback("app.notes");
    const rolled_back = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), rolled_back.current_version_major);
    try std.testing.expectEqual(@as(u16, 0), rolled_back.current_version_minor);
    try std.testing.expectEqual(@as(u32, 1), rolled_back.current_schema_version);
    try std.testing.expectEqual(@as(usize, 1), rolled_back.current_component_count);
}

test "package service rejects invalid signatures and rollback before any update" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test",
        .seed = [_]u8{0x31} ** 32,
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true },
            .local_only = true,
        },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .requested_permissions = &permissions,
    };
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

    var tampered = bundle;
    tampered.publisher = "Malicious Fork";
    try std.testing.expectError(error.InvalidManifestSignature, service.install(.{
        .bundle = tampered,
        .source_identity = "store:zigos",
    }, null));

    _ = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null);
    try std.testing.expectError(error.NoRollbackVersion, service.rollback("app.notes"));
}

test "package service resolves installed manifests with stable slices" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-resolve",
        .seed = [_]u8{0x32} ** 32,
    };
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes", .entry = "app.notes" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
        },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
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
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .requested_permissions = &permissions,
        .background_tasks = &background_tasks,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
    };
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

    _ = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null);

    var resolved: ResolvedManifest = undefined;
    const current = try service.resolveCurrentManifest("app.notes", &resolved);

    try std.testing.expectEqualStrings("app.notes", current.bundle_id);
    try std.testing.expectEqualStrings("Notes", current.display_name);
    try std.testing.expectEqualStrings("zigos.workspace.document", current.provided_interfaces[0].name);
    try std.testing.expectEqualStrings("zigos.object.workspace", current.consumed_interfaces[0].name);
    try std.testing.expectEqualStrings("notes", current.components[0].id);
    try std.testing.expectEqualStrings("app.notes", current.components[0].entry);
    try std.testing.expectEqualStrings("workspace:notes", current.requested_permissions[0].resource);
    try std.testing.expectEqualStrings("sync", current.requested_permissions[1].resource);
    try std.testing.expectEqualStrings("sync", current.background_tasks[0].id);
    try std.testing.expectEqualStrings("tiny-embed", current.ai_metadata.model_family);
}
