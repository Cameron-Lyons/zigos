const manifest = @import("../policy/manifest.zig");

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
    declared_permission_change: bool = false,
};

pub const InstallResult = struct {
    installed_new: bool,
    updated_existing: bool,
    permissions_changed: bool,
    rollback_available: bool,
};

pub const RemoveResult = struct {
    removed_existing: bool,
    removed_revision_count: usize,
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
    rights: @FieldType(manifest.PermissionRequest, "rights") = .{ .policy = .{} },
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
    public_key: [manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES,
    value_len: usize = 0,
    value: [manifest.MAX_SIGNATURE_VALUE_BYTES]u8 = [_]u8{0} ** manifest.MAX_SIGNATURE_VALUE_BYTES,

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

pub const BundleRevision = struct {
    revision_id: u32 = 0,
    display_name_len: usize = 0,
    display_name: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    publisher_len: usize = 0,
    publisher: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    version_major: u16 = 0,
    version_minor: u16 = 0,
    channel: manifest.UpdateChannel = .stable,
    permission_digest: [32]u8 = [_]u8{0} ** 32,
    schema_version: u32 = 0,
    component_count: usize = 0,
    components: [MAX_COMPONENTS_PER_BUNDLE]StoredComponent = [_]StoredComponent{zeroStoredComponent()} ** MAX_COMPONENTS_PER_BUNDLE,
    asset_count: usize = 0,
    assets: [MAX_ASSETS_PER_BUNDLE]StoredAsset = [_]StoredAsset{zeroStoredAsset()} ** MAX_ASSETS_PER_BUNDLE,
    provided_interface_count: usize = 0,
    provided_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
    consumed_interface_count: usize = 0,
    consumed_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
    requested_permission_count: usize = 0,
    requested_permissions: [MAX_PERMISSIONS_PER_BUNDLE]StoredPermission = [_]StoredPermission{zeroStoredPermission()} ** MAX_PERMISSIONS_PER_BUNDLE,
    background_task_count: usize = 0,
    background_tasks: [MAX_BACKGROUND_TASKS_PER_BUNDLE]StoredBackgroundTask = [_]StoredBackgroundTask{zeroStoredBackgroundTask()} ** MAX_BACKGROUND_TASKS_PER_BUNDLE,
    ai_metadata: StoredAiMetadata = zeroStoredAiMetadata(),
    signature: StoredSignature = zeroStoredSignature(),

    pub fn displayNameSlice(self: *const BundleRevision) []const u8 {
        return self.display_name[0..self.display_name_len];
    }

    pub fn publisherSlice(self: *const BundleRevision) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const InstalledBundle = struct {
    bundle_id_len: usize,
    bundle_id: [MAX_LABEL_BYTES]u8,
    revision_count: usize,
    next_revision_id: u32,
    active_revision_slot: u8,
    rollback_revision_slot: ?u8,
    revisions: [2]BundleRevision,

    pub fn bundleIdSlice(self: *const InstalledBundle) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn activeRevision(self: *const InstalledBundle) *const BundleRevision {
        return &self.revisions[self.active_revision_slot];
    }

    pub fn activeRevisionMut(self: *InstalledBundle) *BundleRevision {
        return &self.revisions[self.active_revision_slot];
    }

    pub fn rollbackRevision(self: *const InstalledBundle) ?*const BundleRevision {
        const slot = self.rollback_revision_slot orelse return null;
        return &self.revisions[slot];
    }

    pub fn rollbackAvailable(self: *const InstalledBundle) bool {
        return self.rollback_revision_slot != null;
    }

    pub fn displayNameSlice(self: *const InstalledBundle) []const u8 {
        return self.activeRevision().displayNameSlice();
    }

    pub fn publisherSlice(self: *const InstalledBundle) []const u8 {
        return self.activeRevision().publisherSlice();
    }

    pub fn inactiveRevisionSlot(self: *const InstalledBundle) u8 {
        return if (self.active_revision_slot == 0) 1 else 0;
    }

    pub fn versionMajor(self: *const InstalledBundle) u16 {
        return self.activeRevision().version_major;
    }

    pub fn versionMinor(self: *const InstalledBundle) u16 {
        return self.activeRevision().version_minor;
    }

    pub fn schemaVersion(self: *const InstalledBundle) u32 {
        return self.activeRevision().schema_version;
    }

    pub fn componentCount(self: *const InstalledBundle) usize {
        return self.activeRevision().component_count;
    }

    pub fn componentAt(self: *const InstalledBundle, index: usize) *const StoredComponent {
        return &self.activeRevision().components[index];
    }
};

pub const BundleSlot = struct {
    in_use: bool = false,
    bundle: InstalledBundle = zeroBundle(),
};

pub fn zeroBundle() InstalledBundle {
    return .{
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_LABEL_BYTES,
        .revision_count = 0,
        .next_revision_id = 1,
        .active_revision_slot = 0,
        .rollback_revision_slot = null,
        .revisions = [_]BundleRevision{zeroBundleRevision()} ** 2,
    };
}

fn zeroBundleRevision() BundleRevision {
    return .{};
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
