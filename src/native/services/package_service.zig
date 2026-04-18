const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const policy_object = @import("../policy/policy_object.zig");
const bundle_digest = @import("package_service_digest.zig");
const bundle_ops = @import("package_service_bundle_ops.zig");
const signing = @import("../core/signing.zig");

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
    retains_data_compatibility: bool = false,
    migration_applier: ?MigrationApplier = null,
};

pub const InstallResult = struct {
    installed_new: bool,
    updated_existing: bool,
    permissions_changed: bool,
    rollback_available: bool,
    migration_applied: bool,
};

pub const MigrationContext = struct {
    bundle_id: []const u8,
    from_schema_version: u32,
    to_schema_version: u32,
    migration_manifest: []const u8,
    previous_version_major: u16,
    previous_version_minor: u16,
    next_version_major: u16,
    next_version_minor: u16,
};

pub const MigrationApplier = *const fn (context: MigrationContext) anyerror!void;

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
    last_migration_manifest_len: usize,
    last_migration_manifest: [MAX_LABEL_BYTES]u8,

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

pub const Error = bundle_ops.Error || error{
    BundleNotFound,
    BundleTableFull,
    InstallSourceDenied,
    InvalidManifestSignature,
    MigrationManifestRequired,
    MigrationHandlerRequired,
    MigrationApplyFailed,
    InvalidMigrationManifest,
    NoRollbackVersion,
    PermissionChangeUndeclared,
};

pub const digestBundle = bundle_digest.digestBundle;

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
        try manifest.validateApplicationPackaging(request.bundle);
        try bundle_ops.validateInstallTarget(InstalledBundle, request.bundle, request.migration_manifest);
        const digest = bundle_digest.digestBundle(request.bundle);
        if (!signing.verify(request.bundle.signature, &digest)) {
            return error.InvalidManifestSignature;
        }
        if (policy) |active_policy| {
            if (!active_policy.allowsInstallSource(request.source_identity)) {
                return error.InstallSourceDenied;
            }
        }

        const permission_digest = bundle_digest.permissionDigest(request.bundle.requested_permissions);
        const existing = self.find(request.bundle.bundle_id);
        if (existing) |bundle| {
            const active_revision = bundle.activeRevision();
            const permissions_changed = !std.mem.eql(u8, &active_revision.permission_digest, &permission_digest);
            const schema_changed = request.data_schema_version != active_revision.schema_version;
            var migration_applied = false;
            if (permissions_changed and !request.declared_permission_change) {
                return error.PermissionChangeUndeclared;
            }
            if (schema_changed and request.migration_manifest.len == 0 and !request.retains_data_compatibility) {
                return error.MigrationManifestRequired;
            }
            if (request.migration_manifest.len != 0) {
                try bundle_digest.validateMigrationManifest(
                    Error,
                    request.migration_manifest,
                    active_revision.schema_version,
                    request.data_schema_version,
                );
                const migration_applier = request.migration_applier orelse return error.MigrationHandlerRequired;
                migration_applier(.{
                    .bundle_id = request.bundle.bundle_id,
                    .from_schema_version = active_revision.schema_version,
                    .to_schema_version = request.data_schema_version,
                    .migration_manifest = request.migration_manifest,
                    .previous_version_major = active_revision.version_major,
                    .previous_version_minor = active_revision.version_minor,
                    .next_version_major = request.bundle.version_major,
                    .next_version_minor = request.bundle.version_minor,
                }) catch return error.MigrationApplyFailed;
                migration_applied = true;
            }

            try bundle_ops.installRevision(
                bundle,
                request.bundle,
                request.data_schema_version,
                permission_digest,
                request.migration_manifest,
            );

            return .{
                .installed_new = false,
                .updated_existing = true,
                .permissions_changed = permissions_changed,
                .rollback_available = bundle.rollbackAvailable(),
                .migration_applied = migration_applied,
            };
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.bundle = zeroBundle();
            try bundle_ops.installNew(
                &slot.bundle,
                request.bundle,
                request.data_schema_version,
                permission_digest,
                request.migration_manifest,
            );
            return .{
                .installed_new = true,
                .updated_existing = false,
                .permissions_changed = false,
                .rollback_available = false,
                .migration_applied = false,
            };
        }

        return error.BundleTableFull;
    }

    pub fn rollback(self: *Service, bundle_id: []const u8) Error!InstallResult {
        const bundle = self.find(bundle_id) orelse return error.BundleNotFound;
        if (!bundle.rollbackAvailable()) return error.NoRollbackVersion;
        bundle_ops.rollback(bundle);

        return .{
            .installed_new = false,
            .updated_existing = true,
            .permissions_changed = true,
            .rollback_available = bundle.rollbackAvailable(),
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
        const active_revision = bundle.activeRevision();
        return .{
            .component_count = active_revision.component_count,
            .components = active_revision.components,
            .asset_count = active_revision.asset_count,
            .assets = active_revision.assets,
        };
    }

    pub fn resolveCurrentManifest(
        self: *const Service,
        bundle_id: []const u8,
        resolved: *ResolvedManifest,
    ) Error!manifest.BundleManifest {
        const bundle = self.findConst(bundle_id) orelse return error.BundleNotFound;
        return bundle_ops.resolveActiveManifest(bundle, resolved);
    }

    fn findConst(self: *const Service, bundle_id: []const u8) ?*const InstalledBundle {
        for (&self.slots) |*slot| {
            if (slot.in_use and std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return &slot.bundle;
        }
        return null;
    }
};

fn zeroBundle() InstalledBundle {
    return .{
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_LABEL_BYTES,
        .revision_count = 0,
        .next_revision_id = 1,
        .active_revision_slot = 0,
        .rollback_revision_slot = null,
        .revisions = [_]BundleRevision{zeroBundleRevision()} ** 2,
        .last_migration_manifest_len = 0,
        .last_migration_manifest = [_]u8{0} ** MAX_LABEL_BYTES,
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

const test_migration = struct {
    var apply_count: usize = 0;
    var last_context: MigrationContext = .{
        .bundle_id = "",
        .from_schema_version = 0,
        .to_schema_version = 0,
        .migration_manifest = "",
        .previous_version_major = 0,
        .previous_version_minor = 0,
        .next_version_major = 0,
        .next_version_minor = 0,
    };

    fn reset() void {
        apply_count = 0;
        last_context = .{
            .bundle_id = "",
            .from_schema_version = 0,
            .to_schema_version = 0,
            .migration_manifest = "",
            .previous_version_major = 0,
            .previous_version_minor = 0,
            .next_version_major = 0,
            .next_version_minor = 0,
        };
    }

    fn apply(context: MigrationContext) anyerror!void {
        apply_count += 1;
        last_context = context;
    }
};

test "package service enforces signed manifests policy gated sources updates and rollback" {
    test_migration.reset();
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
    const v1_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
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
        .provided_interfaces = v1_interfaces[0..1],
        .consumed_interfaces = v1_interfaces[1..2],
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
    const v2_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
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
        .provided_interfaces = v2_interfaces[0..1],
        .consumed_interfaces = v2_interfaces[1..2],
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

    try std.testing.expectError(error.InvalidMigrationManifest, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "notes-v2-migration",
        .declared_permission_change = true,
    }, org_policy));

    try std.testing.expectError(error.MigrationHandlerRequired, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "schema:1->2;notes-v2-migration",
        .declared_permission_change = true,
    }, org_policy));

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "schema:1->2;notes-v2-migration",
        .declared_permission_change = true,
        .migration_applier = test_migration.apply,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);
    try std.testing.expect(updated.migration_applied);
    try std.testing.expectEqual(@as(usize, 1), test_migration.apply_count);
    try std.testing.expectEqual(@as(u32, 1), test_migration.last_context.from_schema_version);
    try std.testing.expectEqual(@as(u32, 2), test_migration.last_context.to_schema_version);
    try std.testing.expectEqualStrings("schema:1->2;notes-v2-migration", test_migration.last_context.migration_manifest);

    const installed = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), installed.versionMajor());
    try std.testing.expectEqual(@as(u16, 1), installed.versionMinor());
    try std.testing.expectEqual(@as(u32, 2), installed.schemaVersion());
    try std.testing.expectEqual(@as(usize, 2), installed.componentCount());
    try std.testing.expectEqualStrings("zigos.notes.sync", installed.componentAt(1).entrySlice());

    const launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 2), launch_plan.component_count);
    try std.testing.expectEqual(@as(usize, 2), launch_plan.asset_count);
    try std.testing.expectEqualStrings("notes-ui", launch_plan.components[0].idSlice());
    try std.testing.expectEqualStrings("assets/editor.css", launch_plan.assets[1].pathSlice());

    _ = try service.rollback("app.notes");
    const rolled_back = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), rolled_back.versionMajor());
    try std.testing.expectEqual(@as(u16, 0), rolled_back.versionMinor());
    try std.testing.expectEqual(@as(u32, 1), rolled_back.schemaVersion());
    try std.testing.expectEqual(@as(usize, 1), rolled_back.componentCount());
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
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        },
        .assets = &assets,
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

test "package service rejects oversized manifests instead of truncating stored metadata" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-bounds",
        .seed = [_]u8{0x36} ** 32,
    };
    const long_bundle_id = [_]u8{'b'} ** (MAX_LABEL_BYTES + 1);
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = long_bundle_id[0..],
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        },
        .assets = &assets,
    };
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

    try std.testing.expectError(error.BundleIdTooLong, service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null));

    const long_migration_manifest = [_]u8{'m'} ** (MAX_LABEL_BYTES + 1);
    bundle.bundle_id = "app.notes";
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));
    try std.testing.expectError(error.MigrationManifestTooLong, service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .migration_manifest = long_migration_manifest[0..],
    }, null));
}

test "package service treats lease and target scope changes as declared permission changes" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-lease-scope",
        .seed = [_]u8{0x34} ** 32,
    };
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true },
            .local_only = true,
            .max_lease_ticks = 120,
            .target_id = 7,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        },
        .assets = &assets,
        .requested_permissions = &v1_permissions,
    };
    v1.signature = try signing.sign(signer_identity, &digestBundle(v1));

    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true },
            .local_only = true,
            .max_lease_ticks = 240,
            .target_id = 9,
        },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_minor = 1,
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        },
        .assets = &assets,
        .requested_permissions = &v2_permissions,
    };
    v2.signature = try signing.sign(signer_identity, &digestBundle(v2));

    try std.testing.expectError(error.PermissionChangeUndeclared, service.install(.{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
        .declared_permission_change = true,
    }, null);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(!updated.migration_applied);
}

test "package service accepts compatible schema updates without a migration manifest" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-compat",
        .seed = [_]u8{0x35} ** 32,
    };
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true },
            .local_only = true,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        },
        .assets = &assets,
        .requested_permissions = &permissions,
    };
    v1.signature = try signing.sign(signer_identity, &digestBundle(v1));
    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    var v2 = v1;
    v2.version_minor = 1;
    v2.signature = try signing.sign(signer_identity, &digestBundle(v2));

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 2,
        .retains_data_compatibility = true,
    }, null);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(!updated.migration_applied);
    try std.testing.expectEqual(@as(u32, 2), service.find("app.notes").?.schemaVersion());
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
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
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
        .assets = &assets,
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
