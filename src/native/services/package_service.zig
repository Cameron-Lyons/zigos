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

pub const InstalledBundle = struct {
    bundle_id_len: usize,
    bundle_id: [MAX_LABEL_BYTES]u8,
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
    previous_version_major: u16,
    previous_version_minor: u16,
    previous_channel: manifest.UpdateChannel,
    previous_permission_digest: [32]u8,
    previous_schema_version: u32,
    previous_component_count: usize,
    previous_components: [MAX_COMPONENTS_PER_BUNDLE]StoredComponent,
    previous_asset_count: usize,
    previous_assets: [MAX_ASSETS_PER_BUNDLE]StoredAsset,
    rollback_available: bool,
    last_migration_manifest_len: usize,
    last_migration_manifest: [MAX_LABEL_BYTES]u8,

    pub fn bundleIdSlice(self: *const InstalledBundle) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
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
            bundle.rollback_available = true;

            bundle.publisher_len = copyText(&bundle.publisher, request.bundle.publisher);
            bundle.current_version_major = request.bundle.version_major;
            bundle.current_version_minor = request.bundle.version_minor;
            bundle.current_channel = request.bundle.update_channel;
            bundle.current_permission_digest = permission_digest;
            bundle.current_schema_version = request.data_schema_version;
            writeLaunchMetadata(bundle, request.bundle);
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
            slot.bundle.publisher_len = copyText(&slot.bundle.publisher, request.bundle.publisher);
            slot.bundle.current_version_major = request.bundle.version_major;
            slot.bundle.current_version_minor = request.bundle.version_minor;
            slot.bundle.current_channel = request.bundle.update_channel;
            slot.bundle.current_permission_digest = permission_digest;
            slot.bundle.current_schema_version = request.data_schema_version;
            writeLaunchMetadata(&slot.bundle, request.bundle);
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

        bundle.current_version_major = bundle.previous_version_major;
        bundle.current_version_minor = bundle.previous_version_minor;
        bundle.current_channel = bundle.previous_channel;
        bundle.current_permission_digest = bundle.previous_permission_digest;
        bundle.current_schema_version = bundle.previous_schema_version;
        bundle.current_component_count = bundle.previous_component_count;
        bundle.current_components = bundle.previous_components;
        bundle.current_asset_count = bundle.previous_asset_count;
        bundle.current_assets = bundle.previous_assets;

        bundle.previous_version_major = current_major;
        bundle.previous_version_minor = current_minor;
        bundle.previous_channel = current_channel;
        bundle.previous_permission_digest = current_permission_digest;
        bundle.previous_schema_version = current_schema_version;
        bundle.previous_component_count = current_component_count;
        bundle.previous_components = current_components;
        bundle.previous_asset_count = current_asset_count;
        bundle.previous_assets = current_assets;

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
        .previous_version_major = 0,
        .previous_version_minor = 0,
        .previous_channel = .stable,
        .previous_permission_digest = [_]u8{0} ** 32,
        .previous_schema_version = 0,
        .previous_component_count = 0,
        .previous_components = [_]StoredComponent{zeroStoredComponent()} ** MAX_COMPONENTS_PER_BUNDLE,
        .previous_asset_count = 0,
        .previous_assets = [_]StoredAsset{zeroStoredAsset()} ** MAX_ASSETS_PER_BUNDLE,
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

fn zeroStoredComponent() StoredComponent {
    return .{};
}

fn zeroStoredAsset() StoredAsset {
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
