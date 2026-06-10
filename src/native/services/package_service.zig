const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const capability = @import("../kernel_api/capability.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const bundle_digest = @import("package_service_digest.zig");
const bundle_ops = @import("package_service_bundle_ops.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const model = @import("package_service_model.zig");
const native_util = @import("../core/util.zig");
const service_authority = @import("service_authority.zig");
const signing = @import("../core/signing.zig");

pub const MAX_INSTALLED_BUNDLES = model.MAX_INSTALLED_BUNDLES;
pub const MAX_LABEL_BYTES = model.MAX_LABEL_BYTES;
pub const MAX_COMPONENTS_PER_BUNDLE = model.MAX_COMPONENTS_PER_BUNDLE;
pub const MAX_ASSETS_PER_BUNDLE = model.MAX_ASSETS_PER_BUNDLE;
pub const MAX_COMPONENT_ID_BYTES = model.MAX_COMPONENT_ID_BYTES;
pub const MAX_COMPONENT_ENTRY_BYTES = model.MAX_COMPONENT_ENTRY_BYTES;
pub const MAX_ASSET_PATH_BYTES = model.MAX_ASSET_PATH_BYTES;
pub const MAX_CONTENT_TYPE_BYTES = model.MAX_CONTENT_TYPE_BYTES;
pub const MAX_INTERFACES_PER_BUNDLE = model.MAX_INTERFACES_PER_BUNDLE;
pub const MAX_INTERFACE_NAME_BYTES = model.MAX_INTERFACE_NAME_BYTES;
pub const MAX_PERMISSIONS_PER_BUNDLE = model.MAX_PERMISSIONS_PER_BUNDLE;
pub const MAX_PERMISSION_RESOURCE_BYTES = model.MAX_PERMISSION_RESOURCE_BYTES;
pub const MAX_BACKGROUND_TASKS_PER_BUNDLE = model.MAX_BACKGROUND_TASKS_PER_BUNDLE;
pub const MAX_BACKGROUND_TASK_ID_BYTES = model.MAX_BACKGROUND_TASK_ID_BYTES;
pub const MAX_MODEL_FAMILY_BYTES = model.MAX_MODEL_FAMILY_BYTES;
pub const MAX_SIGNATURE_FORMAT_BYTES = model.MAX_SIGNATURE_FORMAT_BYTES;
pub const MAX_SIGNATURE_SIGNER_BYTES = model.MAX_SIGNATURE_SIGNER_BYTES;
pub const InstallRequest = model.InstallRequest;
pub const InstallResult = model.InstallResult;
pub const RemoveResult = model.RemoveResult;
pub const StoredComponent = model.StoredComponent;
pub const StoredAsset = model.StoredAsset;
pub const LaunchPlan = model.LaunchPlan;
pub const StoredInterface = model.StoredInterface;
pub const StoredPermission = model.StoredPermission;
pub const StoredBackgroundTask = model.StoredBackgroundTask;
pub const StoredAiMetadata = model.StoredAiMetadata;
pub const StoredSignature = model.StoredSignature;
pub const ResolvedManifest = model.ResolvedManifest;
pub const BundleRevision = model.BundleRevision;
pub const InstalledBundle = model.InstalledBundle;
pub const AuthorityContext = service_authority.Context;
pub const AuthorityError = service_authority.Error;

pub const Error = bundle_ops.Error || error{
    BundleNotFound,
    BundleTableFull,
    InstallSourceDenied,
    InvalidManifestSignature,
    UntrustedManifestSigner,
    PublisherKeyRevoked,
    NoRollbackVersion,
    PermissionChangeUndeclared,
    SchemaChangeRequiresExplicitVersion,
};

pub const digestBundle = bundle_digest.digestBundle;

const BundleSlot = model.BundleSlot;
const BUNDLE_INDEX_CAPACITY: usize = MAX_INSTALLED_BUNDLES * 2;
const BundleIndex = indexed_arena.MultimapIndex(MAX_INSTALLED_BUNDLES, MAX_INSTALLED_BUNDLES, BUNDLE_INDEX_CAPACITY);
const zeroBundle = model.zeroBundle;

pub const Service = struct {
    service_id: u64 = 0,
    owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    slots: [MAX_INSTALLED_BUNDLES]BundleSlot = [_]BundleSlot{BundleSlot{}} ** MAX_INSTALLED_BUNDLES,
    bundle_index: BundleIndex = BundleIndex.init(),
    trust_store: principal.Keyring = principal.Keyring.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn bind(self: *Service, service_id: u64, owner: principal.PrincipalId) void {
        self.service_id = service_id;
        self.owner = owner;
    }

    fn trustPublisher(
        self: *Service,
        publisher_principal: principal.PrincipalId,
        issuer: principal.PrincipalId,
        publisher: []const u8,
        public_key: [32]u8,
    ) principal.KeyringError!*principal.PrincipalKeyRecord {
        return self.trust_store.bindPublisher(publisher_principal, issuer, publisher, public_key);
    }

    fn trustPolicyAuthorityRoot(
        self: *Service,
        authority: principal.PrincipalId,
        public_key: [32]u8,
    ) principal.KeyringError!*principal.PrincipalKeyRecord {
        return self.trust_store.bindPolicyAuthorityRoot(authority, public_key);
    }

    fn revokePublisher(self: *Service, publisher_principal: principal.PrincipalId) principal.KeyringError!void {
        return self.trust_store.revokePrincipal(publisher_principal);
    }

    fn install(
        self: *Service,
        request: InstallRequest,
        policy: ?*const policy_object.PolicyObject,
    ) Error!InstallResult {
        try manifest.validate(request.bundle);
        try manifest.validateApplicationPackaging(request.bundle);
        try bundle_ops.validateInstallTarget(InstalledBundle, request.bundle);
        const digest = bundle_digest.digestBundle(request.bundle);
        if (!signing.verifyWithDefaultRegistry(request.bundle.signature, &digest)) {
            return error.InvalidManifestSignature;
        }
        const trusted = self.trust_store.trustedPublisherSignature(request.bundle.publisher, request.bundle.signature);
        if (!trusted) {
            if (publisherKeyWasRevoked(&self.trust_store, request.bundle.publisher, request.bundle.signature)) {
                return error.PublisherKeyRevoked;
            }
            return error.UntrustedManifestSigner;
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
            if (permissions_changed and !request.declared_permission_change) {
                return error.PermissionChangeUndeclared;
            }
            if (schema_changed and request.bundle.version_minor == active_revision.version_minor and request.bundle.version_major == active_revision.version_major) {
                return error.SchemaChangeRequiresExplicitVersion;
            }

            try bundle_ops.installRevision(
                bundle,
                request.bundle,
                request.data_schema_version,
                permission_digest,
            );

            return .{
                .installed_new = false,
                .updated_existing = true,
                .permissions_changed = permissions_changed,
                .rollback_available = bundle.rollbackAvailable(),
            };
        }

        const slot_index = self.firstFreeSlotIndex() orelse return error.BundleTableFull;
        const slot = &self.slots[slot_index];
        slot.in_use = true;
        errdefer slot.* = .{};
        slot.bundle = zeroBundle();
        try bundle_ops.installNew(
            &slot.bundle,
            request.bundle,
            request.data_schema_version,
            permission_digest,
        );
        self.indexBundle(slot_index);
        return .{
            .installed_new = true,
            .updated_existing = false,
            .permissions_changed = false,
            .rollback_available = false,
        };
    }

    fn rollback(self: *Service, bundle_id: []const u8) Error!InstallResult {
        const bundle = self.find(bundle_id) orelse return error.BundleNotFound;
        if (!bundle.rollbackAvailable()) return error.NoRollbackVersion;
        bundle_ops.rollback(bundle);

        return .{
            .installed_new = false,
            .updated_existing = true,
            .permissions_changed = true,
            .rollback_available = bundle.rollbackAvailable(),
        };
    }

    fn remove(self: *Service, bundle_id: []const u8) Error!RemoveResult {
        const slot_index = self.findSlotIndex(bundle_id) orelse return error.BundleNotFound;
        const slot = &self.slots[slot_index];
        const removed_revision_count = slot.bundle.revision_count;
        _ = self.bundle_index.remove(bundleKey(bundle_id), slot_index);
        slot.in_use = false;
        slot.bundle = zeroBundle();
        return .{
            .removed_existing = true,
            .removed_revision_count = removed_revision_count,
        };
    }

    pub fn find(self: *Service, bundle_id: []const u8) ?*InstalledBundle {
        const slot_index = self.findSlotIndex(bundle_id) orelse return null;
        const slot = &self.slots[slot_index];
        return &slot.bundle;
    }

    pub fn rebuildIndexes(self: *Service) void {
        self.bundle_index.reset();
        for (self.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            self.indexBundle(slot_index);
        }
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
        const slot_index = self.findSlotIndexConst(bundle_id) orelse return null;
        const slot = &self.slots[slot_index];
        return &slot.bundle;
    }

    fn firstFreeSlotIndex(self: *const Service) ?usize {
        for (self.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) return slot_index;
        }
        return null;
    }

    fn findSlotIndex(self: *Service, bundle_id: []const u8) ?usize {
        return self.findSlotIndexConst(bundle_id);
    }

    fn findSlotIndexConst(self: *const Service, bundle_id: []const u8) ?usize {
        var cursor = self.bundle_index.head(bundleKey(bundle_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.bundle_index.next(cursor)) {
            if (cursor >= MAX_INSTALLED_BUNDLES) native_util.impossibleByInvariant("package bundle index points outside slots");
            const slot = &self.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("package bundle index points at a free slot");
            if (std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return cursor;
        }
        return null;
    }

    fn indexBundle(self: *Service, slot_index: usize) void {
        if (slot_index >= MAX_INSTALLED_BUNDLES) native_util.impossibleByInvariant("package bundle index update points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.bundle.bundle_id_len == 0) native_util.impossibleByInvariant("package bundle index update requires a live bundle");
        if (!self.bundle_index.append(bundleKey(slot.bundle.bundleIdSlice()), slot_index)) {
            native_util.impossibleByInvariant("package bundle index capacity covers bundle slots");
        }
    }
};

pub const PackagePort = struct {
    service: *Service,
    capability_table: *const capability.CapabilityTable,

    pub fn init(service: *Service, capability_table: *const capability.CapabilityTable) PackagePort {
        return .{
            .service = service,
            .capability_table = capability_table,
        };
    }

    pub fn trustPublisher(
        self: *PackagePort,
        authority: AuthorityContext,
        publisher_principal: principal.PrincipalId,
        issuer: principal.PrincipalId,
        publisher: []const u8,
        public_key: [32]u8,
    ) (AuthorityError || principal.KeyringError)!*principal.PrincipalKeyRecord {
        _ = try self.requirePackageAuthority(authority, .capability_mint);
        return self.service.trustPublisher(publisher_principal, issuer, publisher, public_key);
    }

    pub fn trustPolicyAuthorityRoot(
        self: *PackagePort,
        authority: AuthorityContext,
        policy_authority: principal.PrincipalId,
        public_key: [32]u8,
    ) (AuthorityError || principal.KeyringError)!*principal.PrincipalKeyRecord {
        _ = try self.requirePackageAuthority(authority, .capability_mint);
        return self.service.trustPolicyAuthorityRoot(policy_authority, public_key);
    }

    pub fn revokePublisher(
        self: *PackagePort,
        authority: AuthorityContext,
        publisher_principal: principal.PrincipalId,
    ) (AuthorityError || principal.KeyringError)!void {
        _ = try self.requirePackageAuthority(authority, .capability_revoke);
        return self.service.revokePublisher(publisher_principal);
    }

    pub fn install(
        self: *PackagePort,
        authority: AuthorityContext,
        request: InstallRequest,
        policy: ?*const policy_object.PolicyObject,
    ) (AuthorityError || Error)!InstallResult {
        _ = try self.requirePackageAuthority(authority, .endpoint_connect);
        return self.service.install(request, policy);
    }

    pub fn rollback(
        self: *PackagePort,
        authority: AuthorityContext,
        bundle_id: []const u8,
    ) (AuthorityError || Error)!InstallResult {
        _ = try self.requirePackageAuthority(authority, .endpoint_connect);
        return self.service.rollback(bundle_id);
    }

    pub fn remove(
        self: *PackagePort,
        authority: AuthorityContext,
        bundle_id: []const u8,
    ) (AuthorityError || Error)!RemoveResult {
        _ = try self.requirePackageAuthority(authority, .endpoint_connect);
        return self.service.remove(bundle_id);
    }

    fn requirePackageAuthority(
        self: *PackagePort,
        authority: AuthorityContext,
        required_right: capability.CapabilityRight,
    ) AuthorityError!*const capability.Capability {
        return service_authority.requireServiceAuthority(
            self.capability_table,
            self.service.service_id,
            authority,
            required_right,
        );
    }
};

fn publisherKeyWasRevoked(
    trust_store: *const principal.Keyring,
    publisher: []const u8,
    signature: manifest.Signature,
) bool {
    if (!signature.isComplete()) return false;
    for (&trust_store.slots) |*slot| {
        if (!slot.in_use or !slot.record.revoked) continue;
        if (slot.record.publisher_len == 0) continue;
        if (!std.mem.eql(u8, slot.record.publisherSlice(), publisher)) continue;
        if (!std.mem.eql(u8, slot.record.public_key[0..], signature.publicKeySlice())) continue;
        return true;
    }
    return false;
}

fn bundleKey(bundle_id: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0x5A47_504B_4742_554E);
    var len_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, len_bytes[0..], bundle_id.len, .little);
    hasher.update(len_bytes[0..]);
    hasher.update(bundle_id);
    return indexed_arena.nonZeroKey(hasher.final());
}

fn trustTestPublisher(
    service: *Service,
    signer_identity: signing.SignerIdentity,
    publisher: []const u8,
) !void {
    _ = try service.trustPolicyAuthorityRoot(
        .{ .kind = .policy_authority, .serial = 1 },
        [_]u8{0x51} ** 32,
    );
    _ = try service.trustPublisher(
        .{ .kind = .app, .serial = std.hash.Wyhash.hash(0x5A47_5445_5354, publisher) },
        .{ .kind = .policy_authority, .serial = 1 },
        publisher,
        try signing.publicKey(signer_identity),
    );
}

fn mintPackageServiceAuthority(
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    holder: principal.PrincipalId,
    task_id: u64,
    rights: capability.CapabilityRights,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = service_id },
        .rights = rights,
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .audit = .{},
    });
}

fn signTestReleaseBundle(identity: signing.SignerIdentity, bundle: manifest.BundleManifest) !manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        identity,
        &digestBundle(bundle),
    );
}

test "package port requires service authority before install update rollback and remove" {
    var service = Service.init();
    service.bind(740, .{ .kind = .service, .serial = 740 });
    var capabilities = capability.CapabilityTable.init();
    var port = PackagePort.init(&service, &capabilities);
    const actor = principal.PrincipalId{ .kind = .service, .serial = 741 };
    const task_id: u64 = 742;
    const signer_identity = signing.SignerIdentity{
        .label = "package-port-signer",
        .seed = [_]u8{0x5E} ** 32,
    };
    var bundle = manifest_fixtures.notesBundle();
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

    const missing_authority = AuthorityContext{
        .task_id = task_id,
        .principal = actor,
        .capability_id = 0,
        .now_ticks = 10,
    };
    try std.testing.expectError(error.CapabilityNotFound, port.install(missing_authority, .{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    const mint_only = try mintPackageServiceAuthority(&capabilities, service.service_id, actor, task_id, .{ .service = .{
        .capability_mint = true,
    } });
    const mint_authority = AuthorityContext{
        .task_id = task_id,
        .principal = actor,
        .capability_id = mint_only.id,
        .now_ticks = 10,
    };
    _ = try port.trustPolicyAuthorityRoot(mint_authority, .{ .kind = .policy_authority, .serial = 1 }, [_]u8{0x51} ** 32);
    _ = try port.trustPublisher(
        mint_authority,
        .{ .kind = .app, .serial = 741 },
        .{ .kind = .policy_authority, .serial = 1 },
        bundle.publisher,
        try signing.publicKey(signer_identity),
    );
    try std.testing.expectError(error.PermissionDenied, port.install(mint_authority, .{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    const package_authority = try mintPackageServiceAuthority(&capabilities, service.service_id, actor, task_id, .{ .service = .{
        .endpoint_connect = true,
        .capability_revoke = true,
    } });
    const install_authority = AuthorityContext{
        .task_id = task_id,
        .principal = actor,
        .capability_id = package_authority.id,
        .now_ticks = 11,
    };
    const installed = try port.install(install_authority, .{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(installed.installed_new);

    var updated_bundle = bundle;
    updated_bundle.version_minor = 1;
    updated_bundle.signature = try signTestReleaseBundle(signer_identity, updated_bundle);
    const updated = try port.install(install_authority, .{
        .bundle = updated_bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(updated.rollback_available);
    const rollback = try port.rollback(install_authority, bundle.bundle_id);
    try std.testing.expect(rollback.updated_existing);
    const removed = try port.remove(install_authority, bundle.bundle_id);
    try std.testing.expect(removed.removed_existing);
    try std.testing.expect(removed.removed_revision_count >= 1);
    try std.testing.expect(service.find(bundle.bundle_id) == null);

    const wrong_target = try mintPackageServiceAuthority(&capabilities, service.service_id + 1, actor, task_id, .{ .service = .{
        .endpoint_connect = true,
    } });
    try std.testing.expectError(error.CapabilityRequired, port.remove(.{
        .task_id = task_id,
        .principal = actor,
        .capability_id = wrong_target.id,
        .now_ticks = 12,
    }, bundle.bundle_id));
}

test "package service enforces signed manifests policy gated sources updates rollback and remove" {
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
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
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
    v1.signature = try signTestReleaseBundle(bundle_key, v1);

    var service = Service.init();
    try trustTestPublisher(&service, bundle_key, "Example Software");
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
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "relay.notes.example",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
        },
    };
    const v2_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        .{ .id = "notes-sync", .entry = "zigos.notes.sync" },
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
    v2.signature = try signTestReleaseBundle(bundle_key, v2);

    try std.testing.expectError(error.PermissionChangeUndeclared, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
    }, org_policy));

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .declared_permission_change = true,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);

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

    const removed = try service.remove("app.notes");
    try std.testing.expect(removed.removed_existing);
    try std.testing.expectEqual(@as(usize, 2), removed.removed_revision_count);
    try std.testing.expect(service.find("app.notes") == null);
    try std.testing.expectError(error.BundleNotFound, service.buildLaunchPlan("app.notes"));
    try std.testing.expectError(error.BundleNotFound, service.remove("app.notes"));
}

test "package service rejects invalid signatures and rollback before any update" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test",
        .seed = [_]u8{0x31} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object = .{ .object_read = true } },
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
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

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

test "package service rejects untrusted self-signed and revoked publisher bundles" {
    const signer_identity = signing.SignerIdentity{
        .label = "self-signed-example",
        .seed = [_]u8{0x38} ** 32,
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
    };
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = &interfaces,
        .components = &components,
        .assets = &assets,
    };
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

    var service = Service.init();
    try std.testing.expectError(error.UntrustedManifestSigner, service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null));

    const publisher_principal = principal.PrincipalId{ .kind = .app, .serial = 38 };
    _ = try service.trustPublisher(
        publisher_principal,
        .{ .kind = .policy_authority, .serial = 1 },
        "Example Software",
        try signing.publicKey(signer_identity),
    );
    try service.revokePublisher(publisher_principal);

    try std.testing.expectError(error.PublisherKeyRevoked, service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null));
}

test "package service rejects oversized manifests instead of truncating stored metadata" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-bounds",
        .seed = [_]u8{0x36} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");
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
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

    try std.testing.expectError(error.BundleIdTooLong, service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null));

    bundle.bundle_id = "app.notes";
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);
    const oversized_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = long_bundle_id[0..], .entry = "zigos.notes.ui" },
    };
    var oversized_component_bundle = bundle;
    oversized_component_bundle.components = &oversized_components;
    oversized_component_bundle.signature = try signTestReleaseBundle(signer_identity, oversized_component_bundle);
    try std.testing.expectError(error.ComponentIdTooLong, service.install(.{
        .bundle = oversized_component_bundle,
        .source_identity = "store:zigos",
    }, null));
}

test "package service treats lease and target scope changes as declared permission changes" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-lease-scope",
        .seed = [_]u8{0x34} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");
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
            .rights = .{ .object = .{ .object_read = true } },
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
    v1.signature = try signTestReleaseBundle(signer_identity, v1);

    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object = .{ .object_read = true } },
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
    v2.signature = try signTestReleaseBundle(signer_identity, v2);

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
}

test "package service requires schema changes to carry an explicit signed version" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-compat",
        .seed = [_]u8{0x35} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");
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
            .rights = .{ .object = .{ .object_read = true } },
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
    v1.signature = try signTestReleaseBundle(signer_identity, v1);
    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    var hidden_schema_change = v1;
    hidden_schema_change.signature = try signTestReleaseBundle(signer_identity, hidden_schema_change);
    try std.testing.expectError(error.SchemaChangeRequiresExplicitVersion, service.install(.{
        .bundle = hidden_schema_change,
        .source_identity = "store:zigos",
        .data_schema_version = 2,
    }, null));

    var v2 = v1;
    v2.version_minor = 1;
    v2.signature = try signTestReleaseBundle(signer_identity, v2);

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 2,
    }, null);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expectEqual(@as(u32, 2), service.find("app.notes").?.schemaVersion());
}

test "package service resolves installed manifests with stable slices" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-resolve",
        .seed = [_]u8{0x32} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");
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
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .task = .{ .background_run = true } },
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
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

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

test "package service indexes rebuild after persisted slots are loaded" {
    var service = Service.init();
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .components = &.{.{
            .id = "notes",
            .entry = "notes.main",
        }},
        .requested_permissions = &.{},
        .assets = &.{},
    };
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-rebuild",
        .seed = [_]u8{0x38} ** 32,
    };
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

    service.slots[3].in_use = true;
    try bundle_ops.installNew(&service.slots[3].bundle, bundle, 1, [_]u8{0x11} ** 32);
    service.rebuildIndexes();

    const launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 1), launch_plan.component_count);
    try std.testing.expectEqualStrings("notes.main", launch_plan.components[0].entrySlice());
}

test "package service round-trips the example writer manifest fields without widening authority" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-example-writer",
        .seed = [_]u8{0x37} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");

    var bundle = manifest_fixtures.exampleWriterBundle();
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);

    _ = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null);

    var resolved: ResolvedManifest = undefined;
    const current = try service.resolveCurrentManifest("com.example.writer", &resolved);

    try std.testing.expectEqualStrings("com.example.writer", current.bundle_id);
    try std.testing.expectEqualStrings("Writer", current.display_name);
    try std.testing.expectEqualStrings("Example Software", current.publisher);
    try std.testing.expectEqual(@as(u16, 1), current.version_major);
    try std.testing.expectEqual(@as(u16, 4), current.version_minor);
    try std.testing.expectEqual(@as(usize, 1), current.provided_interfaces.len);
    try std.testing.expectEqual(@as(usize, 2), current.consumed_interfaces.len);
    try std.testing.expectEqualStrings("writer.edit/v1", current.provided_interfaces[0].name);
    try std.testing.expectEqualStrings("documents.open/v1", current.consumed_interfaces[0].name);
    try std.testing.expectEqualStrings("export.pdf/v1", current.consumed_interfaces[1].name);
    try std.testing.expectEqual(@as(usize, 3), current.requested_permissions.len);
    try std.testing.expectEqualStrings("workspace://report-alpha", current.requested_permissions[0].resource);
    try std.testing.expectEqualStrings("sync.example.com", current.requested_permissions[1].resource);
    try std.testing.expectEqualStrings("sync-complete", current.requested_permissions[2].resource);
    try std.testing.expectEqual(@as(usize, 1), current.background_tasks.len);
    try std.testing.expectEqualStrings("sync-complete", current.background_tasks[0].id);
    try std.testing.expectEqual(@as(u32, 30), current.background_tasks[0].expected_duration_seconds);
    try std.testing.expectEqual(manifest.BackgroundNetworkMode.none, current.background_tasks[0].network);
    try std.testing.expectEqual(manifest.BackgroundVisibility.status_only, current.background_tasks[0].visibility);
    try std.testing.expectEqual(manifest.UpdateChannel.stable, current.update_channel);

    for (current.requested_permissions) |request| {
        try std.testing.expect(request.kind != .camera);
        try std.testing.expect(request.kind != .mic);
        try std.testing.expect(request.kind != .location);
    }
}

test "package service rejects example writer manifest updates that widen permissions without declaration" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-example-writer-update",
        .seed = [_]u8{0x39} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");

    var bundle = manifest_fixtures.exampleWriterBundle();
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);
    const installed = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(installed.installed_new);

    const widened_permissions = [_]manifest.PermissionRequest{
        manifest_fixtures.example_writer_permissions[0],
        manifest_fixtures.example_writer_permissions[1],
        manifest_fixtures.example_writer_permissions[2],
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{ .device_use = true } },
            .required = false,
            .local_only = true,
        },
    };
    var widened = manifest_fixtures.exampleWriterBundle();
    widened.version_minor = 5;
    widened.requested_permissions = &widened_permissions;
    widened.signature = try signTestReleaseBundle(signer_identity, widened);

    try std.testing.expectError(error.PermissionChangeUndeclared, service.install(.{
        .bundle = widened,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));
}
