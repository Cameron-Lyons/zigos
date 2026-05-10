const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const capability = @import("../kernel_api/capability.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const bundle_digest = @import("package_service_digest.zig");
const bundle_ops = @import("package_service_bundle_ops.zig");
const fixed_table = @import("../core/fixed_table.zig");
const model = @import("package_service_model.zig");
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
pub const MigrationContext = model.MigrationContext;
pub const MigrationApplier = model.MigrationApplier;
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
    MigrationManifestRequired,
    MigrationHandlerRequired,
    MigrationApplyFailed,
    InvalidMigrationManifest,
    NoRollbackVersion,
    PermissionChangeUndeclared,
};

pub const digestBundle = bundle_digest.digestBundle;

const BundleSlot = model.BundleSlot;
const zeroBundle = model.zeroBundle;

pub const Service = struct {
    service_id: u64 = 0,
    owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    slots: [MAX_INSTALLED_BUNDLES]BundleSlot = [_]BundleSlot{BundleSlot{}} ** MAX_INSTALLED_BUNDLES,
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
        try bundle_ops.validateInstallTarget(InstalledBundle, request.bundle, request.migration_manifest);
        const digest = bundle_digest.digestBundle(request.bundle);
        if (!signing.verify(request.bundle.signature, &digest)) {
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

        if (fixed_table.firstFreeSlot(BundleSlot, MAX_INSTALLED_BUNDLES, &self.slots)) |slot| {
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

    fn rollback(self: *Service, bundle_id: []const u8) Error!InstallResult {
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

    fn remove(self: *Service, bundle_id: []const u8) Error!RemoveResult {
        const slot = fixed_table.findSlot(BundleSlot, MAX_INSTALLED_BUNDLES, &self.slots, bundle_id, bundleSlotMatchesId) orelse return error.BundleNotFound;
        const removed_revision_count = slot.bundle.revision_count;
        slot.in_use = false;
        slot.bundle = zeroBundle();
        return .{
            .removed_existing = true,
            .removed_revision_count = removed_revision_count,
        };
    }

    pub fn find(self: *Service, bundle_id: []const u8) ?*InstalledBundle {
        const slot = fixed_table.findSlot(BundleSlot, MAX_INSTALLED_BUNDLES, &self.slots, bundle_id, bundleSlotMatchesId) orelse return null;
        return &slot.bundle;
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
        const slot = fixed_table.findConstSlot(BundleSlot, MAX_INSTALLED_BUNDLES, &self.slots, bundle_id, bundleSlotMatchesId) orelse return null;
        return &slot.bundle;
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

fn bundleSlotMatchesId(bundle_id: []const u8, slot: *const BundleSlot) bool {
    return std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id);
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
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

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
    updated_bundle.signature = try signing.sign(signer_identity, &digestBundle(updated_bundle));
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
    v1.signature = try signing.sign(bundle_key, &digestBundle(v1));

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
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

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

test "package service round-trips the example writer manifest fields without widening authority" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-example-writer",
        .seed = [_]u8{0x37} ** 32,
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");
    const provided_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "writer.edit/v1" },
    };
    const consumed_interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "documents.open/v1" },
        .{ .name = "export.pdf/v1" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "writer-ui", .entry = "com.example.writer.ui" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://report-alpha",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "sync.example.com",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
        },
        .{
            .kind = .background_execution,
            .resource = "sync-complete",
            .rights = .{ .task = .{ .background_run = true } },
            .required = false,
        },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync-complete",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 64 * 1024,
            },
            .network = .none,
            .visibility = .status_only,
        },
    };

    var bundle = manifest.BundleManifest{
        .bundle_id = "com.example.writer",
        .display_name = "Writer",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 4,
        .provided_interfaces = &provided_interfaces,
        .consumed_interfaces = &consumed_interfaces,
        .components = &components,
        .assets = &assets,
        .requested_permissions = &permissions,
        .background_tasks = &background_tasks,
    };
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

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

    for (current.requested_permissions) |request| {
        try std.testing.expect(request.kind != .camera);
        try std.testing.expect(request.kind != .mic);
        try std.testing.expect(request.kind != .location);
    }
}
