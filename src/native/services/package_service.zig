const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const manifest_fixtures = @import("../policy/manifest_fixtures.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const bundle_digest = @import("package_service_digest.zig");
const bundle_ops = @import("package_service_bundle_ops.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const model = @import("package_service_model.zig");
const service_authority = @import("service_authority.zig");
const signing = @import("../core/signing.zig");
const units = @import("../core/units.zig");

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
pub const MAX_INSTALL_SOURCE_BYTES = model.MAX_INSTALL_SOURCE_BYTES;
pub const InstallRequest = model.InstallRequest;
pub const InstallResult = model.InstallResult;
pub const RemoveResult = model.RemoveResult;
pub const OffboardResult = model.OffboardResult;
pub const ReleaseTransparencyEvidence = model.ReleaseTransparencyEvidence;
pub const StoredComponent = model.StoredComponent;
pub const StoredAsset = model.StoredAsset;
pub const LaunchPlan = model.LaunchPlan;
pub const PackageLaunchProvenance = model.PackageLaunchProvenance;
pub const StoredInterface = model.StoredInterface;
pub const StoredPermission = model.StoredPermission;
pub const StoredBackgroundTask = model.StoredBackgroundTask;
pub const StoredAiMetadata = model.StoredAiMetadata;
pub const StoredDataRights = model.StoredDataRights;
pub const StoredSupplyChain = model.StoredSupplyChain;
pub const StoredSignature = model.StoredSignature;
pub const StoredObjectResilience = model.StoredObjectResilience;
pub const StoredSemanticIndex = model.StoredSemanticIndex;
pub const ResolvedManifest = model.ResolvedManifest;
pub const BundleRevision = model.BundleRevision;
pub const InstalledBundle = model.InstalledBundle;
pub const AuthorityContext = service_authority.Context;
pub const AuthorityError = service_authority.Error;
pub const Digest = bundle_digest.Digest;

pub const Error = bundle_ops.Error || error{
    BundleNotFound,
    BundleTableFull,
    InstallSourceMissing,
    InstallSourceInvalid,
    InvalidDataSchemaVersion,
    InstallSourceDenied,
    InvalidManifestSignature,
    UntrustedManifestSigner,
    PublisherKeyRevoked,
    PackageProvenanceDenied,
    PolicyDenied,
    PackageActiveRevisionMismatch,
    NoRollbackVersion,
    PermissionChangeUndeclared,
    PublisherChanged,
    SchemaChangeRequiresExplicitVersion,
    SchemaVersionRegressionRejected,
    UpdateChannelChanged,
    UpdateSourceChanged,
    VersionRegressionRejected,
    VersionReplayRejected,
    StoreTransparencyMissing,
    StoreTransparencyReplayRejected,
};

pub const digestBundle = bundle_digest.digestBundle;

pub const OffboardRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    bundle_id: []const u8,
    sensitivity: manifest.DataSensitivity = .private_user_data,
    bytes: usize = 0,
    deletion_receipt_id: u64 = 0,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const RollbackRequest = struct {
    bundle_id: []const u8,
    expected_active_digest: Digest,
};

pub const RemoveRequest = struct {
    bundle_id: []const u8,
    expected_active_digest: Digest,
};

const BundleSlot = model.BundleSlot;
const BUNDLE_INDEX_CAPACITY: usize = MAX_INSTALLED_BUNDLES * 2;
const BundleArena = indexed_arena.IndexedArenaWithKey(u64, BundleSlot, MAX_INSTALLED_BUNDLES, BUNDLE_INDEX_CAPACITY, bundleSlotKey);
const zeroBundle = model.zeroBundle;

pub const Service = struct {
    service_id: u64 = 0,
    owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    slots: BundleArena = BundleArena.init(),
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
        public_key: signing.PublicKey,
    ) principal.KeyringError!*principal.PrincipalKeyRecord {
        return self.trust_store.bindPublisher(publisher_principal, issuer, publisher, public_key);
    }

    fn trustPolicyAuthorityRoot(
        self: *Service,
        authority: principal.PrincipalId,
        public_key: signing.PublicKey,
    ) principal.KeyringError!*principal.PrincipalKeyRecord {
        return self.trust_store.bindPolicyAuthorityRoot(authority, public_key);
    }

    fn revokePublisher(self: *Service, publisher_principal: principal.PrincipalId) principal.KeyringError!void {
        return self.trust_store.revokePrincipal(publisher_principal);
    }

    pub fn install(
        self: *Service,
        request: InstallRequest,
        policy: ?*const policy_object.PolicyObject,
    ) Error!InstallResult {
        try validateInstallRequestShape(request);
        try manifest.validate(request.bundle);
        try manifest.validateApplicationPackaging(request.bundle);
        try bundle_ops.validateInstallStorageShape(InstalledBundle, request.bundle);
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
            if (!active_policy.allowsPackageProvenance(.{
                .sbom_present = request.bundle.supply_chain.sbom_digest.len != 0,
                .source_archive_present = request.bundle.supply_chain.source_archive_digest.len != 0,
                .build_recipe_present = request.bundle.supply_chain.build_recipe_digest.len != 0,
                .reproducible_build = request.bundle.supply_chain.reproducible_build,
                .trusted_builder = request.bundle.supply_chain.trusted_builder,
                .vulnerability_scan_present = request.bundle.supply_chain.vulnerability_scan_digest.len != 0,
            })) return error.PackageProvenanceDenied;
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
            try validateRevisionTransition(active_revision, request.bundle, request.data_schema_version);
            if (!std.mem.eql(u8, active_revision.sourceIdentitySlice(), request.source_identity)) {
                return error.UpdateSourceChanged;
            }
            try validateTransparencyTransition(bundle, request);

            try bundle_ops.installRevisionValidated(
                bundle,
                request.bundle,
                request.source_identity,
                request.data_schema_version,
                permission_digest,
            );
            bundle.activeRevisionMut().release_transparency = request.release_transparency;

            return .{
                .installed_new = false,
                .updated_existing = true,
                .permissions_changed = permissions_changed,
                .rollback_available = bundle.rollbackAvailable(),
            };
        }

        const slot_index = self.slots.reserveIndex(bundleKey(request.bundle.bundle_id)) orelse return error.BundleTableFull;
        errdefer _ = self.slots.removeIndex(slot_index);
        const slot = &self.slots.slots[slot_index];
        slot.bundle = zeroBundle();
        try bundle_ops.installNewValidated(
            &slot.bundle,
            request.bundle,
            request.source_identity,
            request.data_schema_version,
            permission_digest,
        );
        slot.bundle.activeRevisionMut().release_transparency = request.release_transparency;
        return .{
            .installed_new = true,
            .updated_existing = false,
            .permissions_changed = false,
            .rollback_available = false,
        };
    }

    fn rollback(self: *Service, request: RollbackRequest) Error!InstallResult {
        const bundle = self.find(request.bundle_id) orelse return error.BundleNotFound;
        try requireActiveRevisionDigest(bundle, request.expected_active_digest);
        const rollback_revision = bundle.rollbackRevision() orelse return error.NoRollbackVersion;
        try self.validateRollbackRevisionTrusted(rollback_revision);
        const active_revision = bundle.activeRevision();
        const permissions_changed = !std.mem.eql(u8, &active_revision.permission_digest, &rollback_revision.permission_digest);
        bundle_ops.rollback(bundle);

        return .{
            .installed_new = false,
            .updated_existing = true,
            .permissions_changed = permissions_changed,
            .rollback_available = bundle.rollbackAvailable(),
        };
    }

    fn validateRollbackRevisionTrusted(self: *const Service, revision: *const BundleRevision) Error!void {
        return self.validateRevisionTrusted(revision);
    }

    fn validateRevisionTrusted(self: *const Service, revision: *const BundleRevision) Error!void {
        const signature = revision.signature.toManifest();
        if (!self.trust_store.trustedPublisherSignature(revision.publisherSlice(), signature)) {
            if (publisherKeyWasRevoked(&self.trust_store, revision.publisherSlice(), signature)) {
                return error.PublisherKeyRevoked;
            }
            return error.UntrustedManifestSigner;
        }
        if (publicStoreSource(revision.sourceIdentitySlice()) and !revision.release_transparency.present()) {
            return error.StoreTransparencyMissing;
        }
    }

    fn remove(self: *Service, request: RemoveRequest) Error!RemoveResult {
        const bundle = self.find(request.bundle_id) orelse return error.BundleNotFound;
        try requireActiveRevisionDigest(bundle, request.expected_active_digest);
        const removed_revision_count = bundle.revision_count;
        _ = self.slots.remove(bundleKey(request.bundle_id));
        return .{
            .removed_existing = true,
            .removed_revision_count = removed_revision_count,
        };
    }

    pub fn offboard(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: OffboardRequest,
        ledger: ?*event_ledger.Ledger,
    ) (Error || event_ledger.Error)!OffboardResult {
        const target = self.find(request.bundle_id) orelse return error.BundleNotFound;
        const expected_active_digest = activeRevisionDigest(target);
        const removed_bundle_digest = offboardRemovedBundleDigest(target);
        const decision = policies.dataRightsDecision(subjects, .{
            .operation = .delete,
            .sensitivity = request.sensitivity,
            .bytes = request.bytes,
            .deletion_receipt_present = request.deletion_receipt_id != 0,
        });
        if (!decision.allowed) {
            try recordOffboard(ledger, request, false);
            return error.PolicyDenied;
        }

        const removed = try self.remove(.{
            .bundle_id = request.bundle_id,
            .expected_active_digest = expected_active_digest,
        });
        try recordOffboard(ledger, request, true);
        return .{
            .removed_existing = removed.removed_existing,
            .removed_revision_count = removed.removed_revision_count,
            .deletion_receipt_id = request.deletion_receipt_id,
            .removed_bundle_digest = removed_bundle_digest,
        };
    }

    pub fn find(self: *Service, bundle_id: []const u8) ?*InstalledBundle {
        const slot = self.slots.get(bundleKey(bundle_id)) orelse return null;
        if (!std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return null;
        return &slot.bundle;
    }

    pub fn rebuildIndexes(self: *Service) void {
        self.slots.rebuildPrimaryIndex();
    }

    pub fn buildLaunchPlan(self: *const Service, bundle_id: []const u8) Error!LaunchPlan {
        const bundle = self.findConst(bundle_id) orelse return error.BundleNotFound;
        const active_revision = bundle.activeRevision();
        try self.validateRevisionTrusted(active_revision);
        return .{
            .components = active_revision.components[0..active_revision.component_count],
            .assets = active_revision.assets[0..active_revision.asset_count],
            .provenance = launchProvenance(bundle, active_revision),
        };
    }

    pub fn resolveCurrentManifest(
        self: *const Service,
        bundle_id: []const u8,
        resolved: *ResolvedManifest,
    ) Error!manifest.BundleManifest {
        const bundle = self.findConst(bundle_id) orelse return error.BundleNotFound;
        try self.validateRevisionTrusted(bundle.activeRevision());
        return bundle_ops.resolveActiveManifest(bundle, resolved);
    }

    fn findConst(self: *const Service, bundle_id: []const u8) ?*const InstalledBundle {
        const slot = self.slots.getConst(bundleKey(bundle_id)) orelse return null;
        if (!std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return null;
        return &slot.bundle;
    }
};

fn recordOffboard(
    ledger: ?*event_ledger.Ledger,
    request: OffboardRequest,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordDataDeletion(
            request.subject,
            request.task_id,
            request.deletion_receipt_id,
            allowed,
            request.now_ticks,
            request.detail,
            manifest.isSensitive(request.sensitivity),
        );
    }
}

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
        public_key: signing.PublicKey,
    ) (AuthorityError || principal.KeyringError)!*principal.PrincipalKeyRecord {
        _ = try self.requirePackageAuthority(authority, .capability_mint);
        return self.service.trustPublisher(publisher_principal, issuer, publisher, public_key);
    }

    pub fn trustPolicyAuthorityRoot(
        self: *PackagePort,
        authority: AuthorityContext,
        policy_authority: principal.PrincipalId,
        public_key: signing.PublicKey,
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
        request: RollbackRequest,
    ) (AuthorityError || Error)!InstallResult {
        _ = try self.requirePackageAuthority(authority, .endpoint_connect);
        return self.service.rollback(request);
    }

    pub fn remove(
        self: *PackagePort,
        authority: AuthorityContext,
        request: RemoveRequest,
    ) (AuthorityError || Error)!RemoveResult {
        _ = try self.requirePackageAuthority(authority, .endpoint_connect);
        return self.service.remove(request);
    }

    pub fn offboard(
        self: *PackagePort,
        authority: AuthorityContext,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: OffboardRequest,
        ledger: ?*event_ledger.Ledger,
    ) (AuthorityError || Error || event_ledger.Error)!OffboardResult {
        _ = try self.requirePackageAuthority(authority, .endpoint_connect);
        return self.service.offboard(policies, subjects, request, ledger);
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

fn validateInstallRequestShape(request: InstallRequest) Error!void {
    if (request.source_identity.len == 0) return error.InstallSourceMissing;
    if (request.source_identity.len > MAX_INSTALL_SOURCE_BYTES) return error.InstallSourceTooLong;
    for (request.source_identity) |byte| {
        const allowed =
            (byte >= 'a' and byte <= 'z') or
            (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or
            byte == ':' or byte == '.' or byte == '_' or byte == '-' or byte == '/';
        if (!allowed) return error.InstallSourceInvalid;
    }
    if (request.data_schema_version == 0) return error.InvalidDataSchemaVersion;
    if (publicStoreSource(request.source_identity) and !request.release_transparency.present()) {
        return error.StoreTransparencyMissing;
    }
}

fn validateRevisionTransition(
    active_revision: *const BundleRevision,
    incoming: manifest.BundleManifest,
    incoming_schema_version: u32,
) Error!void {
    if (!std.mem.eql(u8, active_revision.publisherSlice(), incoming.publisher)) {
        return error.PublisherChanged;
    }
    if (active_revision.channel != incoming.update_channel) {
        return error.UpdateChannelChanged;
    }
    if (incoming_schema_version < active_revision.schema_version) {
        return error.SchemaVersionRegressionRejected;
    }
    if (incoming.version_major < active_revision.version_major or
        (incoming.version_major == active_revision.version_major and incoming.version_minor < active_revision.version_minor))
    {
        return error.VersionRegressionRejected;
    }
    if (incoming.version_major == active_revision.version_major and incoming.version_minor == active_revision.version_minor) {
        return error.VersionReplayRejected;
    }
}

fn validateTransparencyTransition(
    installed: *const InstalledBundle,
    request: InstallRequest,
) Error!void {
    if (!publicStoreSource(request.source_identity)) return;
    var max_known_sequence: u64 = 0;
    for (installed.revisions) |revision| {
        if (revision.revision_id == 0) continue;
        max_known_sequence = @max(max_known_sequence, revision.release_transparency.sequence);
    }
    if (request.release_transparency.sequence <= max_known_sequence) return error.StoreTransparencyReplayRejected;
}

fn launchProvenance(
    bundle: *const InstalledBundle,
    revision: *const BundleRevision,
) PackageLaunchProvenance {
    const signature = revision.signature.toManifest();
    return .{
        .bundle_id = bundle.bundleIdSlice(),
        .display_name = revision.displayNameSlice(),
        .publisher = revision.publisherSlice(),
        .source_identity = revision.sourceIdentitySlice(),
        .version_major = revision.version_major,
        .version_minor = revision.version_minor,
        .update_channel = revision.channel,
        .data_schema_version = revision.schema_version,
        .permission_digest = revision.permission_digest,
        .signature_format = signature.format,
        .signature_signer = signature.signer,
        .signature_public_key_len = signature.public_key_len,
        .signed = signature.isComplete(),
        .release_transparency = revision.release_transparency,
    };
}

pub fn activeRevisionDigest(bundle: *const InstalledBundle) Digest {
    return installedBundleRevisionDigest(bundle, "zigos.package.active-revision");
}

pub fn rollbackRequestForActive(bundle: *const InstalledBundle) RollbackRequest {
    return .{
        .bundle_id = bundle.bundleIdSlice(),
        .expected_active_digest = activeRevisionDigest(bundle),
    };
}

pub fn removeRequestForActive(bundle: *const InstalledBundle) RemoveRequest {
    return .{
        .bundle_id = bundle.bundleIdSlice(),
        .expected_active_digest = activeRevisionDigest(bundle),
    };
}

pub fn offboardRemovedBundleDigest(bundle: *const InstalledBundle) Digest {
    return installedBundleRevisionDigest(bundle, "zigos.package.offboard.removed-bundle");
}

fn installedBundleRevisionDigest(bundle: *const InstalledBundle, schema: []const u8) Digest {
    const revision = bundle.activeRevision();
    const signature = revision.signature.toManifest();
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "schema", schema);
    crypto_hash.updateBytes(&hasher, "bundle-id", bundle.bundleIdSlice());
    crypto_hash.updateInt(&hasher, "revision-id", revision.revision_id);
    crypto_hash.updateBytes(&hasher, "display-name", revision.displayNameSlice());
    crypto_hash.updateBytes(&hasher, "publisher", revision.publisherSlice());
    crypto_hash.updateBytes(&hasher, "source-identity", revision.sourceIdentitySlice());
    crypto_hash.updateInt(&hasher, "version-major", revision.version_major);
    crypto_hash.updateInt(&hasher, "version-minor", revision.version_minor);
    crypto_hash.updateEnum(&hasher, "update-channel", revision.channel);
    crypto_hash.updateInt(&hasher, "schema-version", revision.schema_version);
    crypto_hash.updateBytes(&hasher, "permission-digest", &revision.permission_digest);
    crypto_hash.updateInt(&hasher, "release-transparency-sequence", revision.release_transparency.sequence);
    crypto_hash.updateBytes(&hasher, "release-transparency-root", &revision.release_transparency.root);
    crypto_hash.updateBytes(&hasher, "release-transparency-log-head", &revision.release_transparency.log_head);
    crypto_hash.updateBytes(&hasher, "signature-format", signature.format);
    crypto_hash.updateBytes(&hasher, "signature-signer", signature.signer);
    crypto_hash.updateInt(&hasher, "signature-public-key-len", signature.public_key_len);
    crypto_hash.updateBytes(&hasher, "signature-public-key", signature.publicKeySlice());
    crypto_hash.updateInt(&hasher, "signature-value-len", signature.value_len);
    crypto_hash.updateBytes(&hasher, "signature-value", signature.valueSlice());
    crypto_hash.updateInt(&hasher, "component-count", revision.component_count);
    for (revision.components[0..revision.component_count], 0..) |component, index| {
        crypto_hash.updateInt(&hasher, "component-index", index);
        crypto_hash.updateBytes(&hasher, "component-id", component.idSlice());
        crypto_hash.updateBytes(&hasher, "component-entry", component.entrySlice());
        crypto_hash.updateEnum(&hasher, "component-abi", component.abi);
    }
    crypto_hash.updateInt(&hasher, "asset-count", revision.asset_count);
    for (revision.assets[0..revision.asset_count], 0..) |asset, index| {
        crypto_hash.updateInt(&hasher, "asset-index", index);
        crypto_hash.updateBytes(&hasher, "asset-path", asset.pathSlice());
        crypto_hash.updateBytes(&hasher, "asset-content-type", asset.contentTypeSlice());
    }
    crypto_hash.updateInt(&hasher, "provided-interface-count", revision.provided_interface_count);
    for (revision.provided_interfaces[0..revision.provided_interface_count], 0..) |interface, index| {
        crypto_hash.updateInt(&hasher, "provided-interface-index", index);
        crypto_hash.updateBytes(&hasher, "provided-interface-name", interface.nameSlice());
        crypto_hash.updateInt(&hasher, "provided-interface-major", interface.version_major);
        crypto_hash.updateInt(&hasher, "provided-interface-minor", interface.version_minor);
    }
    crypto_hash.updateInt(&hasher, "consumed-interface-count", revision.consumed_interface_count);
    for (revision.consumed_interfaces[0..revision.consumed_interface_count], 0..) |interface, index| {
        crypto_hash.updateInt(&hasher, "consumed-interface-index", index);
        crypto_hash.updateBytes(&hasher, "consumed-interface-name", interface.nameSlice());
        crypto_hash.updateInt(&hasher, "consumed-interface-major", interface.version_major);
        crypto_hash.updateInt(&hasher, "consumed-interface-minor", interface.version_minor);
    }
    crypto_hash.updateInt(&hasher, "requested-permission-count", revision.requested_permission_count);
    for (revision.requested_permissions[0..revision.requested_permission_count], 0..) |permission, index| {
        crypto_hash.updateInt(&hasher, "permission-index", index);
        crypto_hash.updateEnum(&hasher, "permission-kind", permission.kind);
        crypto_hash.updateBytes(&hasher, "permission-resource", permission.resourceSlice());
        crypto_hash.updateEnum(&hasher, "permission-rights-target", std.meta.activeTag(permission.rights));
        crypto_hash.updateInt(&hasher, "permission-rights-bits", permission.rights.toBits());
        crypto_hash.updateBool(&hasher, "permission-required", permission.required);
        crypto_hash.updateBool(&hasher, "permission-local-only", permission.local_only);
        crypto_hash.updateInt(&hasher, "permission-max-lease-ticks", permission.max_lease_ticks);
        crypto_hash.updateInt(&hasher, "permission-target-id", permission.target_id);
        crypto_hash.updateEnum(&hasher, "permission-egress-intent-kind", permission.egress_intent_kind);
        crypto_hash.updateEnum(&hasher, "permission-sensitivity", permission.sensitivity);
        crypto_hash.updateEnum(&hasher, "permission-purpose", permission.purpose);
        crypto_hash.updateInt(&hasher, "permission-retention-days", permission.retention_days);
        crypto_hash.updateBytes(&hasher, "permission-user-visible-reason", permission.userVisibleReasonSlice());
        crypto_hash.updateBytes(&hasher, "permission-egress-object", permission.egressObjectSlice());
        crypto_hash.updateBytes(&hasher, "permission-egress-principal", permission.egressPrincipalSlice());
        crypto_hash.updateBytes(&hasher, "permission-egress-service", permission.egressServiceSlice());
        crypto_hash.updateBytes(&hasher, "permission-egress-event-type", permission.egressEventTypeSlice());
    }
    crypto_hash.updateInt(&hasher, "background-task-count", revision.background_task_count);
    for (revision.background_tasks[0..revision.background_task_count], 0..) |task, index| {
        crypto_hash.updateInt(&hasher, "background-task-index", index);
        crypto_hash.updateBytes(&hasher, "background-task-id", task.idSlice());
        crypto_hash.updateEnum(&hasher, "background-task-trigger", task.trigger);
        crypto_hash.updateInt(&hasher, "background-task-duration", task.expected_duration_seconds);
        crypto_hash.updateInt(&hasher, "background-task-cpu", task.budget.cpu_time_ticks);
        crypto_hash.updateInt(&hasher, "background-task-memory", task.budget.memory_bytes);
        crypto_hash.updateInt(&hasher, "background-task-shared-memory", task.budget.shared_memory_bytes);
        crypto_hash.updateEnum(&hasher, "background-task-network", task.network);
        crypto_hash.updateEnum(&hasher, "background-task-visibility", task.visibility);
    }
    crypto_hash.updateBytes(&hasher, "ai-model-family", revision.ai_metadata.modelFamilySlice());
    crypto_hash.updateBytes(&hasher, "ai-model-digest", revision.ai_metadata.modelDigestSlice());
    crypto_hash.updateBytes(&hasher, "ai-model-source-identity", revision.ai_metadata.modelSourceIdentitySlice());
    crypto_hash.updateEnum(&hasher, "ai-locality", revision.ai_metadata.locality);
    crypto_hash.updateBool(&hasher, "ai-offline-required", revision.ai_metadata.offline_required);
    crypto_hash.updateBool(&hasher, "ai-private-context", revision.ai_metadata.private_context);
    crypto_hash.updateBool(&hasher, "ai-training-allowed", revision.ai_metadata.training_allowed);
    crypto_hash.updateInt(&hasher, "ai-max-context-bytes", revision.ai_metadata.max_context_bytes);
    crypto_hash.updateBool(&hasher, "ai-audit-prompt-use", revision.ai_metadata.audit_prompt_use);
    crypto_hash.updateBool(&hasher, "data-rights-user-data-present", revision.data_rights.user_data_present);
    crypto_hash.updateBool(&hasher, "data-rights-portable-export", revision.data_rights.portable_export);
    crypto_hash.updateBool(&hasher, "data-rights-deletion-supported", revision.data_rights.deletion_supported);
    crypto_hash.updateBool(&hasher, "data-rights-deletion-receipt-required", revision.data_rights.deletion_receipt_required);
    crypto_hash.updateBytes(&hasher, "data-rights-export-format", revision.data_rights.exportFormatSlice());
    crypto_hash.updateBytes(&hasher, "supply-chain-sbom-digest", revision.supply_chain.sbomDigestSlice());
    crypto_hash.updateBytes(&hasher, "supply-chain-source-archive-digest", revision.supply_chain.sourceArchiveDigestSlice());
    crypto_hash.updateBytes(&hasher, "supply-chain-build-recipe-digest", revision.supply_chain.buildRecipeDigestSlice());
    crypto_hash.updateBytes(&hasher, "supply-chain-vulnerability-scan-digest", revision.supply_chain.vulnerabilityScanDigestSlice());
    crypto_hash.updateBytes(&hasher, "supply-chain-build-provenance", revision.supply_chain.buildProvenanceIdentitySlice());
    crypto_hash.updateBool(&hasher, "supply-chain-reproducible-build", revision.supply_chain.reproducible_build);
    crypto_hash.updateBool(&hasher, "supply-chain-trusted-builder", revision.supply_chain.trusted_builder);
    crypto_hash.updateBool(&hasher, "agent-enabled", revision.agent_delegation.enabled);
    crypto_hash.updateBytes(&hasher, "agent-purpose", revision.agent_delegation.purposeSlice());
    crypto_hash.updateInt(&hasher, "agent-max-actions", revision.agent_delegation.max_autonomous_actions);
    crypto_hash.updateInt(&hasher, "agent-max-remote-calls", revision.agent_delegation.max_remote_calls);
    crypto_hash.updateBool(&hasher, "agent-user-confirmation", revision.agent_delegation.user_confirmation_required);
    crypto_hash.updateBool(&hasher, "agent-audit-required", revision.agent_delegation.audit_required);
    crypto_hash.updateBool(&hasher, "agent-session-bound", revision.agent_delegation.session_bound);
    crypto_hash.updateBool(&hasher, "agent-local-context-only", revision.agent_delegation.local_context_only);
    crypto_hash.updateInt(&hasher, "agent-max-context-bytes", revision.agent_delegation.max_context_bytes);
    crypto_hash.updateBool(&hasher, "agent-kill-switch", revision.agent_delegation.kill_switch_supported);
    crypto_hash.updateBool(&hasher, "accessibility-adaptive-ui", revision.accessibility.adaptive_ui);
    crypto_hash.updateBool(&hasher, "accessibility-screen-reader", revision.accessibility.supports_screen_reader);
    crypto_hash.updateBool(&hasher, "accessibility-keyboard-navigation", revision.accessibility.supports_keyboard_navigation);
    crypto_hash.updateBool(&hasher, "accessibility-reduced-motion", revision.accessibility.supports_reduced_motion);
    crypto_hash.updateBool(&hasher, "accessibility-high-contrast", revision.accessibility.supports_high_contrast);
    crypto_hash.updateBytes(&hasher, "accessibility-profile-notes", revision.accessibility.profileNotesSlice());
    crypto_hash.updateBool(&hasher, "object-resilience-backup-enabled", revision.object_resilience.backup_enabled);
    crypto_hash.updateBool(&hasher, "object-resilience-encrypted-snapshots", revision.object_resilience.encrypted_snapshots);
    crypto_hash.updateBool(&hasher, "object-resilience-recovery-key-required", revision.object_resilience.recovery_key_required);
    crypto_hash.updateBool(&hasher, "object-resilience-portable-restore", revision.object_resilience.portable_restore);
    crypto_hash.updateBool(&hasher, "object-resilience-device-trust-required", revision.object_resilience.device_trust_required);
    crypto_hash.updateInt(&hasher, "object-resilience-max-restore-age-days", revision.object_resilience.max_restore_age_days);
    crypto_hash.updateBytes(&hasher, "object-resilience-backup-format", revision.object_resilience.backupFormatSlice());
    crypto_hash.updateBool(&hasher, "semantic-index-enabled", revision.semantic_index.enabled);
    crypto_hash.updateBool(&hasher, "semantic-index-local-only", revision.semantic_index.local_only);
    crypto_hash.updateBool(&hasher, "semantic-index-encrypted-index", revision.semantic_index.encrypted_index);
    crypto_hash.updateBool(&hasher, "semantic-index-redacted-snippets", revision.semantic_index.redacted_snippets);
    crypto_hash.updateInt(&hasher, "semantic-index-max-query-bytes", revision.semantic_index.max_query_bytes);
    crypto_hash.updateBytes(&hasher, "semantic-index-model-digest", revision.semantic_index.modelDigestSlice());
    return crypto_hash.finalize(&hasher);
}

fn requireActiveRevisionDigest(bundle: *const InstalledBundle, expected: Digest) Error!void {
    const actual = activeRevisionDigest(bundle);
    if (!std.mem.eql(u8, &actual, &expected)) return error.PackageActiveRevisionMismatch;
}

fn publicStoreSource(source_identity: []const u8) bool {
    return std.mem.startsWith(u8, source_identity, "store:zigos/public");
}

fn publisherKeyWasRevoked(
    trust_store: *const principal.Keyring,
    publisher: []const u8,
    signature: manifest.Signature,
) bool {
    return trust_store.revokedPublisherSignature(publisher, signature);
}

fn bundleKey(bundle_id: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(hash_seeds.package_bundle_key);
    var len_bytes: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &len_bytes, bundle_id.len, .little);
    hasher.update(&len_bytes);
    hasher.update(bundle_id);
    return indexed_arena.nonZeroKey(hasher.final());
}

fn bundleSlotKey(slot: *const BundleSlot) u64 {
    return bundleKey(slot.bundle.bundleIdSlice());
}

fn trustTestPublisher(
    service: *Service,
    signer_identity: signing.SignerIdentity,
    publisher: []const u8,
) !void {
    _ = try service.trustPolicyAuthorityRoot(
        .{ .kind = .policy_authority, .serial = 1 },
        signing.publicKeyFromByte(0x51),
    );
    _ = try service.trustPublisher(
        .{ .kind = .app, .serial = std.hash.Wyhash.hash(hash_seeds.package_test_publisher, publisher) },
        .{ .kind = .policy_authority, .serial = 1 },
        publisher,
        try signing.publicKey(signer_identity),
    );
}

pub fn testingTrustPublisher(
    service: *Service,
    signer_identity: signing.SignerIdentity,
    publisher: []const u8,
) !void {
    return trustTestPublisher(service, signer_identity, publisher);
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

fn publicStoreTransparency(sequence: u64, root_byte: u8, log_head_byte: u8) ReleaseTransparencyEvidence {
    return .{
        .sequence = sequence,
        .root = crypto_hash.digestFromByte(root_byte),
        .log_head = crypto_hash.digestFromByte(log_head_byte),
    };
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
        .seed = signing.seedFromByte(0x5E),
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
    _ = try port.trustPolicyAuthorityRoot(mint_authority, .{ .kind = .policy_authority, .serial = 1 }, signing.publicKeyFromByte(0x51));
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
    const stale_rollback_request = rollbackRequestForActive(service.find(bundle.bundle_id).?);

    var updated_bundle = bundle;
    updated_bundle.version_minor = 1;
    updated_bundle.signature = try signTestReleaseBundle(signer_identity, updated_bundle);
    const updated = try port.install(install_authority, .{
        .bundle = updated_bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(updated.rollback_available);
    const stale_remove_request = removeRequestForActive(service.find(bundle.bundle_id).?);
    try std.testing.expectError(error.PackageActiveRevisionMismatch, port.rollback(install_authority, stale_rollback_request));
    const rollback = try port.rollback(install_authority, rollbackRequestForActive(service.find(bundle.bundle_id).?));
    try std.testing.expect(rollback.updated_existing);
    try std.testing.expectError(error.PackageActiveRevisionMismatch, port.remove(install_authority, stale_remove_request));
    const removed = try port.remove(install_authority, removeRequestForActive(service.find(bundle.bundle_id).?));
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
    }, .{
        .bundle_id = bundle.bundle_id,
        .expected_active_digest = crypto_hash.zero_digest,
    }));
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
        .seed = signing.seedFromByte(0x22),
    });

    const bundle_key = signing.SignerIdentity{
        .label = "bundle-key",
        .seed = signing.seedFromByte(0x23),
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
            .sensitivity = .private_user_data,
            .user_visible_reason = "Sync notes through the user's chosen relay",
            .purpose = .document_editing,
            .retention_days = 30,
            .egress_intent = .{
                .kind = .call_service,
                .service = "notes.relay.sync",
            },
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
        .data_rights = .{
            .user_data_present = true,
            .portable_export = true,
            .deletion_supported = true,
            .deletion_receipt_required = true,
            .export_format = "application/zigos-object-archive",
        },
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
        .source_identity = "store:zigos",
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
    try std.testing.expectEqualStrings("store:zigos", installed.sourceIdentitySlice());
    try std.testing.expectEqual(@as(usize, 2), installed.componentCount());
    try std.testing.expectEqualStrings("zigos.notes.sync", installed.componentAt(1).entrySlice());
    var resolved: ResolvedManifest = undefined;
    const resolved_v2 = try service.resolveCurrentManifest("app.notes", &resolved);
    try std.testing.expectEqual(manifest.DataSensitivity.private_user_data, resolved_v2.requested_permissions[1].sensitivity);
    try std.testing.expectEqual(manifest.PermissionPurpose.document_editing, resolved_v2.requested_permissions[1].purpose);
    try std.testing.expectEqual(@as(u16, 30), resolved_v2.requested_permissions[1].retention_days);
    try std.testing.expectEqualStrings("Sync notes through the user's chosen relay", resolved_v2.requested_permissions[1].user_visible_reason);
    try std.testing.expectEqual(manifest.DataEgressIntentKind.call_service, resolved_v2.requested_permissions[1].egress_intent.kind);
    try std.testing.expectEqualStrings("notes.relay.sync", resolved_v2.requested_permissions[1].egress_intent.service);
    try std.testing.expect(resolved_v2.data_rights.user_data_present);
    try std.testing.expect(resolved_v2.data_rights.portable_export);
    try std.testing.expect(resolved_v2.data_rights.deletion_supported);
    try std.testing.expect(resolved_v2.data_rights.deletion_receipt_required);
    try std.testing.expectEqualStrings("application/zigos-object-archive", resolved_v2.data_rights.export_format);

    const launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 2), launch_plan.components.len);
    try std.testing.expectEqual(@as(usize, 2), launch_plan.assets.len);
    try std.testing.expectEqualStrings("notes-ui", launch_plan.components[0].idSlice());
    try std.testing.expectEqualStrings("assets/editor.css", launch_plan.assets[1].pathSlice());
    try std.testing.expectEqualStrings("app.notes", launch_plan.provenance.bundle_id);
    try std.testing.expectEqualStrings("Example Software", launch_plan.provenance.publisher);
    try std.testing.expectEqualStrings("store:zigos", launch_plan.provenance.source_identity);
    try std.testing.expectEqual(@as(u16, 1), launch_plan.provenance.version_major);
    try std.testing.expectEqual(@as(u16, 1), launch_plan.provenance.version_minor);
    try std.testing.expectEqual(@as(u32, 2), launch_plan.provenance.data_schema_version);
    try std.testing.expect(launch_plan.provenance.signed);
    try std.testing.expectEqualStrings(manifest.SIGNATURE_FORMAT_ED25519, launch_plan.provenance.signature_format);
    try std.testing.expectEqual(@as(usize, signing.PUBLIC_KEY_BYTES), launch_plan.provenance.signature_public_key_len);

    _ = try service.rollback(rollbackRequestForActive(service.find("app.notes").?));
    const rolled_back = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), rolled_back.versionMajor());
    try std.testing.expectEqual(@as(u16, 0), rolled_back.versionMinor());
    try std.testing.expectEqual(@as(u32, 1), rolled_back.schemaVersion());
    try std.testing.expectEqualStrings("store:zigos", rolled_back.sourceIdentitySlice());
    try std.testing.expectEqual(@as(usize, 1), rolled_back.componentCount());
    const resolved_v1 = try service.resolveCurrentManifest("app.notes", &resolved);
    try std.testing.expectEqual(@as(usize, 1), resolved_v1.components.len);
    try std.testing.expectEqual(@as(usize, 1), resolved_v1.assets.len);
    try std.testing.expectEqual(@as(usize, 1), resolved_v1.requested_permissions.len);
    try std.testing.expectEqualStrings("notes-ui", resolved_v1.components[0].id);
    try std.testing.expectEqualStrings("assets/icon.svg", resolved_v1.assets[0].path);

    const removed = try service.remove(removeRequestForActive(service.find("app.notes").?));
    try std.testing.expect(removed.removed_existing);
    try std.testing.expectEqual(@as(usize, 2), removed.removed_revision_count);
    try std.testing.expect(service.find("app.notes") == null);
    try std.testing.expectError(error.BundleNotFound, service.buildLaunchPlan("app.notes"));
    try std.testing.expectError(error.BundleNotFound, service.remove(.{
        .bundle_id = "app.notes",
        .expected_active_digest = crypto_hash.zero_digest,
    }));
}

test "package service offboarding requires deletion receipt removes bundle and redacts audit" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-offboard",
        .seed = signing.seedFromByte(0x39),
    };
    try trustTestPublisher(&service, signer_identity, "zigos.dev");
    var bundle = manifest_fixtures.notesBundle();
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);
    const installed = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(installed.installed_new);

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 840 };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 840 },
        .label = "offboarding-policy",
        .data_deletion_allowed = true,
        .require_data_deletion_receipt = true,
    }, signing.SignerIdentity{
        .label = "offboard-policy-key",
        .seed = signing.seedFromByte(0x94),
    });
    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var ledger = event_ledger.Ledger.init();

    try std.testing.expectError(error.PolicyDenied, service.offboard(&policies, subjects, .{
        .subject = user,
        .task_id = 404,
        .bundle_id = "app.notes",
        .sensitivity = .private_user_data,
        .bytes = units.kibibytes(64),
        .now_ticks = 50,
        .detail = "private app offboarding denied detail",
    }, &ledger));
    try std.testing.expect(service.find("app.notes") != null);
    const expected_removed_digest = offboardRemovedBundleDigest(service.find("app.notes").?);
    var altered_bundle = service.find("app.notes").?.*;
    const altered_revision = altered_bundle.activeRevisionMut();
    if (altered_revision.component_count != 0 and altered_revision.components[0].entry_len != 0) {
        altered_revision.components[0].entry[0] +%= 1;
    } else {
        altered_revision.data_rights.deletion_supported = !altered_revision.data_rights.deletion_supported;
    }
    const altered_digest = offboardRemovedBundleDigest(&altered_bundle);
    try std.testing.expect(!std.mem.eql(u8, &expected_removed_digest, &altered_digest));

    const offboarded = try service.offboard(&policies, subjects, .{
        .subject = user,
        .task_id = 404,
        .bundle_id = "app.notes",
        .sensitivity = .private_user_data,
        .bytes = units.kibibytes(64),
        .deletion_receipt_id = 7001,
        .now_ticks = 51,
        .detail = "private app offboarding receipt detail",
    }, &ledger);
    try std.testing.expect(offboarded.removed_existing);
    try std.testing.expectEqual(@as(u64, 7001), offboarded.deletion_receipt_id);
    try std.testing.expect(!std.mem.eql(u8, &offboarded.removed_bundle_digest, &crypto_hash.zero_digest));
    try std.testing.expectEqualSlices(u8, &expected_removed_digest, &offboarded.removed_bundle_digest);
    try std.testing.expect(service.find("app.notes") == null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.data_deletion_events);
    try std.testing.expectEqual(@as(usize, 1), summary.data_deletion_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.data_deletion_receipts);
    try std.testing.expect(summary.protected_details_redacted >= 2);

    var buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private app offboarding") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=data_deletion") != null);
}

test "package service rejects invalid signatures and rollback before any update" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test",
        .seed = signing.seedFromByte(0x31),
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
    try std.testing.expectError(error.NoRollbackVersion, service.rollback(rollbackRequestForActive(service.find("app.notes").?)));
}

test "package revision identifiers issue the maximum once and stop before mutation" {
    var bundle = zeroBundle();
    const v1 = manifest_fixtures.notesBundle();
    const permission_digest = bundle_digest.permissionDigest(v1.requested_permissions);
    try bundle_ops.installNewValidated(
        &bundle,
        v1,
        "store:zigos",
        1,
        permission_digest,
    );

    try std.testing.expectEqual(@as(u64, 1), bundle.activeRevision().revision_id);
    bundle.next_revision_id = std.math.maxInt(u64);

    var v2 = v1;
    v2.version_minor = 1;
    try bundle_ops.installRevisionValidated(
        &bundle,
        v2,
        "store:zigos",
        1,
        permission_digest,
    );

    try std.testing.expectEqual(std.math.maxInt(u64), bundle.activeRevision().revision_id);
    try std.testing.expectEqual(@as(u64, 1), bundle.rollbackRevision().?.revision_id);
    try std.testing.expectEqual(@as(u64, 0), bundle.next_revision_id);

    const exhausted = bundle;
    var v3 = v2;
    v3.version_minor = 2;
    try std.testing.expectError(error.RevisionIdExhausted, bundle_ops.installRevisionValidated(
        &bundle,
        v3,
        "store:zigos",
        1,
        permission_digest,
    ));
    try std.testing.expectEqualDeep(exhausted, bundle);
}

test "package service rejects stale update metadata publisher drift and channel drift" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-update-freshness",
        .seed = signing.seedFromByte(0x3A),
    };
    const other_signer_identity = signing.SignerIdentity{
        .label = "pkg-test-other-publisher",
        .seed = signing.seedFromByte(0x3B),
    };
    try trustTestPublisher(&service, signer_identity, "zigos.dev");
    try trustTestPublisher(&service, other_signer_identity, "Other Software");

    var v1 = manifest_fixtures.notesBundle();
    v1.signature = try signTestReleaseBundle(signer_identity, v1);

    try std.testing.expectError(error.InstallSourceMissing, service.install(.{
        .bundle = v1,
        .source_identity = "",
        .data_schema_version = 1,
    }, null));
    try std.testing.expectError(error.InvalidDataSchemaVersion, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 0,
    }, null));
    const oversized_source = [_]u8{'s'} ** (MAX_INSTALL_SOURCE_BYTES + 1);
    try std.testing.expectError(error.InstallSourceTooLong, service.install(.{
        .bundle = v1,
        .source_identity = oversized_source[0..],
        .data_schema_version = 1,
    }, null));
    try std.testing.expectError(error.InstallSourceInvalid, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos beta",
        .data_schema_version = 1,
    }, null));
    try std.testing.expectError(error.InstallSourceInvalid, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos\nmirror",
        .data_schema_version = 1,
    }, null));

    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    try std.testing.expectError(error.VersionReplayRejected, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    try std.testing.expectError(error.SchemaChangeRequiresExplicitVersion, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 2,
    }, null));

    const widened_permissions = [_]manifest.PermissionRequest{
        manifest_fixtures.notes_permissions[0],
        manifest_fixtures.notes_permissions[1],
        .{
            .kind = .notification_post,
            .resource = "notifications://notes",
            .rights = .{ .task = .{ .notification_post = true } },
            .required = false,
        },
    };
    var same_version_permission_change = v1;
    same_version_permission_change.requested_permissions = &widened_permissions;
    same_version_permission_change.signature = try signTestReleaseBundle(signer_identity, same_version_permission_change);
    try std.testing.expectError(error.VersionReplayRejected, service.install(.{
        .bundle = same_version_permission_change,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
        .declared_permission_change = true,
    }, null));

    var other_publisher = v1;
    other_publisher.publisher = "Other Software";
    other_publisher.version_minor = 1;
    other_publisher.signature = try signTestReleaseBundle(other_signer_identity, other_publisher);
    try std.testing.expectError(error.PublisherChanged, service.install(.{
        .bundle = other_publisher,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    var channel_changed = v1;
    channel_changed.update_channel = .stable;
    channel_changed.version_minor = 1;
    channel_changed.signature = try signTestReleaseBundle(signer_identity, channel_changed);
    try std.testing.expectError(error.UpdateChannelChanged, service.install(.{
        .bundle = channel_changed,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    var v11 = v1;
    v11.version_minor = 1;
    v11.signature = try signTestReleaseBundle(signer_identity, v11);
    try std.testing.expectError(error.UpdateSourceChanged, service.install(.{
        .bundle = v11,
        .source_identity = "repo:mirror",
        .data_schema_version = 1,
    }, null));
    const updated_minor = try service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(updated_minor.updated_existing);
    try std.testing.expect(updated_minor.rollback_available);

    try std.testing.expectError(error.VersionReplayRejected, service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));
    try std.testing.expectError(error.VersionRegressionRejected, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    var v20 = v1;
    v20.version_major = 2;
    v20.version_minor = 0;
    v20.signature = try signTestReleaseBundle(signer_identity, v20);
    const updated_major = try service.install(.{
        .bundle = v20,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);
    try std.testing.expect(updated_major.updated_existing);
    try std.testing.expectEqual(@as(u16, 2), service.find("app.notes").?.versionMajor());

    var lower_major = v1;
    lower_major.version_minor = 9;
    lower_major.signature = try signTestReleaseBundle(signer_identity, lower_major);
    try std.testing.expectError(error.VersionRegressionRejected, service.install(.{
        .bundle = lower_major,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    const rollback = try service.rollback(rollbackRequestForActive(service.find("app.notes").?));
    try std.testing.expect(!rollback.permissions_changed);
    try std.testing.expectEqual(@as(u16, 1), service.find("app.notes").?.versionMajor());
    try std.testing.expectEqual(@as(u16, 1), service.find("app.notes").?.versionMinor());
    try std.testing.expectError(error.VersionReplayRejected, service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));
}

test "package service preserves and advances public store transparency evidence" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-public-store-transparency",
        .seed = signing.seedFromByte(0x3D),
    };
    try trustTestPublisher(&service, signer_identity, "zigos.dev");

    var v1 = manifest_fixtures.notesBundle();
    v1.signature = try signTestReleaseBundle(signer_identity, v1);

    try std.testing.expectError(error.StoreTransparencyMissing, service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
    }, null));

    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(1, 0x61, 0x61),
    }, null);
    try std.testing.expectEqual(
        @as(u64, 1),
        service.find("app.notes").?.activeRevision().release_transparency.sequence,
    );

    var v11 = v1;
    v11.version_minor = 1;
    v11.signature = try signTestReleaseBundle(signer_identity, v11);
    try std.testing.expectError(error.StoreTransparencyReplayRejected, service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(1, 0x61, 0x61),
    }, null));

    _ = try service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(2, 0x62, 0x62),
    }, null);
    try std.testing.expectEqual(
        @as(u64, 2),
        service.find("app.notes").?.activeRevision().release_transparency.sequence,
    );
    const v11_launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqualStrings("store:zigos/public", v11_launch_plan.provenance.source_identity);
    try std.testing.expectEqual(@as(u64, 2), v11_launch_plan.provenance.release_transparency.sequence);

    _ = try service.rollback(rollbackRequestForActive(service.find("app.notes").?));
    try std.testing.expectEqual(
        @as(u64, 1),
        service.find("app.notes").?.activeRevision().release_transparency.sequence,
    );
    const rollback_launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(u64, 1), rollback_launch_plan.provenance.release_transparency.sequence);

    var v20 = v1;
    v20.version_major = 2;
    v20.version_minor = 0;
    v20.signature = try signTestReleaseBundle(signer_identity, v20);
    try std.testing.expectError(error.StoreTransparencyReplayRejected, service.install(.{
        .bundle = v20,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(2, 0x62, 0x62),
    }, null));

    const updated = try service.install(.{
        .bundle = v20,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(3, 0x63, 0x63),
    }, null);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expectEqual(
        @as(u64, 3),
        service.find("app.notes").?.activeRevision().release_transparency.sequence,
    );
}

test "package service refuses runtime use of public store revisions with stripped transparency" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-public-store-runtime-transparency",
        .seed = signing.seedFromByte(0x3E),
    };
    try trustTestPublisher(&service, signer_identity, "zigos.dev");

    var v1 = manifest_fixtures.notesBundle();
    v1.signature = try signTestReleaseBundle(signer_identity, v1);
    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(1, 0x71, 0x71),
    }, null);

    var resolved: ResolvedManifest = undefined;
    _ = try service.buildLaunchPlan("app.notes");
    _ = try service.resolveCurrentManifest("app.notes", &resolved);

    const bundle = service.find("app.notes").?;
    const saved_active_transparency = bundle.activeRevision().release_transparency;
    bundle.activeRevisionMut().release_transparency = .{};
    try std.testing.expectError(error.StoreTransparencyMissing, service.buildLaunchPlan("app.notes"));
    try std.testing.expectError(error.StoreTransparencyMissing, service.resolveCurrentManifest("app.notes", &resolved));
    bundle.activeRevisionMut().release_transparency = saved_active_transparency;

    var v11 = v1;
    v11.version_minor = 1;
    v11.signature = try signTestReleaseBundle(signer_identity, v11);
    _ = try service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos/public",
        .data_schema_version = 1,
        .release_transparency = publicStoreTransparency(2, 0x72, 0x72),
    }, null);

    const rollback_slot = service.find("app.notes").?.rollback_revision_slot.?;
    service.find("app.notes").?.revisions[rollback_slot].release_transparency = .{};
    try std.testing.expectError(error.StoreTransparencyMissing, service.rollback(rollbackRequestForActive(service.find("app.notes").?)));
    try std.testing.expectEqual(@as(u16, 1), service.find("app.notes").?.versionMinor());
}

test "package service refuses rollback to a revision whose publisher key was revoked" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-revoked-rollback",
        .seed = signing.seedFromByte(0x3C),
    };
    const publisher_principal = principal.PrincipalId{ .kind = .app, .serial = 3_900 };
    _ = try service.trustPolicyAuthorityRoot(
        .{ .kind = .policy_authority, .serial = 1 },
        signing.publicKeyFromByte(0x51),
    );
    _ = try service.trustPublisher(
        publisher_principal,
        .{ .kind = .policy_authority, .serial = 1 },
        "zigos.dev",
        try signing.publicKey(signer_identity),
    );

    var v1 = manifest_fixtures.notesBundle();
    v1.signature = try signTestReleaseBundle(signer_identity, v1);
    _ = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    var v11 = v1;
    v11.version_minor = 1;
    v11.signature = try signTestReleaseBundle(signer_identity, v11);
    _ = try service.install(.{
        .bundle = v11,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    try service.revokePublisher(publisher_principal);
    try std.testing.expectError(error.PublisherKeyRevoked, service.buildLaunchPlan("app.notes"));
    var resolved: ResolvedManifest = undefined;
    try std.testing.expectError(error.PublisherKeyRevoked, service.resolveCurrentManifest("app.notes", &resolved));
    try std.testing.expectError(error.PublisherKeyRevoked, service.rollback(rollbackRequestForActive(service.find("app.notes").?)));
    const removed = try service.remove(removeRequestForActive(service.find("app.notes").?));
    try std.testing.expect(removed.removed_existing);
}

test "package service rejects untrusted self-signed and revoked publisher bundles" {
    const signer_identity = signing.SignerIdentity{
        .label = "self-signed-example",
        .seed = signing.seedFromByte(0x38),
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
        .seed = signing.seedFromByte(0x36),
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
        .seed = signing.seedFromByte(0x34),
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
        .seed = signing.seedFromByte(0x35),
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

    var schema_downgrade = v2;
    schema_downgrade.version_minor = 2;
    schema_downgrade.signature = try signTestReleaseBundle(signer_identity, schema_downgrade);
    try std.testing.expectError(error.SchemaVersionRegressionRejected, service.install(.{
        .bundle = schema_downgrade,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));
}

test "package service resolves installed manifests with stable slices" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-resolve",
        .seed = signing.seedFromByte(0x32),
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
                .memory_bytes = units.kibibytes(1),
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
            .model_digest = "sha256:tiny-embed-notes",
            .model_source_identity = "store:zigos/local-models",
            .locality = .local_only,
            .offline_required = true,
        },
        .data_rights = .{
            .user_data_present = true,
            .portable_export = true,
            .deletion_supported = true,
            .deletion_receipt_required = true,
            .export_format = "application/zigos-object-archive",
        },
        .supply_chain = .{
            .sbom_digest = "sha256:notes-sbom",
            .source_archive_digest = "sha256:notes-source",
            .build_recipe_digest = "sha256:notes-build-recipe",
            .vulnerability_scan_digest = "sha256:notes-vuln-scan",
            .build_provenance_identity = "builder:zigos/release",
            .reproducible_build = true,
            .trusted_builder = true,
        },
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize notes locally",
            .max_autonomous_actions = 4,
            .max_remote_calls = 0,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .local_context_only = true,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
        .accessibility = .{
            .adaptive_ui = true,
            .supports_screen_reader = true,
            .supports_keyboard_navigation = true,
            .supports_reduced_motion = true,
            .supports_high_contrast = true,
            .profile_notes = "first-party notes honors user accessibility profile",
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
    try std.testing.expectEqualStrings("sha256:tiny-embed-notes", current.ai_metadata.model_digest);
    try std.testing.expectEqualStrings("store:zigos/local-models", current.ai_metadata.model_source_identity);
    try std.testing.expect(current.data_rights.deletion_receipt_required);
    try std.testing.expectEqualStrings("application/zigos-object-archive", current.data_rights.export_format);
    try std.testing.expectEqualStrings("sha256:notes-sbom", current.supply_chain.sbom_digest);
    try std.testing.expectEqualStrings("sha256:notes-source", current.supply_chain.source_archive_digest);
    try std.testing.expectEqualStrings("sha256:notes-build-recipe", current.supply_chain.build_recipe_digest);
    try std.testing.expectEqualStrings("sha256:notes-vuln-scan", current.supply_chain.vulnerability_scan_digest);
    try std.testing.expectEqualStrings("builder:zigos/release", current.supply_chain.build_provenance_identity);
    try std.testing.expect(current.supply_chain.reproducible_build);
    try std.testing.expect(current.supply_chain.trusted_builder);
    try std.testing.expect(current.agent_delegation.enabled);
    try std.testing.expectEqualStrings("Organize notes locally", current.agent_delegation.purpose);
    try std.testing.expectEqual(@as(u16, 4), current.agent_delegation.max_autonomous_actions);
    try std.testing.expect(current.agent_delegation.audit_required);
    try std.testing.expect(current.agent_delegation.session_bound);
    try std.testing.expect(current.agent_delegation.local_context_only);
    try std.testing.expectEqual(@as(usize, 4096), current.agent_delegation.max_context_bytes);
    try std.testing.expect(current.agent_delegation.kill_switch_supported);
    try std.testing.expect(current.accessibility.adaptive_ui);
    try std.testing.expect(current.accessibility.supports_screen_reader);
    try std.testing.expect(current.accessibility.supports_keyboard_navigation);
    try std.testing.expect(current.accessibility.supports_reduced_motion);
    try std.testing.expect(current.accessibility.supports_high_contrast);
    try std.testing.expectEqualStrings("first-party notes honors user accessibility profile", current.accessibility.profile_notes);
}

test "package service enforces package supply chain policy before install" {
    var policies = policy_object.Directory.init();
    const policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 94,
        .issuer = .{ .kind = .policy_authority, .serial = 97 },
        .label = "trusted-package-provenance",
        .install_source_mode = .platform_store_only,
        .require_package_sbom = true,
        .require_reproducible_package_build = true,
        .require_trusted_package_builder = true,
        .require_vulnerability_scan = true,
    }, .{
        .label = "package-provenance-policy-key",
        .seed = signing.seedFromByte(0x3A),
    });

    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-supply-chain",
        .seed = signing.seedFromByte(0x3B),
    };
    try trustTestPublisher(&service, signer_identity, "Example Software");

    var bundle = manifest.BundleManifest{
        .bundle_id = "app.supply",
        .display_name = "Supply",
        .publisher = "Example Software",
        .provided_interfaces = &.{.{ .name = "zigos.supply.example" }},
        .components = &.{.{
            .id = "supply",
            .entry = "app.supply",
        }},
        .assets = &.{.{ .path = "assets/icon.svg", .content_type = "image/svg+xml" }},
    };
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);
    try std.testing.expectError(error.PackageProvenanceDenied, service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, policy));

    bundle.supply_chain = .{
        .sbom_digest = "sha256:supply-sbom",
        .source_archive_digest = "sha256:supply-source",
        .build_recipe_digest = "sha256:supply-build-recipe",
        .vulnerability_scan_digest = "sha256:supply-vuln-scan",
        .build_provenance_identity = "builder:zigos/release",
        .reproducible_build = true,
        .trusted_builder = true,
    };
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);
    const installed = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, policy);
    try std.testing.expect(installed.installed_new);
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
        .seed = signing.seedFromByte(0x38),
    };
    bundle.signature = try signTestReleaseBundle(signer_identity, bundle);
    try trustTestPublisher(&service, signer_identity, "Example Software");

    service.slots.slots[3].in_use = true;
    try bundle_ops.installNew(&service.slots.slots[3].bundle, bundle, "store:zigos", 1, crypto_hash.digestFromByte(0x11));
    service.rebuildIndexes();

    const launch_plan = try service.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 1), launch_plan.components.len);
    try std.testing.expectEqualStrings("notes.main", launch_plan.components[0].entrySlice());
}

test "package service round-trips the example writer manifest fields without widening authority" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-example-writer",
        .seed = signing.seedFromByte(0x37),
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

test "package bundle ops reject semantically invalid manifests before storage" {
    var service = Service.init();
    const duplicate_permissions = [_]manifest.PermissionRequest{
        manifest_fixtures.example_writer_permissions[0],
        manifest_fixtures.example_writer_permissions[0],
        manifest_fixtures.example_writer_permissions[2],
    };
    var bundle = manifest_fixtures.exampleWriterBundle();
    bundle.requested_permissions = &duplicate_permissions;

    try std.testing.expectError(
        error.DuplicatePermissionRequest,
        bundle_ops.installNew(&service.slots.slots[0].bundle, bundle, "store:zigos", 1, crypto_hash.digestFromByte(0x66)),
    );
    try std.testing.expectEqual(@as(u32, 0), service.slots.slots[0].bundle.revision_count);
}

test "package service rejects example writer manifest updates that widen permissions without declaration" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test-example-writer-update",
        .seed = signing.seedFromByte(0x39),
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
