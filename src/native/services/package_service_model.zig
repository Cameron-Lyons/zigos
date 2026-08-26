const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
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
pub const MAX_PERMISSION_REASON_BYTES: usize = 128;
pub const MAX_PERMISSION_TEXT_BYTES_PER_REVISION: usize = 4096;
pub const MAX_BACKGROUND_TASKS_PER_BUNDLE: usize = 8;
pub const MAX_BACKGROUND_TASK_ID_BYTES: usize = 48;
pub const MAX_MODEL_FAMILY_BYTES: usize = 48;
pub const MAX_MODEL_DIGEST_BYTES: usize = manifest.MAX_AI_MODEL_DIGEST_BYTES;
pub const MAX_MODEL_SOURCE_BYTES: usize = manifest.MAX_AI_MODEL_SOURCE_BYTES;
pub const MAX_DATA_RIGHTS_FORMAT_BYTES: usize = manifest.MAX_DATA_RIGHTS_FORMAT_BYTES;
pub const MAX_SUPPLY_CHAIN_DIGEST_BYTES: usize = manifest.MAX_SUPPLY_CHAIN_DIGEST_BYTES;
pub const MAX_BUILD_PROVENANCE_IDENTITY_BYTES: usize = manifest.MAX_BUILD_PROVENANCE_IDENTITY_BYTES;
pub const MAX_AGENT_PURPOSE_BYTES: usize = manifest.MAX_AGENT_PURPOSE_BYTES;
pub const MAX_ACCESSIBILITY_PROFILE_BYTES: usize = manifest.MAX_ACCESSIBILITY_PROFILE_BYTES;
pub const MAX_OBJECT_BACKUP_FORMAT_BYTES: usize = manifest.MAX_OBJECT_BACKUP_FORMAT_BYTES;
pub const MAX_SEMANTIC_MODEL_DIGEST_BYTES: usize = manifest.MAX_SEMANTIC_MODEL_DIGEST_BYTES;
pub const MAX_SIGNATURE_FORMAT_BYTES: usize = 16;
pub const MAX_SIGNATURE_SIGNER_BYTES: usize = 64;
pub const MAX_INSTALL_SOURCE_BYTES: usize = 96;
pub const MAX_REVISIONS_PER_BUNDLE: usize = 2;
pub const DERIVES_REVISION_METADATA_FROM_RETAINED_SLOTS = true;
pub const COMPACT_PACKAGE_RESULT_METADATA = true;
pub const REMOVE_RESULT_SIZE_CEILING_BYTES: usize = 2;
pub const OFFBOARD_RESULT_SIZE_CEILING_BYTES: usize = 48;
pub const PACKAGE_LAUNCH_PROVENANCE_SIZE_CEILING_BYTES: usize = 216;
pub const LAUNCH_PLAN_SIZE_CEILING_BYTES: usize = 248;

comptime {
    const byte_capacities = [_]usize{
        MAX_INSTALLED_BUNDLES,
        MAX_LABEL_BYTES,
        MAX_COMPONENTS_PER_BUNDLE,
        MAX_ASSETS_PER_BUNDLE,
        MAX_COMPONENT_ID_BYTES,
        MAX_COMPONENT_ENTRY_BYTES,
        MAX_ASSET_PATH_BYTES,
        MAX_CONTENT_TYPE_BYTES,
        MAX_INTERFACES_PER_BUNDLE,
        MAX_INTERFACE_NAME_BYTES,
        MAX_PERMISSIONS_PER_BUNDLE,
        MAX_PERMISSION_RESOURCE_BYTES,
        MAX_PERMISSION_REASON_BYTES,
        MAX_BACKGROUND_TASKS_PER_BUNDLE,
        MAX_BACKGROUND_TASK_ID_BYTES,
        MAX_MODEL_FAMILY_BYTES,
        MAX_MODEL_DIGEST_BYTES,
        MAX_MODEL_SOURCE_BYTES,
        MAX_DATA_RIGHTS_FORMAT_BYTES,
        MAX_SUPPLY_CHAIN_DIGEST_BYTES,
        MAX_BUILD_PROVENANCE_IDENTITY_BYTES,
        MAX_AGENT_PURPOSE_BYTES,
        MAX_ACCESSIBILITY_PROFILE_BYTES,
        MAX_OBJECT_BACKUP_FORMAT_BYTES,
        MAX_SEMANTIC_MODEL_DIGEST_BYTES,
        MAX_SIGNATURE_FORMAT_BYTES,
        MAX_SIGNATURE_SIGNER_BYTES,
        MAX_INSTALL_SOURCE_BYTES,
        MAX_REVISIONS_PER_BUNDLE,
        manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES,
        manifest.MAX_SIGNATURE_VALUE_BYTES,
    };
    for (byte_capacities) |capacity| {
        if (capacity > std.math.maxInt(u8)) {
            @compileError("package catalog capacity exceeds its compact field");
        }
    }
}

pub const InstallRequest = struct {
    bundle: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32 = 1,
    declared_permission_change: bool = false,
    release_transparency: ReleaseTransparencyEvidence = .{},
};

pub const ReleaseTransparencyEvidence = struct {
    sequence: u64 = 0,
    root: crypto_hash.Digest = crypto_hash.zero_digest,
    log_head: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn present(self: ReleaseTransparencyEvidence) bool {
        return self.sequence != 0 and
            !digestIsZero(self.root) and
            !digestIsZero(self.log_head);
    }
};

pub const InstallResult = struct {
    installed_new: bool,
    updated_existing: bool,
    permissions_changed: bool,
    rollback_available: bool,
};

pub const RemoveResult = struct {
    removed_existing: bool,
    removed_revision_count: u8,

    comptime {
        if (@sizeOf(@This()) > REMOVE_RESULT_SIZE_CEILING_BYTES) {
            @compileError("package remove result exceeds its compact size ceiling");
        }
    }
};

pub const OffboardResult = struct {
    removed_existing: bool,
    removed_revision_count: u8,
    deletion_receipt_id: u64,
    removed_bundle_digest: crypto_hash.Digest,

    comptime {
        if (@sizeOf(@This()) > OFFBOARD_RESULT_SIZE_CEILING_BYTES) {
            @compileError("package offboard result exceeds its compact size ceiling");
        }
    }
};

pub const StoredComponent = struct {
    id_len: u8 = 0,
    id: [MAX_COMPONENT_ID_BYTES]u8 = [_]u8{0} ** MAX_COMPONENT_ID_BYTES,
    entry_len: u8 = 0,
    entry: [MAX_COMPONENT_ENTRY_BYTES]u8 = [_]u8{0} ** MAX_COMPONENT_ENTRY_BYTES,

    pub fn idSlice(self: *const StoredComponent) []const u8 {
        return self.id[0..self.id_len];
    }

    pub fn entrySlice(self: *const StoredComponent) []const u8 {
        return self.entry[0..self.entry_len];
    }
};

pub const StoredAsset = struct {
    path_len: u8 = 0,
    path: [MAX_ASSET_PATH_BYTES]u8 = [_]u8{0} ** MAX_ASSET_PATH_BYTES,
    content_type_len: u8 = 0,
    content_type: [MAX_CONTENT_TYPE_BYTES]u8 = [_]u8{0} ** MAX_CONTENT_TYPE_BYTES,

    pub fn pathSlice(self: *const StoredAsset) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn contentTypeSlice(self: *const StoredAsset) []const u8 {
        return self.content_type[0..self.content_type_len];
    }
};

pub const LaunchPlan = struct {
    components: []const StoredComponent,
    assets: []const StoredAsset,
    provenance: PackageLaunchProvenance = .{},

    comptime {
        if (@sizeOf(@This()) > LAUNCH_PLAN_SIZE_CEILING_BYTES) {
            @compileError("package launch plan exceeds its compact size ceiling");
        }
    }
};

pub const PackageLaunchProvenance = struct {
    bundle_id: []const u8 = "",
    display_name: []const u8 = "",
    publisher: []const u8 = "",
    source_identity: []const u8 = "",
    version_major: u16 = 0,
    version_minor: u16 = 0,
    update_channel: manifest.UpdateChannel = .stable,
    data_schema_version: u32 = 0,
    permission_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    signature_format: []const u8 = "",
    signature_signer: []const u8 = "",
    signature_public_key_len: u8 = 0,
    signed: bool = false,
    release_transparency: ReleaseTransparencyEvidence = .{},

    comptime {
        if (@sizeOf(@This()) > PACKAGE_LAUNCH_PROVENANCE_SIZE_CEILING_BYTES) {
            @compileError("package launch provenance exceeds its compact size ceiling");
        }
    }
};

pub const StoredInterface = struct {
    name_len: u8 = 0,
    name: [MAX_INTERFACE_NAME_BYTES]u8 = [_]u8{0} ** MAX_INTERFACE_NAME_BYTES,
    version_major: u16 = 1,
    version_minor: u16 = 0,

    pub fn nameSlice(self: *const StoredInterface) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const PermissionTextRef = struct {
    offset: u16 = 0,
    len: u8 = 0,
    reserved: u8 = 0,

    pub fn slice(self: PermissionTextRef, text: []const u8) []const u8 {
        const start: usize = self.offset;
        const end = start + self.len;
        std.debug.assert(end <= text.len);
        return text[start..end];
    }
};

pub const StoredPermission = struct {
    pub const max_resource_bytes = MAX_PERMISSION_RESOURCE_BYTES;
    pub const max_reason_bytes = MAX_PERMISSION_REASON_BYTES;

    kind: manifest.PermissionKind = .object_access,
    resource: PermissionTextRef = .{},
    rights: @FieldType(manifest.PermissionRequest, "rights") = .{ .policy = .{} },
    required: bool = true,
    local_only: bool = false,
    max_lease_ticks: u64 = 0,
    target_id: u64 = 0,
    egress_intent_kind: manifest.DataEgressIntentKind = .unspecified,
    sensitivity: manifest.DataSensitivity = .internal_data,
    purpose: manifest.PermissionPurpose = .unspecified,
    retention_days: u16 = 0,
    user_visible_reason: PermissionTextRef = .{},
    egress_object: PermissionTextRef = .{},
    egress_principal: PermissionTextRef = .{},
    egress_service: PermissionTextRef = .{},
    egress_event_type: PermissionTextRef = .{},

    pub fn resourceSlice(self: *const StoredPermission, text: []const u8) []const u8 {
        return self.resource.slice(text);
    }

    pub fn userVisibleReasonSlice(self: *const StoredPermission, text: []const u8) []const u8 {
        return self.user_visible_reason.slice(text);
    }

    pub fn egressObjectSlice(self: *const StoredPermission, text: []const u8) []const u8 {
        return self.egress_object.slice(text);
    }

    pub fn egressPrincipalSlice(self: *const StoredPermission, text: []const u8) []const u8 {
        return self.egress_principal.slice(text);
    }

    pub fn egressServiceSlice(self: *const StoredPermission, text: []const u8) []const u8 {
        return self.egress_service.slice(text);
    }

    pub fn egressEventTypeSlice(self: *const StoredPermission, text: []const u8) []const u8 {
        return self.egress_event_type.slice(text);
    }
};

pub const StoredBackgroundTask = struct {
    id_len: u8 = 0,
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
    model_family_len: u8 = 0,
    model_family: [MAX_MODEL_FAMILY_BYTES]u8 = [_]u8{0} ** MAX_MODEL_FAMILY_BYTES,
    model_digest_len: u8 = 0,
    model_digest: [MAX_MODEL_DIGEST_BYTES]u8 = [_]u8{0} ** MAX_MODEL_DIGEST_BYTES,
    model_source_identity_len: u8 = 0,
    model_source_identity: [MAX_MODEL_SOURCE_BYTES]u8 = [_]u8{0} ** MAX_MODEL_SOURCE_BYTES,
    locality: manifest.AiLocality = .inherit_task,
    offline_required: bool = false,
    private_context: bool = false,
    training_allowed: bool = false,
    max_context_bytes: usize = 0,
    audit_prompt_use: bool = false,

    pub fn modelFamilySlice(self: *const StoredAiMetadata) []const u8 {
        return self.model_family[0..self.model_family_len];
    }

    pub fn modelDigestSlice(self: *const StoredAiMetadata) []const u8 {
        return self.model_digest[0..self.model_digest_len];
    }

    pub fn modelSourceIdentitySlice(self: *const StoredAiMetadata) []const u8 {
        return self.model_source_identity[0..self.model_source_identity_len];
    }
};

pub const StoredDataRights = struct {
    user_data_present: bool = false,
    portable_export: bool = false,
    deletion_supported: bool = false,
    deletion_receipt_required: bool = false,
    export_format_len: u8 = 0,
    export_format: [MAX_DATA_RIGHTS_FORMAT_BYTES]u8 = [_]u8{0} ** MAX_DATA_RIGHTS_FORMAT_BYTES,

    pub fn exportFormatSlice(self: *const StoredDataRights) []const u8 {
        return self.export_format[0..self.export_format_len];
    }
};

pub const StoredSupplyChain = struct {
    sbom_digest_len: u8 = 0,
    sbom_digest: [MAX_SUPPLY_CHAIN_DIGEST_BYTES]u8 = [_]u8{0} ** MAX_SUPPLY_CHAIN_DIGEST_BYTES,
    source_archive_digest_len: u8 = 0,
    source_archive_digest: [MAX_SUPPLY_CHAIN_DIGEST_BYTES]u8 = [_]u8{0} ** MAX_SUPPLY_CHAIN_DIGEST_BYTES,
    build_recipe_digest_len: u8 = 0,
    build_recipe_digest: [MAX_SUPPLY_CHAIN_DIGEST_BYTES]u8 = [_]u8{0} ** MAX_SUPPLY_CHAIN_DIGEST_BYTES,
    vulnerability_scan_digest_len: u8 = 0,
    vulnerability_scan_digest: [MAX_SUPPLY_CHAIN_DIGEST_BYTES]u8 = [_]u8{0} ** MAX_SUPPLY_CHAIN_DIGEST_BYTES,
    build_provenance_identity_len: u8 = 0,
    build_provenance_identity: [MAX_BUILD_PROVENANCE_IDENTITY_BYTES]u8 = [_]u8{0} ** MAX_BUILD_PROVENANCE_IDENTITY_BYTES,
    reproducible_build: bool = false,
    trusted_builder: bool = false,

    pub fn sbomDigestSlice(self: *const StoredSupplyChain) []const u8 {
        return self.sbom_digest[0..self.sbom_digest_len];
    }

    pub fn sourceArchiveDigestSlice(self: *const StoredSupplyChain) []const u8 {
        return self.source_archive_digest[0..self.source_archive_digest_len];
    }

    pub fn buildRecipeDigestSlice(self: *const StoredSupplyChain) []const u8 {
        return self.build_recipe_digest[0..self.build_recipe_digest_len];
    }

    pub fn vulnerabilityScanDigestSlice(self: *const StoredSupplyChain) []const u8 {
        return self.vulnerability_scan_digest[0..self.vulnerability_scan_digest_len];
    }

    pub fn buildProvenanceIdentitySlice(self: *const StoredSupplyChain) []const u8 {
        return self.build_provenance_identity[0..self.build_provenance_identity_len];
    }
};

pub const StoredAgentDelegation = struct {
    enabled: bool = false,
    purpose_len: u8 = 0,
    purpose: [MAX_AGENT_PURPOSE_BYTES]u8 = [_]u8{0} ** MAX_AGENT_PURPOSE_BYTES,
    max_autonomous_actions: u16 = 0,
    max_remote_calls: u16 = 0,
    user_confirmation_required: bool = true,
    audit_required: bool = true,
    session_bound: bool = false,
    local_context_only: bool = true,
    max_context_bytes: usize = 0,
    kill_switch_supported: bool = false,

    pub fn purposeSlice(self: *const StoredAgentDelegation) []const u8 {
        return self.purpose[0..self.purpose_len];
    }
};

pub const StoredAccessibility = struct {
    adaptive_ui: bool = false,
    supports_screen_reader: bool = false,
    supports_keyboard_navigation: bool = false,
    supports_reduced_motion: bool = false,
    supports_high_contrast: bool = false,
    profile_notes_len: u8 = 0,
    profile_notes: [MAX_ACCESSIBILITY_PROFILE_BYTES]u8 = [_]u8{0} ** MAX_ACCESSIBILITY_PROFILE_BYTES,

    pub fn profileNotesSlice(self: *const StoredAccessibility) []const u8 {
        return self.profile_notes[0..self.profile_notes_len];
    }
};

pub const StoredObjectResilience = struct {
    backup_enabled: bool = false,
    encrypted_snapshots: bool = false,
    recovery_key_required: bool = false,
    portable_restore: bool = false,
    device_trust_required: bool = false,
    max_restore_age_days: u16 = 0,
    backup_format_len: u8 = 0,
    backup_format: [MAX_OBJECT_BACKUP_FORMAT_BYTES]u8 = [_]u8{0} ** MAX_OBJECT_BACKUP_FORMAT_BYTES,

    pub fn backupFormatSlice(self: *const StoredObjectResilience) []const u8 {
        return self.backup_format[0..self.backup_format_len];
    }
};

pub const StoredSemanticIndex = struct {
    enabled: bool = false,
    local_only: bool = true,
    encrypted_index: bool = false,
    redacted_snippets: bool = false,
    max_query_bytes: usize = 0,
    model_digest_len: u8 = 0,
    model_digest: [MAX_SEMANTIC_MODEL_DIGEST_BYTES]u8 = [_]u8{0} ** MAX_SEMANTIC_MODEL_DIGEST_BYTES,

    pub fn modelDigestSlice(self: *const StoredSemanticIndex) []const u8 {
        return self.model_digest[0..self.model_digest_len];
    }
};

pub const StoredSignature = struct {
    format_len: u8 = 0,
    format: [MAX_SIGNATURE_FORMAT_BYTES]u8 = [_]u8{0} ** MAX_SIGNATURE_FORMAT_BYTES,
    signer_len: u8 = 0,
    signer: [MAX_SIGNATURE_SIGNER_BYTES]u8 = [_]u8{0} ** MAX_SIGNATURE_SIGNER_BYTES,
    public_key_len: u8 = 0,
    public_key: [manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES]u8 = [_]u8{0} ** manifest.MAX_SIGNATURE_PUBLIC_KEY_BYTES,
    value_len: u8 = 0,
    value: [manifest.MAX_SIGNATURE_VALUE_BYTES]u8 = [_]u8{0} ** manifest.MAX_SIGNATURE_VALUE_BYTES,

    pub fn formatSlice(self: *const StoredSignature) []const u8 {
        return self.format[0..self.format_len];
    }

    pub fn signerSlice(self: *const StoredSignature) []const u8 {
        return self.signer[0..self.signer_len];
    }

    pub fn toManifest(self: *const StoredSignature) manifest.Signature {
        return .{
            .format = manifest.parseSignatureFormat(self.formatSlice()),
            .signer = self.signerSlice(),
            .public_key_len = @intCast(self.public_key_len),
            .public_key = self.public_key,
            .value_len = @intCast(self.value_len),
            .value = self.value,
        };
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
    data_rights: manifest.DataRightsDecl,
    supply_chain: manifest.SupplyChainDecl,
    agent_delegation: manifest.AgentDelegationDecl,
    accessibility: manifest.AccessibilityDecl,
    object_resilience: manifest.ObjectResilienceDecl,
    semantic_index: manifest.SemanticIndexDecl,
    signature: manifest.Signature,
};

pub const BundleRevision = struct {
    revision_id: u64 = 0,
    display_name_len: u8 = 0,
    display_name: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    publisher_len: u8 = 0,
    publisher: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    source_identity_len: u8 = 0,
    source_identity: [MAX_INSTALL_SOURCE_BYTES]u8 = [_]u8{0} ** MAX_INSTALL_SOURCE_BYTES,
    version_major: u16 = 0,
    version_minor: u16 = 0,
    channel: manifest.UpdateChannel = .stable,
    permission_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    release_transparency: ReleaseTransparencyEvidence = .{},
    schema_version: u32 = 0,
    component_count: u8 = 0,
    components: [MAX_COMPONENTS_PER_BUNDLE]StoredComponent = [_]StoredComponent{zeroStoredComponent()} ** MAX_COMPONENTS_PER_BUNDLE,
    asset_count: u8 = 0,
    assets: [MAX_ASSETS_PER_BUNDLE]StoredAsset = [_]StoredAsset{zeroStoredAsset()} ** MAX_ASSETS_PER_BUNDLE,
    provided_interface_count: u8 = 0,
    provided_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
    consumed_interface_count: u8 = 0,
    consumed_interfaces: [MAX_INTERFACES_PER_BUNDLE]StoredInterface = [_]StoredInterface{zeroStoredInterface()} ** MAX_INTERFACES_PER_BUNDLE,
    requested_permission_count: u8 = 0,
    permission_text_len: u16 = 0,
    permission_text: [MAX_PERMISSION_TEXT_BYTES_PER_REVISION]u8 = [_]u8{0} ** MAX_PERMISSION_TEXT_BYTES_PER_REVISION,
    requested_permissions: [MAX_PERMISSIONS_PER_BUNDLE]StoredPermission = [_]StoredPermission{zeroStoredPermission()} ** MAX_PERMISSIONS_PER_BUNDLE,
    background_task_count: u8 = 0,
    background_tasks: [MAX_BACKGROUND_TASKS_PER_BUNDLE]StoredBackgroundTask = [_]StoredBackgroundTask{zeroStoredBackgroundTask()} ** MAX_BACKGROUND_TASKS_PER_BUNDLE,
    ai_metadata: StoredAiMetadata = zeroStoredAiMetadata(),
    data_rights: StoredDataRights = zeroStoredDataRights(),
    supply_chain: StoredSupplyChain = zeroStoredSupplyChain(),
    agent_delegation: StoredAgentDelegation = zeroStoredAgentDelegation(),
    accessibility: StoredAccessibility = zeroStoredAccessibility(),
    object_resilience: StoredObjectResilience = zeroStoredObjectResilience(),
    semantic_index: StoredSemanticIndex = zeroStoredSemanticIndex(),
    signature: StoredSignature = zeroStoredSignature(),

    pub fn displayNameSlice(self: *const BundleRevision) []const u8 {
        return self.display_name[0..self.display_name_len];
    }

    pub fn publisherSlice(self: *const BundleRevision) []const u8 {
        return self.publisher[0..self.publisher_len];
    }

    pub fn sourceIdentitySlice(self: *const BundleRevision) []const u8 {
        return self.source_identity[0..self.source_identity_len];
    }

    pub fn permissionTextSlice(self: *const BundleRevision) []const u8 {
        return self.permission_text[0..self.permission_text_len];
    }
};

fn digestIsZero(digest: crypto_hash.Digest) bool {
    return std.mem.eql(u8, &digest, &crypto_hash.zero_digest);
}

pub const InstalledBundle = struct {
    bundle_id_len: u8,
    bundle_id: [MAX_LABEL_BYTES]u8,
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

    pub fn revisionCount(self: *const InstalledBundle) u8 {
        if (self.activeRevision().revision_id == 0) return 0;
        return 1 + @as(u8, @intFromBool(self.rollback_revision_slot != null));
    }

    pub fn nextRevisionId(self: *const InstalledBundle) u64 {
        var latest_revision_id: u64 = 0;
        for (self.revisions) |revision| {
            latest_revision_id = @max(latest_revision_id, revision.revision_id);
        }
        if (latest_revision_id == std.math.maxInt(u64)) return 0;
        return latest_revision_id + 1;
    }

    pub fn displayNameSlice(self: *const InstalledBundle) []const u8 {
        return self.activeRevision().displayNameSlice();
    }

    pub fn publisherSlice(self: *const InstalledBundle) []const u8 {
        return self.activeRevision().publisherSlice();
    }

    pub fn sourceIdentitySlice(self: *const InstalledBundle) []const u8 {
        return self.activeRevision().sourceIdentitySlice();
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

test "package catalog uses capacity-sized resident metadata" {
    try std.testing.expect(DERIVES_REVISION_METADATA_FROM_RETAINED_SLOTS);
    try std.testing.expect(!@hasField(InstalledBundle, "revision_count"));
    try std.testing.expect(!@hasField(InstalledBundle, "next_revision_id"));
    try std.testing.expectEqual(@as(usize, 114), @sizeOf(StoredComponent));
    try std.testing.expectEqual(@as(usize, 180), @sizeOf(StoredSignature));
    try std.testing.expectEqual(@as(usize, 10_400), @sizeOf(BundleRevision));
    try std.testing.expectEqual(@as(usize, 20_880), @sizeOf(BundleSlot));
}

test "package results use compact bounded metadata" {
    try std.testing.expect(COMPACT_PACKAGE_RESULT_METADATA);
    try std.testing.expectEqual(u8, @FieldType(RemoveResult, "removed_revision_count"));
    try std.testing.expectEqual(u8, @FieldType(OffboardResult, "removed_revision_count"));
    try std.testing.expectEqual(u8, @FieldType(PackageLaunchProvenance, "signature_public_key_len"));
    try std.testing.expect(@sizeOf(RemoveResult) <= REMOVE_RESULT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(OffboardResult) <= OFFBOARD_RESULT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(PackageLaunchProvenance) <= PACKAGE_LAUNCH_PROVENANCE_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(LaunchPlan) <= LAUNCH_PLAN_SIZE_CEILING_BYTES);
}

pub fn zeroBundle() InstalledBundle {
    return .{
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_LABEL_BYTES,
        .active_revision_slot = 0,
        .rollback_revision_slot = null,
        .revisions = [_]BundleRevision{zeroBundleRevision()} ** MAX_REVISIONS_PER_BUNDLE,
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

fn zeroStoredDataRights() StoredDataRights {
    return .{};
}

fn zeroStoredSupplyChain() StoredSupplyChain {
    return .{};
}

fn zeroStoredAgentDelegation() StoredAgentDelegation {
    return .{};
}

fn zeroStoredAccessibility() StoredAccessibility {
    return .{};
}

fn zeroStoredObjectResilience() StoredObjectResilience {
    return .{};
}

fn zeroStoredSemanticIndex() StoredSemanticIndex {
    return .{};
}

fn zeroStoredSignature() StoredSignature {
    return .{};
}
