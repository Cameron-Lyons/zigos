const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const units = @import("../core/units.zig");

pub const MAX_DATA_RIGHTS_FORMAT_BYTES: usize = 64;
pub const MAX_AI_MODEL_DIGEST_BYTES: usize = 96;
pub const MAX_AI_MODEL_SOURCE_BYTES: usize = 96;
pub const MAX_SUPPLY_CHAIN_DIGEST_BYTES: usize = 96;
pub const MAX_BUILD_PROVENANCE_IDENTITY_BYTES: usize = 96;
pub const MAX_AGENT_PURPOSE_BYTES: usize = 128;
pub const MAX_ACCESSIBILITY_PROFILE_BYTES: usize = 128;
pub const MAX_OBJECT_BACKUP_FORMAT_BYTES: usize = 64;
pub const MAX_SEMANTIC_MODEL_DIGEST_BYTES: usize = 96;

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

pub const DataRightsDecl = struct {
    user_data_present: bool = false,
    portable_export: bool = false,
    deletion_supported: bool = false,
    deletion_receipt_required: bool = false,
    export_format: []const u8 = "",
};

pub const SupplyChainDecl = struct {
    sbom_digest: []const u8 = "",
    source_archive_digest: []const u8 = "",
    build_recipe_digest: []const u8 = "",
    vulnerability_scan_digest: []const u8 = "",
    build_provenance_identity: []const u8 = "",
    reproducible_build: bool = false,
    trusted_builder: bool = false,
};

pub const AgentDelegationDecl = struct {
    enabled: bool = false,
    purpose: []const u8 = "",
    max_autonomous_actions: u16 = 0,
    max_remote_calls: u16 = 0,
    user_confirmation_required: bool = true,
    audit_required: bool = true,
    session_bound: bool = false,
    local_context_only: bool = true,
    max_context_bytes: usize = 0,
    kill_switch_supported: bool = false,
};

pub const AccessibilityDecl = struct {
    adaptive_ui: bool = false,
    supports_screen_reader: bool = false,
    supports_keyboard_navigation: bool = false,
    supports_reduced_motion: bool = false,
    supports_high_contrast: bool = false,
    profile_notes: []const u8 = "",
};

pub const ObjectResilienceDecl = struct {
    backup_enabled: bool = false,
    encrypted_snapshots: bool = false,
    recovery_key_required: bool = false,
    portable_restore: bool = false,
    device_trust_required: bool = false,
    max_restore_age_days: u16 = 0,
    backup_format: []const u8 = "",
};

pub const SemanticIndexDecl = struct {
    enabled: bool = false,
    local_only: bool = true,
    encrypted_index: bool = false,
    redacted_snippets: bool = false,
    max_query_bytes: usize = 0,
    model_digest: []const u8 = "",
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
    model_digest: []const u8 = "",
    model_source_identity: []const u8 = "",
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
pub const SIGNATURE_FORMAT_ML_DSA65 = "ml-dsa-65";
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA65_SIGNATURE_BYTES: usize = 3309;
pub const MAX_SIGNATURE_PUBLIC_KEY_BYTES: usize = ED25519_PUBLIC_KEY_BYTES;
pub const MAX_SIGNATURE_VALUE_BYTES: usize = ED25519_SIGNATURE_BYTES;

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
    data_rights: DataRightsDecl = .{},
    supply_chain: SupplyChainDecl = .{},
    agent_delegation: AgentDelegationDecl = .{},
    accessibility: AccessibilityDecl = .{},
    object_resilience: ObjectResilienceDecl = .{},
    semantic_index: SemanticIndexDecl = .{},
    update_channel: UpdateChannel = .stable,
    signature: Signature = .{},
};

pub fn bundleDeclaresInterface(bundle: BundleManifest, expected: InterfaceDecl) bool {
    return interfaceListDeclares(bundle.provided_interfaces, expected) or
        interfaceListDeclares(bundle.consumed_interfaces, expected);
}

fn interfaceListDeclares(interfaces: []const InterfaceDecl, expected: InterfaceDecl) bool {
    for (interfaces) |candidate| {
        if (!std.mem.eql(u8, candidate.name, expected.name)) continue;
        if (candidate.version_major != expected.version_major) continue;
        if (candidate.version_minor != expected.version_minor) continue;
        return true;
    }
    return false;
}

pub const ValidationError = error{
    EmptyBundleId,
    EmptyDisplayName,
    EmptyPublisher,
    BundleIdTooLong,
    DisplayNameTooLong,
    PublisherTooLong,
    CompatibilityNamespaceUnsupported,
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
    DataRightsExportMissing,
    DataRightsDeletionMissing,
    DataRightsExportFormatMissing,
    DataRightsExportFormatTooLong,
    DataDeletionReceiptRequired,
    SupplyChainDigestTooLong,
    BuildProvenanceIdentityTooLong,
    ReproducibleBuildRequiresSourceArchive,
    ReproducibleBuildRequiresBuildRecipe,
    TrustedBuilderRequiresIdentity,
    AgentDelegationPurposeMissing,
    AgentDelegationPurposeTooLong,
    AgentDelegationActionBudgetMissing,
    AgentDelegationAuditRequired,
    AgentDelegationNeedsConfirmation,
    AgentDelegationSessionBindingRequired,
    AgentDelegationLocalContextRequired,
    AgentDelegationContextBudgetMissing,
    AgentDelegationKillSwitchRequired,
    AccessibilityProfileTooLong,
    AccessibilityKeyboardNavigationMissing,
    AccessibilityScreenReaderMissing,
    AccessibilityReducedMotionMissing,
    ObjectBackupFormatMissing,
    ObjectBackupFormatTooLong,
    ObjectEncryptedBackupRequired,
    ObjectBackupRecoveryKeyRequired,
    ObjectBackupRestoreRequired,
    ObjectBackupDeviceTrustRequired,
    SemanticIndexRequiresLocal,
    SemanticIndexRequiresEncryption,
    SemanticIndexRequiresRedaction,
    SemanticIndexQueryBudgetMissing,
    SemanticIndexModelDigestMissing,
    SemanticIndexModelDigestTooLong,
    AiModelFamilyTooLong,
    AiModelDigestMissing,
    AiModelDigestTooLong,
    AiModelSourceMissing,
    AiModelSourceTooLong,
    PrivateAiRequiresLocalModel,
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

    try validateNativeOnlyNaming(bundle);
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
    try validateDataRights(bundle);
    try validateSupplyChain(bundle);
    try validateAgentDelegation(bundle);
    try validateAccessibility(bundle);
    try validateObjectResilience(bundle);
    try validateSemanticIndex(bundle);
    try validateBackgroundTasks(bundle);
    try validateDataEgressRequests(bundle);
    try validateAiMetadata(bundle);
}

fn validateDataRights(bundle: BundleManifest) ValidationError!void {
    if (bundle.data_rights.export_format.len > MAX_DATA_RIGHTS_FORMAT_BYTES) return error.DataRightsExportFormatTooLong;
    if (!bundle.data_rights.user_data_present and !bundleContainsSensitiveObjectData(bundle)) return;
    if (!bundle.data_rights.portable_export) return error.DataRightsExportMissing;
    if (bundle.data_rights.export_format.len == 0) return error.DataRightsExportFormatMissing;
    if (!bundle.data_rights.deletion_supported) return error.DataRightsDeletionMissing;
    if (!bundle.data_rights.deletion_receipt_required) return error.DataDeletionReceiptRequired;
}

fn validateSupplyChain(bundle: BundleManifest) ValidationError!void {
    if (bundle.supply_chain.sbom_digest.len > MAX_SUPPLY_CHAIN_DIGEST_BYTES) return error.SupplyChainDigestTooLong;
    if (bundle.supply_chain.source_archive_digest.len > MAX_SUPPLY_CHAIN_DIGEST_BYTES) return error.SupplyChainDigestTooLong;
    if (bundle.supply_chain.build_recipe_digest.len > MAX_SUPPLY_CHAIN_DIGEST_BYTES) return error.SupplyChainDigestTooLong;
    if (bundle.supply_chain.vulnerability_scan_digest.len > MAX_SUPPLY_CHAIN_DIGEST_BYTES) return error.SupplyChainDigestTooLong;
    if (bundle.supply_chain.build_provenance_identity.len > MAX_BUILD_PROVENANCE_IDENTITY_BYTES) return error.BuildProvenanceIdentityTooLong;
    if (bundle.supply_chain.reproducible_build and bundle.supply_chain.source_archive_digest.len == 0) {
        return error.ReproducibleBuildRequiresSourceArchive;
    }
    if (bundle.supply_chain.reproducible_build and bundle.supply_chain.build_recipe_digest.len == 0) {
        return error.ReproducibleBuildRequiresBuildRecipe;
    }
    if (bundle.supply_chain.trusted_builder and bundle.supply_chain.build_provenance_identity.len == 0) {
        return error.TrustedBuilderRequiresIdentity;
    }
}

fn validateAgentDelegation(bundle: BundleManifest) ValidationError!void {
    if (bundle.agent_delegation.purpose.len > MAX_AGENT_PURPOSE_BYTES) return error.AgentDelegationPurposeTooLong;
    if (!bundle.agent_delegation.enabled) return;
    if (bundle.agent_delegation.purpose.len == 0) return error.AgentDelegationPurposeMissing;
    if (bundle.agent_delegation.max_autonomous_actions == 0) return error.AgentDelegationActionBudgetMissing;
    if (!bundle.agent_delegation.audit_required) return error.AgentDelegationAuditRequired;
    if (!bundle.agent_delegation.user_confirmation_required and bundle.agent_delegation.max_remote_calls != 0) {
        return error.AgentDelegationNeedsConfirmation;
    }
    if (!bundle.agent_delegation.session_bound) return error.AgentDelegationSessionBindingRequired;
    if (!bundle.agent_delegation.local_context_only) return error.AgentDelegationLocalContextRequired;
    if (bundle.agent_delegation.max_context_bytes == 0) return error.AgentDelegationContextBudgetMissing;
    if (!bundle.agent_delegation.kill_switch_supported) return error.AgentDelegationKillSwitchRequired;
}

fn validateAccessibility(bundle: BundleManifest) ValidationError!void {
    if (bundle.accessibility.profile_notes.len > MAX_ACCESSIBILITY_PROFILE_BYTES) return error.AccessibilityProfileTooLong;
    if (!bundle.accessibility.adaptive_ui) return;
    if (!bundle.accessibility.supports_keyboard_navigation) return error.AccessibilityKeyboardNavigationMissing;
    if (!bundle.accessibility.supports_screen_reader) return error.AccessibilityScreenReaderMissing;
    if (!bundle.accessibility.supports_reduced_motion) return error.AccessibilityReducedMotionMissing;
}

fn validateObjectResilience(bundle: BundleManifest) ValidationError!void {
    if (bundle.object_resilience.backup_format.len > MAX_OBJECT_BACKUP_FORMAT_BYTES) return error.ObjectBackupFormatTooLong;
    if (!bundle.object_resilience.backup_enabled) return;
    if (bundle.object_resilience.backup_format.len == 0) return error.ObjectBackupFormatMissing;
    if (!bundle.object_resilience.encrypted_snapshots) return error.ObjectEncryptedBackupRequired;
    if (!bundle.object_resilience.recovery_key_required) return error.ObjectBackupRecoveryKeyRequired;
    if (!bundle.object_resilience.portable_restore) return error.ObjectBackupRestoreRequired;
    if (!bundle.object_resilience.device_trust_required) return error.ObjectBackupDeviceTrustRequired;
}

fn validateSemanticIndex(bundle: BundleManifest) ValidationError!void {
    if (bundle.semantic_index.model_digest.len > MAX_SEMANTIC_MODEL_DIGEST_BYTES) return error.SemanticIndexModelDigestTooLong;
    if (!bundle.semantic_index.enabled) return;
    if (!bundle.semantic_index.local_only) return error.SemanticIndexRequiresLocal;
    if (!bundle.semantic_index.encrypted_index) return error.SemanticIndexRequiresEncryption;
    if (!bundle.semantic_index.redacted_snippets) return error.SemanticIndexRequiresRedaction;
    if (bundle.semantic_index.max_query_bytes == 0) return error.SemanticIndexQueryBudgetMissing;
    if (bundle.semantic_index.model_digest.len == 0) return error.SemanticIndexModelDigestMissing;
}

fn validateAiMetadata(bundle: BundleManifest) ValidationError!void {
    if (bundle.ai_metadata.model_digest.len > MAX_AI_MODEL_DIGEST_BYTES) return error.AiModelDigestTooLong;
    if (bundle.ai_metadata.model_source_identity.len > MAX_AI_MODEL_SOURCE_BYTES) return error.AiModelSourceTooLong;
    if (bundle.ai_metadata.locality == .local_only) {
        for (bundle.requested_permissions) |request| {
            if (request.kind != .network_egress) continue;
            if (!request.local_only or request.rights.has(.network_remote)) {
                return error.LocalOnlyAiRequiresLocalNetwork;
            }
        }
    }
    if (bundle.ai_metadata.private_context and bundle.ai_metadata.locality != .local_only) {
        return error.PrivateAiRequiresLocalModel;
    }
    if (bundle.ai_metadata.offline_required and
        (bundle.ai_metadata.model_family.len == 0 or bundle.ai_metadata.locality != .local_only))
    {
        return error.OfflineAiRequiresLocalModel;
    }
    if (requiresMeasuredLocalAi(bundle.ai_metadata) and bundle.ai_metadata.model_digest.len == 0) {
        return error.AiModelDigestMissing;
    }
    if (requiresMeasuredLocalAi(bundle.ai_metadata) and bundle.ai_metadata.model_source_identity.len == 0) {
        return error.AiModelSourceMissing;
    }
    if (bundle.ai_metadata.training_allowed and !bundle.ai_metadata.audit_prompt_use) {
        return error.AiTrainingRequiresAudit;
    }
    if (bundle.ai_metadata.max_context_bytes > units.mebibytes(64)) {
        return error.AiContextTooLarge;
    }
}

fn requiresMeasuredLocalAi(ai_metadata: AiMetadata) bool {
    return ai_metadata.locality == .local_only and
        (ai_metadata.model_family.len != 0 or ai_metadata.offline_required or ai_metadata.private_context);
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
        if (hasDuplicatePermissionBefore(bundle.requested_permissions, index, request)) {
            return error.DuplicatePermissionRequest;
        }
    }
}

fn hasDuplicatePermissionBefore(requests: []const PermissionRequest, index: usize, request: PermissionRequest) bool {
    var previous_index: usize = 0;
    while (previous_index < index) : (previous_index += 1) {
        const previous = requests[previous_index];
        if (previous.kind == request.kind and std.mem.eql(u8, previous.resource, request.resource)) return true;
    }
    return false;
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

fn bundleContainsSensitiveObjectData(bundle: BundleManifest) bool {
    for (bundle.requested_permissions) |request| {
        if (request.kind == .object_access and isSensitive(request.sensitivity)) return true;
    }
    return false;
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

// Canonical short display label for a permission kind. Review surfaces (the
// compositor permission review, permission_review rendering, and the SDK review
// tree) share this single source of truth; the humane permissions layer keeps
// its own friendlier, separately-tested vocabulary on purpose.
pub fn permissionDisplayLabel(kind: PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "Object access",
        .network_egress => "Data egress",
        .device_access => "Device access",
        .clipboard => "Clipboard",
        .camera => "Camera",
        .mic => "Microphone",
        .sensor => "Sensor",
        .location => "Location",
        .contacts => "Contacts",
        .screen_capture => "Screen capture",
        .notification_post => "Notification posting",
        .background_execution => "Background execution",
        .peer_ipc => "Peer IPC",
    };
}

pub fn validateApplicationPackaging(bundle: BundleManifest) ValidationError!void {
    if (isUnsupportedCompatibilityNamespace(bundle.bundle_id)) return error.CompatibilityNamespaceUnsupported;
    if (!requiresApplicationPackaging(bundle.bundle_id)) return;
    try validateNativeOnlyNaming(bundle);
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

        if (hasDuplicateStringFieldBefore(bundle.background_tasks, index, "id", task.id)) return error.DuplicateBackgroundTaskId;
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

        if (hasDuplicateStringFieldBefore(bundle.components, index, "id", component.id)) return error.DuplicateComponentId;
    }
}

fn hasDuplicateStringFieldBefore(items: anytype, index: usize, comptime field_name: []const u8, value: []const u8) bool {
    var previous_index: usize = 0;
    while (previous_index < index) : (previous_index += 1) {
        if (std.mem.eql(u8, @field(items[previous_index], field_name), value)) return true;
    }
    return false;
}

pub fn requiresApplicationPackaging(bundle_id: []const u8) bool {
    return !isReservedPlatformBundle(bundle_id) and
        !isUnsupportedCompatibilityNamespace(bundle_id);
}

pub fn isApplicationBundle(bundle_id: []const u8) bool {
    return requiresApplicationPackaging(bundle_id);
}

pub fn isReservedPlatformBundle(bundle_id: []const u8) bool {
    return std.mem.startsWith(u8, bundle_id, "zigos.") or
        std.mem.startsWith(u8, bundle_id, "svc.");
}

pub fn isUnsupportedCompatibilityNamespace(bundle_id: []const u8) bool {
    return mentionsPosix(bundle_id) or mentionsCompatNamespace(bundle_id);
}

fn validateNativeOnlyNaming(bundle: BundleManifest) ValidationError!void {
    if (isUnsupportedCompatibilityNamespace(bundle.bundle_id)) {
        return error.CompatibilityNamespaceUnsupported;
    }
    for (bundle.components) |component| {
        if (mentionsPosix(component.entry) or mentionsCompatNamespace(component.entry)) {
            return error.CompatibilityNamespaceUnsupported;
        }
    }
}

fn mentionsPosix(value: []const u8) bool {
    return std.mem.indexOf(u8, value, "posix") != null or
        std.mem.indexOf(u8, value, "POSIX") != null;
}

fn mentionsCompatNamespace(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "compat.") or
        std.mem.indexOf(u8, value, ".compat.") != null;
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

test "validate requires local AI model provenance and private AI locality" {
    try std.testing.expectError(error.AiModelDigestMissing, validate(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .locality = .local_only,
        },
    }));

    try std.testing.expectError(error.AiModelSourceMissing, validate(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .model_digest = "sha256:tiny-local",
            .locality = .local_only,
        },
    }));

    try std.testing.expectError(error.PrivateAiRequiresLocalModel, validate(.{
        .bundle_id = "app.remote-private-ai",
        .display_name = "Remote Private AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "remote-private",
            .locality = .remote_allowed,
            .private_context = true,
        },
    }));

    try validate(.{
        .bundle_id = "app.local-ai",
        .display_name = "Local AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .model_digest = "sha256:tiny-local",
            .model_source_identity = "store:zigos/local-models",
            .locality = .local_only,
            .private_context = true,
        },
    });
}

test "validate requires AI training audit and bounded context" {
    try std.testing.expectError(error.AiTrainingRequiresAudit, validate(.{
        .bundle_id = "app.training-ai",
        .display_name = "Training AI",
        .publisher = "zigos.dev",
        .ai_metadata = .{
            .model_family = "tiny-local",
            .model_digest = "sha256:tiny-local-training",
            .model_source_identity = "store:zigos/local-models",
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
            .model_digest = "sha256:tiny-local-context",
            .model_source_identity = "store:zigos/local-models",
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

test "validate requires sensitive object data to declare export delete and deletion receipts" {
    const sensitive_object = [_]PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:private-notes",
            .rights = .{ .object = .{ .object_read = true, .object_write = true } },
            .local_only = true,
            .sensitivity = .private_user_data,
            .purpose = .document_editing,
            .retention_days = 30,
        },
    };

    try std.testing.expectError(error.DataRightsExportMissing, validate(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &sensitive_object,
    }));

    try std.testing.expectError(error.DataRightsExportFormatMissing, validate(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &sensitive_object,
        .data_rights = .{
            .portable_export = true,
            .deletion_supported = true,
            .deletion_receipt_required = true,
        },
    }));

    try std.testing.expectError(error.DataRightsDeletionMissing, validate(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &sensitive_object,
        .data_rights = .{
            .portable_export = true,
            .export_format = "application/zigos-object-archive",
        },
    }));

    try std.testing.expectError(error.DataDeletionReceiptRequired, validate(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &sensitive_object,
        .data_rights = .{
            .portable_export = true,
            .deletion_supported = true,
            .export_format = "application/zigos-object-archive",
        },
    }));

    try validate(.{
        .bundle_id = "app.private-notes",
        .display_name = "Private Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &sensitive_object,
        .data_rights = .{
            .portable_export = true,
            .deletion_supported = true,
            .deletion_receipt_required = true,
            .export_format = "application/zigos-object-archive",
        },
    });
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
            .model_digest = "sha256:tiny-embed-notes",
            .model_source_identity = "store:zigos/local-models",
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

test "validate gates package supply chain reproducibility metadata" {
    try std.testing.expectError(error.ReproducibleBuildRequiresSourceArchive, validate(.{
        .bundle_id = "app.repro",
        .display_name = "Repro",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .reproducible_build = true,
            .build_recipe_digest = "sha256:recipe",
        },
    }));
    try std.testing.expectError(error.ReproducibleBuildRequiresBuildRecipe, validate(.{
        .bundle_id = "app.repro",
        .display_name = "Repro",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .reproducible_build = true,
            .source_archive_digest = "sha256:source",
        },
    }));
    try std.testing.expectError(error.TrustedBuilderRequiresIdentity, validate(.{
        .bundle_id = "app.builder",
        .display_name = "Builder",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .trusted_builder = true,
        },
    }));
    try validate(.{
        .bundle_id = "app.builder",
        .display_name = "Builder",
        .publisher = "zigos.dev",
        .supply_chain = .{
            .sbom_digest = "sha256:sbom",
            .source_archive_digest = "sha256:source",
            .build_recipe_digest = "sha256:recipe",
            .vulnerability_scan_digest = "sha256:vuln-scan",
            .build_provenance_identity = "builder:zigos/release",
            .reproducible_build = true,
            .trusted_builder = true,
        },
    });
}

test "validate gates agent delegation behind bounded audited consent" {
    try std.testing.expectError(error.AgentDelegationPurposeMissing, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .max_autonomous_actions = 4,
        },
    }));
    try std.testing.expectError(error.AgentDelegationActionBudgetMissing, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
        },
    }));
    try std.testing.expectError(error.AgentDelegationAuditRequired, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
            .max_autonomous_actions = 4,
            .audit_required = false,
        },
    }));
    try std.testing.expectError(error.AgentDelegationNeedsConfirmation, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Summarize shared documents",
            .max_autonomous_actions = 4,
            .max_remote_calls = 1,
            .user_confirmation_required = false,
        },
    }));
    try std.testing.expectError(error.AgentDelegationSessionBindingRequired, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
    }));
    try std.testing.expectError(error.AgentDelegationLocalContextRequired, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .local_context_only = false,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
    }));
    try std.testing.expectError(error.AgentDelegationContextBudgetMissing, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .kill_switch_supported = true,
        },
    }));
    try std.testing.expectError(error.AgentDelegationKillSwitchRequired, validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
            .max_autonomous_actions = 4,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .max_context_bytes = 4096,
        },
    }));
    try validate(.{
        .bundle_id = "app.agent",
        .display_name = "Agent",
        .publisher = "zigos.dev",
        .agent_delegation = .{
            .enabled = true,
            .purpose = "Organize incoming notes",
            .max_autonomous_actions = 4,
            .max_remote_calls = 0,
            .user_confirmation_required = true,
            .audit_required = true,
            .session_bound = true,
            .local_context_only = true,
            .max_context_bytes = 4096,
            .kill_switch_supported = true,
        },
    });
}

test "validate gates adaptive UI declarations behind concrete accessibility support" {
    try std.testing.expectError(error.AccessibilityKeyboardNavigationMissing, validate(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_screen_reader = true,
            .supports_reduced_motion = true,
        },
    }));

    try std.testing.expectError(error.AccessibilityScreenReaderMissing, validate(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_keyboard_navigation = true,
            .supports_reduced_motion = true,
        },
    }));

    try std.testing.expectError(error.AccessibilityReducedMotionMissing, validate(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_keyboard_navigation = true,
            .supports_screen_reader = true,
        },
    }));

    try validate(.{
        .bundle_id = "app.reader",
        .display_name = "Reader",
        .publisher = "zigos.dev",
        .accessibility = .{
            .adaptive_ui = true,
            .supports_keyboard_navigation = true,
            .supports_screen_reader = true,
            .supports_reduced_motion = true,
            .supports_high_contrast = true,
            .profile_notes = "honors user accessibility profile",
        },
    });
}

test "compatibility namespaces are rejected by native-only manifest validation" {
    try std.testing.expect(!isReservedPlatformBundle("compat.posix"));
    try std.testing.expect(isUnsupportedCompatibilityNamespace("compat.posix"));
    try std.testing.expect(!requiresApplicationPackaging("compat.posix"));
    try std.testing.expectError(error.CompatibilityNamespaceUnsupported, validateApplicationPackaging(.{
        .bundle_id = "compat.posix",
        .display_name = "Compat POSIX",
        .publisher = "zigos.dev",
    }));
    try std.testing.expectError(error.CompatibilityNamespaceUnsupported, validate(.{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .components = &.{.{ .id = "main", .entry = "compat.posix.main" }},
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
