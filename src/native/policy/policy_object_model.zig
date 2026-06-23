// Policy model: scopes, decision reasons, request records, and the PolicyObject
// itself. Extracted from policy_object.zig so the policy data model is separate
// from the Directory container/index logic that operates on it.
const std = @import("std");
const manifest = @import("manifest.zig");
const principal = @import("../core/principal.zig");

pub const MAX_ALLOW_LIST: usize = 8;
pub const MAX_LABEL_BYTES: usize = 64;

pub const Scope = enum(u8) {
    user,
    device,
    workspace,
    organization,
};

pub const InstallSourceMode = enum(u8) {
    any_signed,
    trusted_sources,
    platform_store_only,
};

pub const NetworkEgressMode = enum(u8) {
    inherit,
    none,
    local_only,
    allow_list,
    unrestricted,
};

pub const SubjectSet = struct {
    user_id: ?u64 = null,
    device_id: ?u64 = null,
    workspace_id: ?u64 = null,
    organization_id: ?u64 = null,
};

pub const DecisionReason = enum(u8) {
    none,
    unsigned_policy,
    install_source_denied,
    network_egress_denied,
    sync_destination_denied,
    removable_storage_denied,
    screen_capture_denied,
    clipboard_denied,
    camera_denied,
    microphone_denied,
    location_denied,
    contacts_denied,
    sensor_denied,
    peer_ipc_denied,
    capture_foreground_denied,
    capture_indicator_denied,
    capture_background_denied,
    capture_lease_denied,
    capture_sample_budget_denied,
    remote_ai_denied,
    ai_training_denied,
    ai_context_denied,
    ai_model_measurement_denied,
    ai_model_source_denied,
    ai_model_staleness_denied,
    session_hardware_denied,
    session_device_posture_denied,
    session_unlock_stale,
    session_primary_device_denied,
    package_sbom_denied,
    package_reproducibility_denied,
    package_builder_denied,
    package_vulnerability_scan_denied,
    agent_delegation_denied,
    agent_action_budget_denied,
    agent_remote_call_denied,
    agent_confirmation_required,
    agent_audit_required,
    agent_session_binding_denied,
    agent_context_scope_denied,
    agent_context_budget_denied,
    agent_kill_switch_denied,
    agent_plan_visibility_required,
    private_egress_budget_denied,
    data_export_denied,
    data_deletion_denied,
    data_deletion_receipt_denied,
    object_backup_denied,
    object_restore_denied,
    object_backup_encryption_denied,
    object_backup_recovery_key_denied,
    object_restore_device_trust_denied,
    object_backup_size_denied,
    object_restore_staleness_denied,
    semantic_memory_denied,
    semantic_memory_remote_model_denied,
    semantic_memory_encryption_denied,
    semantic_memory_redaction_denied,
    semantic_query_budget_denied,
    credential_assertion_denied,
    credential_password_fallback_denied,
    credential_phishing_resistance_denied,
    credential_hardware_denied,
    credential_unlock_denied,
    credential_unlock_stale,
    secret_vault_denied,
    secret_hardware_denied,
    secret_raw_export_denied,
    secret_lease_denied,
    task_lifecycle_denied,
    task_lifecycle_checkpoint_required,
    attention_quiet_denied,
    attention_visible_budget_denied,
    attention_interruption_budget_denied,
    attention_critical_denied,
    accessibility_adaptive_ui_denied,
    accessibility_screen_reader_denied,
    accessibility_keyboard_navigation_denied,
    accessibility_reduced_motion_denied,
    accessibility_high_contrast_denied,
    background_duration_denied,
    background_cpu_denied,
    background_memory_denied,
    background_network_denied,
    background_visibility_denied,
    permission_retention_denied,
    permission_lease_denied,
    retention_denied,
    audit_export_required,
};

pub const PolicyDecision = struct {
    allowed: bool,
    reason: DecisionReason = .none,
    blocking_scope: ?Scope = null,
    blocking_policy_id: u64 = 0,
    blocking_generation: u32 = 0,
};

pub const CreateRequest = struct {
    scope: Scope,
    subject_id: u64,
    issuer: principal.PrincipalId,
    label: []const u8,
    install_source_mode: InstallSourceMode = .any_signed,
    allowed_install_sources: []const []const u8 = &.{},
    network_egress_mode: NetworkEgressMode = .inherit,
    allowed_network_destinations: []const []const u8 = &.{},
    allowed_sync_destinations: []const []const u8 = &.{},
    removable_storage_allowed: bool = false,
    screen_capture_allowed: bool = false,
    clipboard_allowed: bool = false,
    camera_allowed: bool = false,
    microphone_allowed: bool = false,
    location_allowed: bool = false,
    contacts_allowed: bool = false,
    sensors_allowed: bool = false,
    peer_ipc_allowed: bool = false,
    remote_ai_allowed: bool = false,
    ai_training_allowed: bool = false,
    max_ai_context_bytes: usize = 0,
    require_ai_model_measurement: bool = false,
    require_trusted_ai_model_source: bool = false,
    max_ai_model_age_days: u16 = 0,
    require_hardware_backed_session: bool = false,
    require_platform_backed_device_session: bool = false,
    require_primary_device_session: bool = false,
    max_session_unlock_age_ticks: u64 = 0,
    require_package_sbom: bool = false,
    require_reproducible_package_build: bool = false,
    require_trusted_package_builder: bool = false,
    require_vulnerability_scan: bool = false,
    agent_delegation_allowed: bool = false,
    max_agent_actions_per_session: u16 = 0,
    max_agent_remote_calls_per_session: u16 = 0,
    require_agent_user_confirmation: bool = true,
    require_agent_audit: bool = true,
    require_agent_session_binding: bool = false,
    require_agent_local_context: bool = false,
    max_agent_context_bytes: usize = 0,
    min_agent_delegation_generation: u32 = 0,
    require_agent_visible_plan: bool = false,
    max_remote_private_egress_bytes: usize = 0,
    data_export_allowed: bool = false,
    data_deletion_allowed: bool = false,
    require_data_deletion_receipt: bool = false,
    max_data_export_bytes: usize = 0,
    object_backup_allowed: bool = false,
    object_restore_allowed: bool = false,
    require_encrypted_object_backup: bool = true,
    require_backup_recovery_key: bool = true,
    require_restore_device_trust: bool = true,
    max_object_backup_bytes: usize = 0,
    max_object_restore_age_days: u16 = 0,
    semantic_memory_allowed: bool = false,
    require_local_semantic_model: bool = true,
    require_encrypted_semantic_index: bool = true,
    require_redacted_semantic_snippets: bool = true,
    max_semantic_query_bytes: usize = 0,
    credential_assertions_allowed: bool = false,
    deny_credential_password_fallback: bool = true,
    require_phishing_resistant_credential: bool = true,
    require_hardware_backed_credential: bool = false,
    require_local_credential_unlock: bool = true,
    max_credential_unlock_age_ticks: u64 = 0,
    secret_vault_allowed: bool = false,
    require_hardware_backed_secrets: bool = true,
    deny_secret_raw_export: bool = true,
    max_secret_handle_lease_ticks: u64 = 0,
    task_lifecycle_allowed: bool = false,
    require_lifecycle_checkpoint_before_terminate: bool = true,
    quiet_until_tick: u64 = 0,
    max_visible_notifications: u16 = 0,
    max_interruptive_notifications: u16 = 0,
    allow_critical_interruption: bool = true,
    require_adaptive_ui: bool = false,
    require_screen_reader_support: bool = false,
    require_keyboard_navigation: bool = false,
    require_reduced_motion_support: bool = false,
    require_high_contrast_support: bool = false,
    max_background_duration_seconds: u32 = 0,
    max_background_cpu_time_ticks: u64 = 0,
    max_background_memory_bytes: usize = 0,
    max_background_shared_memory_bytes: usize = 0,
    allow_remote_background_network: bool = false,
    require_visible_background_activity: bool = false,
    max_sensitive_retention_days: u16 = 0,
    max_permission_lease_ticks: u64 = 0,
    require_sensitive_permission_lease: bool = false,
    require_sensitive_capture_foreground: bool = true,
    require_capture_indicator: bool = true,
    allow_background_capture: bool = false,
    max_sensitive_capture_lease_ticks: u64 = 0,
    max_sensitive_capture_samples: u32 = 0,
    retention_days: u16 = 0,
    audit_export_required: bool = false,
};

pub const RetentionAuditRequest = struct {
    retention_days: u16,
    audit_export_present: bool = false,
};

pub const AiUseRequest = struct {
    remote_model: bool = false,
    training_user_content: bool = false,
    context_bytes: usize = 0,
    local_model_measured: bool = true,
    model_source_trusted: bool = true,
    model_age_days: u16 = 0,
};

pub const SessionTrustRequest = struct {
    hardware_backed_credential: bool = false,
    device_platform_backed: bool = false,
    primary_device_assertion: bool = false,
    unlock_age_ticks: u64 = 0,
};

pub const SensitiveEgressRequest = struct {
    sensitivity: manifest.DataSensitivity = .internal_data,
    remote_bytes: usize = 0,
};

pub const DataRightsOperation = enum(u8) {
    portable_export,
    delete,
};

pub const PackageProvenanceRequest = struct {
    sbom_present: bool = false,
    source_archive_present: bool = false,
    build_recipe_present: bool = false,
    reproducible_build: bool = false,
    trusted_builder: bool = false,
    vulnerability_scan_present: bool = false,
};

pub const DataRightsRequest = struct {
    operation: DataRightsOperation,
    sensitivity: manifest.DataSensitivity = .internal_data,
    bytes: usize = 0,
    deletion_receipt_present: bool = false,
};

pub const ObjectResilienceOperation = enum(u8) {
    backup,
    restore,
    migrate,
};

pub const ObjectResilienceRequest = struct {
    operation: ObjectResilienceOperation,
    sensitivity: manifest.DataSensitivity = .internal_data,
    bytes: usize = 0,
    encrypted: bool = false,
    recovery_key_present: bool = false,
    device_trust_verified: bool = false,
    restore_age_days: u16 = 0,
};

pub const SemanticMemoryRequest = struct {
    sensitivity: manifest.DataSensitivity = .internal_data,
    query_bytes: usize = 0,
    local_model: bool = false,
    encrypted_index: bool = false,
    redacted_snippets: bool = false,
};

pub const CredentialAssertionRequest = struct {
    password_fallback: bool = false,
    phishing_resistant: bool = false,
    hardware_backed: bool = false,
    local_unlock_verified: bool = false,
    unlock_age_ticks: u64 = 0,
};

pub const SecretVaultOperation = enum(u8) {
    import,
    lend,
    export_raw,
    rotate,
    revoke,
};

pub const SecretVaultRequest = struct {
    operation: SecretVaultOperation,
    hardware_backed: bool = false,
    raw_export: bool = false,
    lease_ticks: u64 = 0,
};

pub const AttentionRequest = struct {
    now_tick: u64 = 0,
    visible_notifications: u16 = 0,
    interruptive_notifications: u16 = 0,
    requests_interruption: bool = false,
    critical: bool = false,
};

pub const LifecycleOperation = enum(u8) {
    suspend_task,
    resume_task,
    terminate_task,
};

pub const LifecycleRequest = struct {
    operation: LifecycleOperation,
    checkpoint_present: bool = false,
};

pub const AccessibilityRequest = struct {
    adaptive_ui: bool = false,
    screen_reader_supported: bool = false,
    keyboard_navigation: bool = false,
    reduced_motion_supported: bool = false,
    high_contrast_supported: bool = false,
};

pub const BackgroundActivityRequest = struct {
    expected_duration_seconds: u32 = 0,
    cpu_time_ticks: u64 = 0,
    memory_bytes: usize = 0,
    shared_memory_bytes: usize = 0,
    network: manifest.BackgroundNetworkMode = .none,
    visibility: manifest.BackgroundVisibility = .status_only,
};

pub const AgentDelegationRequest = struct {
    enabled: bool = false,
    autonomous_actions: u16 = 0,
    remote_calls: u16 = 0,
    user_confirmed: bool = false,
    audit_enabled: bool = false,
    session_bound: bool = false,
    local_context_only: bool = true,
    context_bytes: usize = 0,
    delegation_generation: u32 = 0,
    user_visible_plan: bool = false,
};

pub const PermissionUseRequest = struct {
    kind: manifest.PermissionKind,
    sensitivity: manifest.DataSensitivity = .internal_data,
    retention_days: u16 = 0,
    lease_ticks: u64 = 0,
};

pub const SensitiveCaptureRequest = struct {
    kind: manifest.PermissionKind,
    lease_ticks: u64 = 0,
    sample_budget: u32 = 0,
    foreground_session: bool = false,
    visible_indicator: bool = false,
    background: bool = false,
};

pub const PolicyObject = struct {
    id: u64,
    generation: u32,
    revoked: bool,
    scope: Scope,
    subject_id: u64,
    issuer: principal.PrincipalId,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    install_source_mode: InstallSourceMode,
    allowed_install_source_count: usize,
    allowed_install_sources: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_install_source_lens: [MAX_ALLOW_LIST]usize,
    network_egress_mode: NetworkEgressMode,
    allowed_network_destination_count: usize,
    allowed_network_destinations: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_network_destination_lens: [MAX_ALLOW_LIST]usize,
    allowed_sync_destination_count: usize,
    allowed_sync_destinations: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_sync_destination_lens: [MAX_ALLOW_LIST]usize,
    removable_storage_allowed: bool,
    screen_capture_allowed: bool,
    clipboard_allowed: bool,
    camera_allowed: bool,
    microphone_allowed: bool,
    location_allowed: bool,
    contacts_allowed: bool,
    sensors_allowed: bool,
    peer_ipc_allowed: bool,
    remote_ai_allowed: bool,
    ai_training_allowed: bool,
    max_ai_context_bytes: usize,
    require_ai_model_measurement: bool,
    require_trusted_ai_model_source: bool,
    max_ai_model_age_days: u16,
    require_hardware_backed_session: bool,
    require_platform_backed_device_session: bool,
    require_primary_device_session: bool,
    max_session_unlock_age_ticks: u64,
    require_package_sbom: bool,
    require_reproducible_package_build: bool,
    require_trusted_package_builder: bool,
    require_vulnerability_scan: bool,
    agent_delegation_allowed: bool,
    max_agent_actions_per_session: u16,
    max_agent_remote_calls_per_session: u16,
    require_agent_user_confirmation: bool,
    require_agent_audit: bool,
    require_agent_session_binding: bool,
    require_agent_local_context: bool,
    max_agent_context_bytes: usize,
    min_agent_delegation_generation: u32,
    require_agent_visible_plan: bool,
    max_remote_private_egress_bytes: usize,
    data_export_allowed: bool,
    data_deletion_allowed: bool,
    require_data_deletion_receipt: bool,
    max_data_export_bytes: usize,
    object_backup_allowed: bool,
    object_restore_allowed: bool,
    require_encrypted_object_backup: bool,
    require_backup_recovery_key: bool,
    require_restore_device_trust: bool,
    max_object_backup_bytes: usize,
    max_object_restore_age_days: u16,
    semantic_memory_allowed: bool,
    require_local_semantic_model: bool,
    require_encrypted_semantic_index: bool,
    require_redacted_semantic_snippets: bool,
    max_semantic_query_bytes: usize,
    credential_assertions_allowed: bool,
    deny_credential_password_fallback: bool,
    require_phishing_resistant_credential: bool,
    require_hardware_backed_credential: bool,
    require_local_credential_unlock: bool,
    max_credential_unlock_age_ticks: u64,
    secret_vault_allowed: bool,
    require_hardware_backed_secrets: bool,
    deny_secret_raw_export: bool,
    max_secret_handle_lease_ticks: u64,
    task_lifecycle_allowed: bool,
    require_lifecycle_checkpoint_before_terminate: bool,
    quiet_until_tick: u64,
    max_visible_notifications: u16,
    max_interruptive_notifications: u16,
    allow_critical_interruption: bool,
    require_adaptive_ui: bool,
    require_screen_reader_support: bool,
    require_keyboard_navigation: bool,
    require_reduced_motion_support: bool,
    require_high_contrast_support: bool,
    max_background_duration_seconds: u32,
    max_background_cpu_time_ticks: u64,
    max_background_memory_bytes: usize,
    max_background_shared_memory_bytes: usize,
    allow_remote_background_network: bool,
    require_visible_background_activity: bool,
    max_sensitive_retention_days: u16,
    max_permission_lease_ticks: u64,
    require_sensitive_permission_lease: bool,
    require_sensitive_capture_foreground: bool,
    require_capture_indicator: bool,
    allow_background_capture: bool,
    max_sensitive_capture_lease_ticks: u64,
    max_sensitive_capture_samples: u32,
    retention_days: u16,
    audit_export_required: bool,
    signature: manifest.Signature,

    pub fn labelSlice(self: *const PolicyObject) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn allowsInstallSource(self: *const PolicyObject, source_identity: []const u8) bool {
        return switch (self.install_source_mode) {
            .any_signed => true,
            .trusted_sources => listContains(
                self.allowed_install_sources[0..self.allowed_install_source_count],
                self.allowed_install_source_lens[0..self.allowed_install_source_count],
                source_identity,
            ),
            .platform_store_only => std.mem.startsWith(u8, source_identity, "store:") or listContains(
                self.allowed_install_sources[0..self.allowed_install_source_count],
                self.allowed_install_source_lens[0..self.allowed_install_source_count],
                source_identity,
            ),
        };
    }

    pub fn packageProvenanceDenial(self: *const PolicyObject, request: PackageProvenanceRequest) ?DecisionReason {
        if (self.require_package_sbom and !request.sbom_present) return .package_sbom_denied;
        if (self.require_reproducible_package_build and
            (!request.reproducible_build or !request.source_archive_present or !request.build_recipe_present))
        {
            return .package_reproducibility_denied;
        }
        if (self.require_trusted_package_builder and !request.trusted_builder) return .package_builder_denied;
        if (self.require_vulnerability_scan and !request.vulnerability_scan_present) return .package_vulnerability_scan_denied;
        return null;
    }

    pub fn allowsPackageProvenance(self: *const PolicyObject, request: PackageProvenanceRequest) bool {
        return self.packageProvenanceDenial(request) == null;
    }

    pub fn allowsNetworkDestination(self: *const PolicyObject, destination: []const u8) bool {
        return switch (self.network_egress_mode) {
            .inherit, .unrestricted => true,
            .none => false,
            .local_only => isLocalDestination(destination),
            .allow_list => listContains(
                self.allowed_network_destinations[0..self.allowed_network_destination_count],
                self.allowed_network_destination_lens[0..self.allowed_network_destination_count],
                destination,
            ),
        };
    }

    pub fn allowsSyncDestination(self: *const PolicyObject, destination: []const u8) bool {
        if (self.allowed_sync_destination_count == 0) {
            return switch (self.network_egress_mode) {
                .inherit, .unrestricted => true,
                .local_only => isLocalDestination(destination),
                .none, .allow_list => false,
            };
        }
        return listContains(
            self.allowed_sync_destinations[0..self.allowed_sync_destination_count],
            self.allowed_sync_destination_lens[0..self.allowed_sync_destination_count],
            destination,
        );
    }
};

pub const Error = error{
    InstallSourceTooLong,
    LabelTooLong,
    NetworkDestinationTooLong,
    PolicyAlreadyRevoked,
    PolicyNotFound,
    PolicyTableFull,
    SyncDestinationTooLong,
    TooManyInstallSources,
    TooManyNetworkDestinations,
    TooManySyncDestinations,
};

fn listContains(items: []const [MAX_LABEL_BYTES]u8, lens: []const usize, needle: []const u8) bool {
    for (items, 0..) |item, index| {
        if (std.mem.eql(u8, item[0..lens[index]], needle)) return true;
    }
    return false;
}

fn isLocalDestination(destination: []const u8) bool {
    return std.mem.startsWith(u8, destination, "local:") or
        std.mem.startsWith(u8, destination, "lan.") or
        std.mem.eql(u8, destination, "local-network");
}
