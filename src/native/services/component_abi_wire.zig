const crypto_hash = @import("../core/crypto_hash.zig");

pub const MAGIC: u32 = 0x54434142;
pub const VERSION: u16 = 4;

pub const WireHeader = extern struct {
    correlation_id: u64,
    subject_task_id: u64,
    magic: u32 = MAGIC,
    abi_version: u16 = VERSION,
    operation: u16,
};

pub const ServiceRegisterRequestWire = extern struct {
    header: WireHeader,
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    interface_id: u16,
    flags: u16,
    _reserved: u32 = 0,
};

pub const ServiceConnectionRequestWire = extern struct {
    header: WireHeader,
    interface_id: u16,
    _reserved: [6]u8 = [_]u8{0} ** 6,
};

pub const TaskDescribeRequestWire = extern struct {
    header: WireHeader,
    task_id: u64,
};

pub const WorkspacePutVersionRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    object_id: u64,
    object_type: u16,
    payload_len: u32,
};

pub const WorkspaceResolveRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    path_len: u16,
    _reserved: u16 = 0,
};

pub const IndexUpsertRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    title_len: u16,
    body_len: u16,
    sensitivity: u16,
    flags: u16,
};

pub const IndexQueryRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    query_len: u16,
    max_results: u16,
};

pub const SemanticIndexQueryRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    query_len: u16,
    max_results: u16,
    flags: u16,
};

pub const SyncDeviceEnrollRequestWire = extern struct {
    header: WireHeader,
    user_id: u64,
    device_id: u64,
    label_len: u16,
    flags: u16,
};

pub const SyncWorkspaceReplicateRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    from_device_id: u64,
    to_device_id: u64,
    transport_mode: u16,
    flags: u16,
};

pub const SyncConflictReviewRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    device_id: u64,
    object_id: u64,
};

pub const SyncConflictResolveRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    device_id: u64,
    object_id: u64,
    decision: u16,
    _reserved: u16 = 0,
};

pub const SyncTransportFrameRequestWire = extern struct {
    header: WireHeader,
    frame_id: u64,
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    semantic: u16,
    flags: u16,
};

pub const NetworkAuthorizeRequestWire = extern struct {
    header: WireHeader,
    policy_id: u64,
    destination_len: u16,
    flags: u16,
};

pub const NetworkOpenSessionRequestWire = extern struct {
    header: WireHeader,
    policy_id: u64,
    capability_id: u64,
    remote_bytes: u64,
    expires_at_tick: u64,
    destination_len: u16,
    sensitivity: u16,
    flags: u16,
    _reserved: u16 = 0,
};

pub const NetworkRecordTransferRequestWire = extern struct {
    header: WireHeader,
    session_id: u64,
    expected_policy_id: u64,
    expected_capability_id: u64,
    bytes: u64,
    flags: u16,
    _reserved: u16 = 0,
};

pub const NetworkRevokeSessionRequestWire = extern struct {
    header: WireHeader,
    session_id: u64,
    expected_policy_id: u64,
    expected_capability_id: u64,
    reason: u16,
    flags: u16,
};

pub const PolicyAuthorizeRequestWire = extern struct {
    header: WireHeader,
    requester_task_id: u64,
    permission_kind: u16,
    resource_len: u16,
};

pub const PackageInstallRequestWire = extern struct {
    header: WireHeader,
    bundle_digest: crypto_hash.Digest,
    bundle_id_len: u16,
    source_identity_len: u16,
    schema_version: u32,
    flags: u32,
};

pub const PackageUpdateRequestWire = extern struct {
    header: WireHeader,
    bundle_digest: crypto_hash.Digest,
    bundle_id_len: u16,
    source_identity_len: u16,
    from_schema_version: u32,
    to_schema_version: u32,
    flags: u16,
};

pub const PackageRollbackRequestWire = extern struct {
    header: WireHeader,
    expected_active_digest: crypto_hash.Digest,
    bundle_id_len: u16,
    _reserved: u16 = 0,
};

pub const PackageRemoveRequestWire = extern struct {
    header: WireHeader,
    expected_active_digest: crypto_hash.Digest,
    bundle_id_len: u16,
    reason: u16,
    flags: u32,
    receipt_id: u64,
};

pub const AiAuthorizeRequestWire = extern struct {
    header: WireHeader,
    model_family_len: u16,
    context_bytes: u32,
    flags: u16,
};

pub const AiRunLocalRequestWire = extern struct {
    header: WireHeader,
    model_family_len: u16,
    prompt_bytes: u32,
    context_bytes: u32,
    flags: u16,
};

pub const AiModelRegisterRequestWire = extern struct {
    header: WireHeader,
    model_digest_len: u16,
    source_identity_len: u16,
    model_family_len: u16,
    flags: u16,
};

pub const AiModelAttestRequestWire = extern struct {
    header: WireHeader,
    model_id: u64,
    measurement_len: u16,
    source_identity_len: u16,
    model_age_days: u16,
    flags: u16,
};

pub const AiModelRevokeRequestWire = extern struct {
    header: WireHeader,
    model_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const PrivacyAuthorizeEgressRequestWire = extern struct {
    header: WireHeader,
    policy_id: u64,
    remote_bytes: u64,
    sensitivity: u16,
    flags: u16,
};

pub const PrivacyQueryBudgetRequestWire = extern struct {
    header: WireHeader,
    window_ticks: u64,
    sensitivity: u16,
    _reserved: u16 = 0,
};

pub const DiagnosticsPrepareExportRequestWire = extern struct {
    header: WireHeader,
    max_bytes: u32,
    include_protected_content: u32,
};

pub const DiagnosticsShareRemoteRequestWire = extern struct {
    header: WireHeader,
    user_opted_in: u32,
    include_protected_content: u32,
};

pub const ConsentRecordRequestWire = extern struct {
    header: WireHeader,
    receipt_id: u64,
    permission_kind: u16,
    purpose: u16,
    retention_days: u16,
    _reserved: u16 = 0,
};

pub const ConsentRevokeRequestWire = extern struct {
    header: WireHeader,
    receipt_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const PermissionLeaseIssueRequestWire = extern struct {
    header: WireHeader,
    permission_kind: u16,
    sensitivity: u16,
    lease_ticks: u64,
};

pub const PermissionLeaseRenewRequestWire = extern struct {
    header: WireHeader,
    lease_id: u64,
    lease_ticks: u64,
};

pub const PermissionLeaseExpireRequestWire = extern struct {
    header: WireHeader,
    lease_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const DataExportPrepareRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    max_bytes: u64,
    sensitivity: u16,
    format_len: u16,
};

pub const DataDeleteRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    object_id: u64,
    reason: u16,
    require_receipt: u16,
};

pub const DataDeleteReceiptRequestWire = extern struct {
    header: WireHeader,
    receipt_id: u64,
    object_id: u64,
    erased_versions: u32,
    retained_tombstone: u32,
};

pub const IdentitySessionAuthorizeRequestWire = extern struct {
    header: WireHeader,
    credential_id: u64,
    unlock_age_ticks: u64,
    device_trust_generation: u32,
    flags: u32,
};

pub const IdentitySessionStepUpRequestWire = extern struct {
    header: WireHeader,
    credential_id: u64,
    challenge_len: u16,
    method: u16,
};

pub const IdentitySessionRevokeRequestWire = extern struct {
    header: WireHeader,
    session_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const IdentityCredentialRegisterRequestWire = extern struct {
    header: WireHeader,
    owner_id: u64,
    device_id: u64,
    relying_party_id_len: u16,
    label_len: u16,
    flags: u16,
    _reserved: u16 = 0,
};

pub const IdentityCredentialAssertRequestWire = extern struct {
    header: WireHeader,
    credential_id: u64,
    device_id: u64,
    relying_party_id_len: u16,
    origin_len: u16,
    challenge_len: u16,
    flags: u16,
};

pub const IdentityCredentialRecoverRequestWire = extern struct {
    header: WireHeader,
    credential_id: u64,
    recovery_device_id: u64,
    relying_party_id_len: u16,
    challenge_len: u16,
    approval_count: u16,
    flags: u16,
};

pub const IdentityCredentialRevokeRequestWire = extern struct {
    header: WireHeader,
    credential_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const AgentAuthorizeRequestWire = extern struct {
    header: WireHeader,
    autonomous_actions: u16,
    remote_calls: u16,
    flags: u16,
    purpose_len: u16,
};

pub const AgentRecordActionRequestWire = extern struct {
    header: WireHeader,
    delegation_id: u64,
    expected_subject_serial: u64,
    expected_task_id: u64,
    expected_generation: u32,
    action_count: u16,
    remote_call_count: u16,
    expected_subject_kind: u16,
    flags: u16,
    detail_len: u16,
    _reserved: u16 = 0,
};

pub const AgentRevokeRequestWire = extern struct {
    header: WireHeader,
    delegation_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const AgentBindSessionRequestWire = extern struct {
    header: WireHeader,
    session_id: u64,
    delegation_generation: u32,
    max_context_bytes: u32,
    flags: u32,
};

pub const AgentKillSwitchRequestWire = extern struct {
    header: WireHeader,
    minimum_generation: u32,
    reason: u16,
    _reserved: u16 = 0,
};

pub const AccessibilityProfileGetRequestWire = extern struct {
    header: WireHeader,
    subject_id: u64,
};

pub const AccessibilityProfileApplyRequestWire = extern struct {
    header: WireHeader,
    subject_id: u64,
    flags: u32,
    profile_notes_len: u16,
    _reserved: u16 = 0,
};

pub const AccessibilityProfileAuditRequestWire = extern struct {
    header: WireHeader,
    subject_id: u64,
    flags: u32,
    decision_reason: u16,
    _reserved: u16 = 0,
};

pub const BackgroundAuthorizeRequestWire = extern struct {
    header: WireHeader,
    task_id: u64,
    duration_seconds: u32,
    cpu_time_ticks: u32,
    memory_bytes: u32,
    shared_memory_bytes: u32,
    network_mode: u16,
    visibility: u16,
};

pub const BackgroundRecordRequestWire = extern struct {
    header: WireHeader,
    task_id: u64,
    record_id: u64,
    duration_seconds: u32,
    decision_reason: u16,
    flags: u16,
};

pub const BackgroundCompleteRequestWire = extern struct {
    header: WireHeader,
    record_id: u64,
    expected_task_id: u64,
    completed_tick: u64,
    expected_background_task_len: u16,
    expected_trigger: u16,
    result_code: u16,
    flags: u16 = 0,
};

pub const ServiceRegisterResponseWire = extern struct {
    accepted: u32,
};

pub const WorkspacePutVersionResponseWire = extern struct {
    object_id: u64,
    version_id: u64,
};

pub const WorkspaceResolveResponseWire = extern struct {
    object_id: u64,
    version_id: u64,
    object_type: u16,
};

pub const IndexResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    result_count: u16,
    top_object_id: u64,
    top_version_id: u64,
    index_generation: u64,
};

pub const SyncResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    selected_entry_count: u16,
    conflict_count: u16,
    transport_frame_count: u16,
    flags: u16,
    latest_frame_id: u64,
};

pub const NetworkAuthorizeResponseWire = extern struct {
    allowed: u32,
    reason: u16,
};

pub const NetworkSessionResponseWire = extern struct {
    allowed: u32,
    reason: u16,
    flags: u16,
    session_id: u64,
    remaining_bytes: u64,
    expires_at_tick: u64,
};

pub const PolicyAuthorizeResponseWire = extern struct {
    allowed: u32,
    denial_reason: u16,
};

pub const PackageLifecycleResponseWire = extern struct {
    installed_new: u32,
    updated_existing: u32,
    permissions_changed: u32,
    rollback_available: u32,
    removed_existing: u32,
    removed_revision_count: u32,
    deletion_receipt_id: u64,
    removed_bundle_digest: crypto_hash.Digest,
};

pub const AiAuthorizeResponseWire = extern struct {
    allowed: u32,
    reason: u16,
    max_context_bytes: u32,
};

pub const AiRunLocalResponseWire = extern struct {
    accepted: u32,
    output_bytes: u32,
    local_model: u32,
};

pub const AiModelRegistryResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    model_id: u64,
    expires_at_tick: u64,
};

pub const PrivacyAuthorizeEgressResponseWire = extern struct {
    allowed: u32,
    reason: u16,
    _reserved: u16 = 0,
    remaining_bytes: u64,
};

pub const PrivacyQueryBudgetResponseWire = extern struct {
    remaining_bytes: u64,
    reset_tick: u64,
};

pub const DiagnosticsExportResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    export_bytes: u32,
};

pub const ConsentReceiptResponseWire = extern struct {
    accepted: u32,
    receipt_id: u64,
};

pub const PermissionLeaseResponseWire = extern struct {
    accepted: u32,
    lease_id: u64,
    expires_at_tick: u64,
};

pub const DataRightsResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    receipt_id: u64,
    bytes_ready: u64,
};

pub const IdentitySessionResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    session_id: u64,
    expires_at_tick: u64,
};

pub const IdentityCredentialResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    flags: u16,
    credential_id: u64,
    credential_generation: u32,
};

pub const AgentDelegationResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    delegation_id: u64,
    remaining_actions: u16,
    remaining_remote_calls: u16,
};

pub const AccessibilityProfileResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    flags: u32,
    profile_generation: u64,
};

pub const BackgroundActivityResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    record_id: u64,
    reserved_until_tick: u64,
};

pub const PasteboardOfferRequestWire = extern struct {
    header: WireHeader,
    destination_subject_serial: u64,
    destination_task_id: u64,
    user_gesture_id: u64,
    foreground_session_id: u64,
    expires_at_ticks: u64,
    payload_len: u32,
    destination_subject_kind: u16,
    purpose_len: u16,
    flags: u16,
};

pub const PasteboardReadRequestWire = extern struct {
    header: WireHeader,
    token_id: u64,
    destination_task_id: u64,
    user_gesture_id: u64,
    foreground_session_id: u64,
    expected_purpose_len: u16,
    flags: u16,
};

pub const PasteboardRevokeRequestWire = extern struct {
    header: WireHeader,
    token_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const PasteboardResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    token_id: u64,
    payload_len: u32,
    flags: u32,
};

pub const ObjectBackupPrepareRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    object_id: u64,
    restore_device_id: u64,
    bytes: u64,
    sensitivity: u16,
    flags: u16,
};

pub const ObjectRestoreAuthorizeRequestWire = extern struct {
    header: WireHeader,
    snapshot_id: u64,
    destination_device_id: u64,
    restore_age_days: u16,
    flags: u16,
};

pub const ObjectBackupRevokeRequestWire = extern struct {
    header: WireHeader,
    snapshot_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const ObjectResilienceResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    snapshot_id: u64,
    bytes: u64,
    flags: u32,
};

pub const CaptureStartRequestWire = extern struct {
    header: WireHeader,
    device_id: u64,
    foreground_session_id: u64,
    user_gesture_id: u64,
    lease_ticks: u64,
    sample_budget: u32,
    kind: u16,
    flags: u16,
};

pub const CaptureSampleRequestWire = extern struct {
    header: WireHeader,
    session_id: u64,
    expected_device_id: u64,
    expected_foreground_session_id: u64,
    bytes: u64,
    expected_kind: u16,
    flags: u16,
};

pub const CaptureStopRequestWire = extern struct {
    header: WireHeader,
    session_id: u64,
    expected_device_id: u64,
    expected_foreground_session_id: u64,
    reason: u16,
    expected_kind: u16,
    flags: u16,
    _reserved: u16 = 0,
};

pub const CaptureResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    session_id: u64,
    samples_remaining: u32,
    flags: u32,
};

pub const AttentionPostRequestWire = extern struct {
    header: WireHeader,
    notification_task_id: u64,
    expires_at_ticks: u64,
    detail_len: u16,
    reason: u16,
    urgency: u16,
    suppression_policy: u16,
    flags: u32,
};

pub const AttentionDismissRequestWire = extern struct {
    header: WireHeader,
    notification_id: u64,
    expected_source_serial: u64,
    expected_notification_task_id: u64,
    expected_source_kind: u16,
    reason: u16,
    flags: u16 = 0,
};

pub const AttentionQueryRequestWire = extern struct {
    header: WireHeader,
    now_ticks: u64,
    flags: u32,
};

pub const AttentionResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    active_visible: u16,
    active_interruptions: u16,
    _reserved: u16 = 0,
    notification_id: u64,
    flags: u32,
};

pub const LifecycleControlRequestWire = extern struct {
    header: WireHeader,
    target_task_id: u64,
    target_owner_serial: u64,
    checkpoint_id: u64,
    target_owner_kind: u16,
    reason: u16,
    flags: u16,
    _reserved: u16 = 0,
};

pub const LifecycleControlResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    state: u16,
    task_id: u64,
    flags: u32,
};

pub const PersonalContextLeaseRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    max_query_bytes: u64,
    expires_at_tick: u64,
    sensitivity: u16,
    flags: u16,
};

pub const PersonalContextQueryRequestWire = extern struct {
    header: WireHeader,
    lease_id: u64,
    workspace_id: u64,
    query_bytes: u64,
    flags: u32,
};

pub const PersonalContextRevokeRequestWire = extern struct {
    header: WireHeader,
    lease_id: u64,
    reason: u16,
    _reserved: u16 = 0,
};

pub const PersonalContextResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    flags: u16,
    result_count: u16,
    receipt_privacy_flags: u16,
    receipt_max_pack_sensitivity: u16,
    lease_revocation_generation: u32,
    top_score: u16,
    top_title_hits: u16,
    top_body_hits: u16,
    top_sensitivity: u16,
    lease_id: u64,
    receipt_id: u64,
    receipt_index_generation: u64,
    remaining_bytes: u64,
    receipt_issued_at_tick: u64,
    expires_at_tick: u64,
    top_object_id: u64,
    top_version_id: u64,
    top_title_fingerprint: u64,
    request_fingerprint: crypto_hash.Digest,
    query_fingerprint: crypto_hash.Digest,
    pack_digest: crypto_hash.Digest,
    receipt_digest: crypto_hash.Digest,
};

pub const SecretImportRequestWire = extern struct {
    header: WireHeader,
    owner_serial: u64,
    label_len: u16,
    raw_len: u16,
    flags: u16,
    _reserved: u16 = 0,
};

pub const SecretLendRequestWire = extern struct {
    header: WireHeader,
    secret_id: u64,
    holder_serial: u64,
    lease_ticks: u64,
    flags: u16,
    _reserved: u16 = 0,
};

pub const SecretRotateRequestWire = extern struct {
    header: WireHeader,
    old_secret_id: u64,
    label_len: u16,
    raw_len: u16,
    flags: u16,
    _reserved: u16 = 0,
};

pub const SecretRevokeRequestWire = extern struct {
    header: WireHeader,
    secret_id: u64,
    handle_id: u64,
    subject_serial: u64,
    expected_holder_serial: u64,
    expected_holder_task_id: u64,
    subject_kind: u16,
    expected_holder_kind: u16,
    reason: u16,
    flags: u16 = 0,
};

pub const SecretVaultResponseWire = extern struct {
    accepted: u32,
    reason: u16,
    _reserved: u16 = 0,
    secret_id: u64,
    handle_id: u64,
    flags: u32,
};
