const crypto_hash = @import("../core/crypto_hash.zig");

pub const MAGIC: u32 = 0x54434142;
pub const VERSION: u16 = 6;

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
    endpoint_id: u64,
    interface_id: u16,
    flags: u16,
    _reserved: u32 = 0,
};

pub const ServiceConnectionRequestWire = extern struct {
    header: WireHeader,
    interface_id: u16,
    _reserved: [6]u8 = @as([6]u8, @splat(0)),
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
