// Event taxonomy: the kinds of events the ledger records and the typed action/
// reason enums their persisted detail codes decode to. Extracted from
// event_ledger.zig as a dependency-free vocabulary module.

pub const EventKind = enum(u8) {
    permission_decision,
    process_crash,
    driver_restart,
    update_transition,
    sync_conflict,
    device_trust_change,
    permission_review,
    capability_grant,
    capability_revocation,
    notification,
    task_flow,
    task_lifecycle,
    policy_change,
    suspicious_app_behavior,
    session_posture,
    ai_inference,
    ai_model_attestation,
    data_egress,
    privacy_budget,
    data_export,
    data_deletion,
    retention_policy,
    permission_lease,
    consent_receipt,
    agent_delegation,
    agent_session,
    attention_policy,
    accessibility_profile,
    background_activity,
    resource_governance,
    network_session,
    pasteboard_access,
    object_resilience,
    semantic_memory,
    identity_credential,
    sensitive_capture,
    secret_vault,
};

pub const PolicyChangeAction = enum(u8) {
    applied,
    overridden,
    revoked,
};

pub const PermissionLeaseAction = enum(u8) {
    issued,
    renewed,
    expired,
};

pub const ConsentReceiptAction = enum(u8) {
    recorded,
    revoked,
};

pub const TaskLifecycleOperation = enum(u8) {
    suspend_task,
    resume_task,
    terminate_task,
};

pub const NetworkSessionAction = enum(u8) {
    open,
    transfer,
    revoke,
    complete,
};

pub const NetworkSessionReason = enum(u8) {
    none,
    policy_denied,
    capability_denied,
    destination_mismatch,
    attestation_required,
    byte_limit_exceeded,
    session_expired,
    session_revoked,
    session_completed,
    source_mismatch,
};
