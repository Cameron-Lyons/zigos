const std = @import("std");
const abi = @import("../core/abi.zig");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");
const contract = @import("../session/contract.zig");
const denial_explanation = @import("../policy/denial_explanation.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const immutable_base = @import("immutable_base.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const native_ux = @import("native_ux.zig");
const notification_center = @import("../services/notification_center.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const workspace = @import("../storage/workspace.zig");
const kinds = @import("event_kinds.zig");
const copyText = native_util.copyText;
const yesNo = native_util.yesNo;

pub const MAX_EVENTS: usize = 64;
pub const MAX_DETAIL_BYTES: usize = 512;
pub const state_workspace_label = "system-diagnostics";

const MAX_PERSISTED_EVENTS: usize = MAX_EVENTS;
const MAX_PERSISTED_DETAIL_BYTES: usize = MAX_DETAIL_BYTES;
const MAX_PERSISTED_LABEL_BYTES: usize = denial_explanation.MAX_LABEL_BYTES;
const state_entry_path = "state/event-ledger";
const event_entry_prefix = "events/";
const persistent_header_magic: u32 = 0x454C4731;
const permission_kind_none: u8 = 0xFF;
const DENIAL_HELP_BUFFER_BYTES: usize = 256;
const PERSISTENT_EVENT_RESERVED_BYTES: usize = 5;
const PERSISTENT_EVENT_TAIL_RESERVED_BYTES: usize = 4;
const persistent_event_flag_allowed: u8 = 1 << 0;
const persistent_event_flag_user_approval_can_resolve: u8 = 1 << 1;
const persistent_event_flag_retry_safe: u8 = 1 << 2;
const persistent_event_flag_detail_protected: u8 = 1 << 3;
const semantic_memory_flag_receipt_audit: u32 = @as(u32, 1) << @as(u5, 28);
const semantic_memory_query_byte_mask: usize = 0x0fff_ffff;

const PersistentHeader = extern struct {
    magic: u32 = persistent_header_magic,
    next_sequence: u64 = 1,
};

pub const EventKind = kinds.EventKind;
pub const PolicyChangeAction = kinds.PolicyChangeAction;
pub const PermissionLeaseAction = kinds.PermissionLeaseAction;
pub const ConsentReceiptAction = kinds.ConsentReceiptAction;
pub const TaskLifecycleOperation = kinds.TaskLifecycleOperation;
pub const NetworkSessionAction = kinds.NetworkSessionAction;
pub const NetworkSessionReason = kinds.NetworkSessionReason;

pub const ExportOptions = struct {
    include_protected_content: bool = false,
};

pub const Query = struct {
    kind: ?EventKind = null,
    subject: ?principal.PrincipalId = null,
    task_id: ?u64 = null,
    workspace_id: ?u64 = null,
    include_protected_content: bool = false,
};

pub const RemoteShareOptions = struct {
    include_protected_content: bool = false,
    personal_device: bool = true,
    user_opted_in: bool = false,
};

pub const DiagnosticSummary = struct {
    total_events: usize = 0,
    protected_details_redacted: usize = 0,
    capability_denials: usize = 0,
    crashes: usize = 0,
    driver_restarts: usize = 0,
    suspicious_app_behavior: usize = 0,
    session_posture_events: usize = 0,
    session_posture_denials: usize = 0,
    sync_conflicts: usize = 0,
    device_trust_changes: usize = 0,
    device_trust_revocations: usize = 0,
    update_health_events: usize = 0,
    update_rollbacks: usize = 0,
    ai_inference_events: usize = 0,
    ai_remote_denials: usize = 0,
    ai_model_attestations: usize = 0,
    ai_model_rejections: usize = 0,
    data_egress_events: usize = 0,
    private_egress_denials: usize = 0,
    privacy_budget_events: usize = 0,
    data_export_events: usize = 0,
    data_export_denials: usize = 0,
    data_deletion_events: usize = 0,
    data_deletion_denials: usize = 0,
    data_deletion_receipts: usize = 0,
    retention_policy_events: usize = 0,
    permission_lease_events: usize = 0,
    permission_lease_expirations: usize = 0,
    consent_receipt_events: usize = 0,
    consent_receipt_revocations: usize = 0,
    agent_delegation_events: usize = 0,
    agent_delegation_denials: usize = 0,
    agent_remote_call_events: usize = 0,
    agent_session_events: usize = 0,
    agent_session_denials: usize = 0,
    agent_kill_switch_denials: usize = 0,
    task_lifecycle_events: usize = 0,
    task_lifecycle_denials: usize = 0,
    task_lifecycle_terminations: usize = 0,
    attention_policy_events: usize = 0,
    attention_interruptions_denied: usize = 0,
    accessibility_profile_events: usize = 0,
    accessibility_denials: usize = 0,
    background_activity_events: usize = 0,
    background_activity_denials: usize = 0,
    resource_governance_events: usize = 0,
    resource_governance_delays: usize = 0,
    resource_governance_thermal_throttles: usize = 0,
    resource_governance_battery_preserves: usize = 0,
    resource_governance_hardware_evidence: usize = 0,
    network_session_events: usize = 0,
    network_session_denials: usize = 0,
    network_session_revocations: usize = 0,
    network_session_byte_denials: usize = 0,
    network_session_attested: usize = 0,
    pasteboard_events: usize = 0,
    pasteboard_denials: usize = 0,
    object_resilience_events: usize = 0,
    object_resilience_denials: usize = 0,
    object_restore_events: usize = 0,
    semantic_memory_events: usize = 0,
    semantic_memory_denials: usize = 0,
    semantic_memory_remote_denials: usize = 0,
    semantic_memory_receipt_events: usize = 0,
    semantic_memory_receipt_denials: usize = 0,
    identity_credential_events: usize = 0,
    identity_credential_denials: usize = 0,
    identity_credential_recoveries: usize = 0,
    identity_credential_revocations: usize = 0,
    identity_credential_phishing_denials: usize = 0,
    sensitive_capture_events: usize = 0,
    sensitive_capture_denials: usize = 0,
    sensitive_capture_background_denials: usize = 0,
    secret_vault_events: usize = 0,
    secret_vault_denials: usize = 0,
    secret_vault_raw_export_denials: usize = 0,
    secret_vault_rotations: usize = 0,
    secret_vault_revocations: usize = 0,
    latest_tick: u64 = 0,

    pub fn evidenceEventCount(self: DiagnosticSummary) usize {
        return self.capability_denials +
            self.crashes +
            self.driver_restarts +
            self.suspicious_app_behavior +
            self.session_posture_events +
            self.sync_conflicts +
            self.device_trust_changes +
            self.update_health_events +
            self.ai_inference_events +
            self.ai_model_attestations +
            self.data_egress_events +
            self.privacy_budget_events +
            self.data_export_events +
            self.data_deletion_events +
            self.retention_policy_events +
            self.permission_lease_events +
            self.consent_receipt_events +
            self.agent_delegation_events +
            self.agent_session_events +
            self.task_lifecycle_events +
            self.attention_policy_events +
            self.accessibility_profile_events +
            self.background_activity_events +
            self.resource_governance_events +
            self.network_session_events +
            self.pasteboard_events +
            self.object_resilience_events +
            self.semantic_memory_events +
            self.identity_credential_events +
            self.sensitive_capture_events +
            self.secret_vault_events;
    }
};

pub const Event = struct {
    sequence: u64 = 0,
    kind: EventKind,
    tick: u64,
    subject: principal.PrincipalId,
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    related_id: u64 = 0,
    detail_code: u32 = 0,
    service_class: contract.ServiceClass = .task_runtime,
    permission_kind: ?manifest.PermissionKind = null,
    allowed: bool = false,
    denial_reason: abi.DenialReason = .none,
    user_approval_can_resolve: bool = false,
    retry_safe: bool = false,
    policy_label_len: usize = 0,
    policy_label: [denial_explanation.MAX_LABEL_BYTES]u8 = [_]u8{0} ** denial_explanation.MAX_LABEL_BYTES,
    missing_capability_len: usize = 0,
    missing_capability: [denial_explanation.MAX_LABEL_BYTES]u8 = [_]u8{0} ** denial_explanation.MAX_LABEL_BYTES,
    detail_protected: bool = false,
    detail_len: usize = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,

    pub fn detailSlice(self: *const Event) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn policyLabelSlice(self: *const Event) []const u8 {
        return self.policy_label[0..self.policy_label_len];
    }

    pub fn missingCapabilitySlice(self: *const Event) []const u8 {
        return self.missing_capability[0..self.missing_capability_len];
    }
};

pub const Error = object_store.Error || workspace.Error || error{
    ConsentRequired,
    CorruptState,
    EventTableFull,
    NoSpaceLeft,
    SigningFailed,
};

const EventSlot = struct {
    in_use: bool = false,
    event: Event = zeroEvent(),
};

fn eventSlotSequence(slot: *const EventSlot) u64 {
    return slot.event.sequence;
}

const EventArena = indexed_arena.IndexedArena(EventSlot, MAX_EVENTS, MAX_EVENTS * 2, eventSlotSequence);
const event_kind_count = std.meta.fields(EventKind).len;
const KindEventIndex = indexed_arena.MultimapIndex(MAX_EVENTS, event_kind_count, event_kind_count * 2);
const SubjectEventIndex = indexed_arena.MultimapIndex(MAX_EVENTS, MAX_EVENTS, MAX_EVENTS * 2);
const TaskEventIndex = indexed_arena.MultimapIndex(MAX_EVENTS, MAX_EVENTS, MAX_EVENTS * 2);

const QueryIndex = enum {
    kind,
    subject,
    task,
};

pub const Ledger = struct {
    storage: ?*storage_service.Service = null,
    owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    state_signer: signing.SignerIdentity = .{
        .label = "",
        .seed = signing.seedFromByte(0),
    },
    workspace_id: u64 = 0,
    loaded_existing_state: bool = false,
    header_version_id: u64 = 0,
    next_sequence: u64 = 1,
    events: EventArena = EventArena.init(),
    kind_index: KindEventIndex = KindEventIndex.init(),
    subject_index: SubjectEventIndex = SubjectEventIndex.init(),
    task_index: TaskEventIndex = TaskEventIndex.init(),
    persistence_batch_depth: usize = 0,
    pending_persist_first_sequence: u64 = 0,
    pending_persist_count: usize = 0,
    pending_persist_latest_tick: u64 = 0,

    pub fn init() Ledger {
        return .{};
    }

    pub fn initPersistent(
        storage: *storage_service.Service,
        owner: principal.PrincipalId,
        state_signer: signing.SignerIdentity,
    ) Error!Ledger {
        const workspace_record = storage.findWorkspace(owner, state_workspace_label) orelse
            storage.findWorkspaceByLabel(state_workspace_label) orelse
            try storage.createWorkspace(.{
                .owner = owner,
                .label = state_workspace_label,
            });

        var ledger = Ledger{
            .storage = storage,
            .owner = owner,
            .state_signer = state_signer,
            .workspace_id = workspace_record.id.raw(),
        };

        if (storage.resolve(workspace_record.id, state_entry_path)) |_| {
            try ledger.loadPersistedEvents();
            ledger.loaded_existing_state = true;
        } else |err| switch (err) {
            error.EntryNotFound => {},
            else => return err,
        }

        return ledger;
    }

    pub fn beginPersistenceBatch(self: *Ledger) void {
        self.persistence_batch_depth += 1;
    }

    pub fn flushPersistenceBatch(self: *Ledger) Error!void {
        if (self.persistence_batch_depth != 0) self.persistence_batch_depth -= 1;
        if (self.persistence_batch_depth != 0 or self.pending_persist_count == 0) return;

        const first_sequence = self.pending_persist_first_sequence;
        const latest_sequence = first_sequence + @as(u64, @intCast(self.pending_persist_count)) - 1;
        try self.persistRange(first_sequence, latest_sequence, self.pending_persist_latest_tick);
        self.clearPendingPersistence();
    }

    pub fn pendingPersistenceCount(self: *const Ledger) usize {
        return self.pending_persist_count;
    }

    pub fn recordPermissionDecision(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        permission_kind: manifest.PermissionKind,
        allowed: bool,
        denial_reason: abi.DenialReason,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        const explanation = if (allowed)
            denial_explanation.none()
        else
            denial_explanation.forPermissionDecision(permission_kind, denial_reason);
        try self.append(.{
            .kind = .permission_decision,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .permission_kind = permission_kind,
            .allowed = allowed,
            .denial_reason = denial_reason,
            .user_approval_can_resolve = explanation.user_approval_can_resolve,
            .retry_safe = explanation.retry_safe,
            .policy_label_len = clampedExplanationLen(explanation.policySlice()),
            .policy_label = copyExplanationTextInto(explanation.policySlice()),
            .missing_capability_len = clampedExplanationLen(explanation.missingCapabilitySlice()),
            .missing_capability = copyExplanationTextInto(explanation.missingCapabilitySlice()),
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordPermissionReview(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        permission_kind: manifest.PermissionKind,
        approved: bool,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .permission_review,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .permission_kind = permission_kind,
            .allowed = approved,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordCapabilityGrant(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        capability_id: u64,
        permission_kind: ?manifest.PermissionKind,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .capability_grant,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = capability_id,
            .permission_kind = permission_kind,
            .allowed = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordCapabilityRevocation(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        capability_id: u64,
        permission_kind: ?manifest.PermissionKind,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .capability_revocation,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = capability_id,
            .permission_kind = permission_kind,
            .allowed = false,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordNotification(
        self: *Ledger,
        notification: notification_center.Notification,
        tick: u64,
    ) Error!void {
        try self.append(.{
            .kind = .notification,
            .tick = tick,
            .subject = notification.source,
            .task_id = notification.task_id orelse 0,
            .related_id = notification.id,
            .detail_code = @intFromEnum(notification.reason),
            .allowed = !notification.suppressed,
            .detail_len = clampedDetailLen(notification.detailSlice()),
            .detail = copyTextInto(notification.detailSlice()),
        });
    }

    pub fn recordTaskFlow(
        self: *Ledger,
        flow: native_ux.FlowRecord,
        tick: u64,
    ) Error!void {
        try self.append(.{
            .kind = .task_flow,
            .tick = tick,
            .subject = flow.subject,
            .task_id = flow.task_id,
            .workspace_id = flow.workspace_id,
            .related_id = flow.id,
            .detail_code = @intFromEnum(flow.kind),
            .permission_kind = if (flow.kind == .review_permission_request) flow.permission_kind else null,
            .allowed = flow.approved,
            .detail_len = clampedDetailLen(flow.detailSlice()),
            .detail = copyTextInto(flow.detailSlice()),
        });
    }

    pub fn recordTaskLifecycle(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        operation: TaskLifecycleOperation,
        allowed: bool,
        checkpoint_present: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = @intFromEnum(operation);
        if (checkpoint_present) code |= @as(u32, 1) << @as(u5, 31);
        try self.append(.{
            .kind = .task_lifecycle,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSuspiciousAppBehavior(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        tick: u64,
        code: u32,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .suspicious_app_behavior,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSessionPosture(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        hardware_backed: bool,
        platform_backed: bool,
        primary_device: bool,
        unlock_age_ticks: u64,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (hardware_backed) code |= 1;
        if (platform_backed) code |= 2;
        if (primary_device) code |= 4;
        try self.append(.{
            .kind = .session_posture,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = unlock_age_ticks,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordProcessCrash(
        self: *Ledger,
        service_class: contract.ServiceClass,
        service_subject: principal.PrincipalId,
        tick: u64,
        code: u32,
        detail: []const u8,
    ) Error!void {
        var event = zeroEvent();
        event.kind = .process_crash;
        event.tick = tick;
        event.subject = service_subject;
        event.service_class = service_class;
        event.detail_code = code;
        event.detail_len = copyText(&event.detail, detail);
        try self.appendEvent(&event);
    }

    pub fn recordDriverRestart(
        self: *Ledger,
        service_class: contract.ServiceClass,
        service_subject: principal.PrincipalId,
        device_capability_id: u64,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var event = zeroEvent();
        event.kind = .driver_restart;
        event.tick = tick;
        event.subject = service_subject;
        event.service_class = service_class;
        event.related_id = device_capability_id;
        event.detail_len = copyText(&event.detail, detail);
        try self.appendEvent(&event);
    }

    pub fn recordUpdateTransition(
        self: *Ledger,
        subject: principal.PrincipalId,
        slot_index: usize,
        failure: immutable_base.HealthFailure,
        rolled_back: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .update_transition,
            .tick = tick,
            .subject = subject,
            .related_id = slot_index,
            .detail_code = @intFromEnum(failure),
            .allowed = !rolled_back,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSyncConflict(
        self: *Ledger,
        subject: principal.PrincipalId,
        workspace_id: u64,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .sync_conflict,
            .tick = tick,
            .subject = subject,
            .workspace_id = workspace_id,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordDeviceTrustChange(
        self: *Ledger,
        subject: principal.PrincipalId,
        device_id: principal.PrincipalId,
        trusted: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .device_trust_change,
            .tick = tick,
            .subject = subject,
            .related_id = device_id.serial,
            .allowed = trusted,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordPolicyChange(
        self: *Ledger,
        subject: principal.PrincipalId,
        policy_id: u64,
        action: PolicyChangeAction,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .policy_change,
            .tick = tick,
            .subject = subject,
            .related_id = policy_id,
            .detail_code = @intFromEnum(action),
            .allowed = action != .revoked,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordAiInference(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        remote_model: bool,
        training_user_content: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (remote_model) code |= 1;
        if (training_user_content) code |= 2;
        try self.append(.{
            .kind = .ai_inference,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordAiModelAttestation(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        measured: bool,
        trusted_source: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (measured) code |= 1;
        if (trusted_source) code |= 2;
        try self.append(.{
            .kind = .ai_model_attestation,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordDataEgress(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        sensitivity: manifest.DataSensitivity,
        remote_bytes: usize,
        allowed: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .data_egress,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = remote_bytes,
            .detail_code = @intFromEnum(sensitivity),
            .allowed = allowed,
            .detail_protected = manifest.isSensitive(sensitivity),
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordPrivacyBudget(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .privacy_budget,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordDataExport(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        sensitivity: manifest.DataSensitivity,
        export_bytes: usize,
        allowed: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .data_export,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = export_bytes,
            .detail_code = @intFromEnum(sensitivity),
            .allowed = allowed,
            .detail_protected = manifest.isSensitive(sensitivity),
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordDataDeletion(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        receipt_id: u64,
        allowed: bool,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .data_deletion,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = receipt_id,
            .allowed = allowed,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordRetentionPolicy(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        retention_days: u16,
        allowed: bool,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .retention_policy,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = retention_days,
            .allowed = allowed,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordPermissionLease(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        permission_kind: manifest.PermissionKind,
        action: PermissionLeaseAction,
        lease_ticks: u64,
        tick: u64,
        detail: []const u8,
        protected: bool,
    ) Error!void {
        try self.append(.{
            .kind = .permission_lease,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = lease_ticks,
            .detail_code = @intFromEnum(action),
            .permission_kind = permission_kind,
            .allowed = action != .expired,
            .detail_protected = protected,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordConsentReceipt(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        receipt_id: u64,
        action: ConsentReceiptAction,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        try self.append(.{
            .kind = .consent_receipt,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = receipt_id,
            .detail_code = @intFromEnum(action),
            .allowed = action != .revoked,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordAgentDelegation(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        autonomous_actions: u16,
        remote_calls: u16,
        user_confirmed: bool,
        audit_enabled: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (user_confirmed) code |= 1;
        if (audit_enabled) code |= 2;
        try self.append(.{
            .kind = .agent_delegation,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = remote_calls,
            .detail_code = (@as(u32, autonomous_actions) << 16) | code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordAgentSessionBoundary(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        session_bound: bool,
        local_context_only: bool,
        generation_blocked: bool,
        delegation_generation: u32,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = delegation_generation & 0x1fff_ffff;
        if (session_bound) code |= @as(u32, 1) << @as(u5, 31);
        if (local_context_only) code |= @as(u32, 1) << @as(u5, 30);
        if (generation_blocked) code |= @as(u32, 1) << @as(u5, 29);
        try self.append(.{
            .kind = .agent_session,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordAttentionDecision(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        interruptive: bool,
        active_visible: u16,
        active_interruptions: u16,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        const active_visible_code: u32 = @min(@as(u32, active_visible), @as(u32, 0x7fff));
        const active_interruptions_code = @as(u32, active_interruptions);
        var code: u32 = (active_visible_code << @as(u5, 16)) | active_interruptions_code;
        if (interruptive) code |= @as(u32, 1) << @as(u5, 31);
        try self.append(.{
            .kind = .attention_policy,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordAccessibilityProfile(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        screen_reader: bool,
        keyboard_navigation: bool,
        reduced_motion: bool,
        high_contrast: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (screen_reader) code |= 1;
        if (keyboard_navigation) code |= 2;
        if (reduced_motion) code |= 4;
        if (high_contrast) code |= 8;
        try self.append(.{
            .kind = .accessibility_profile,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordBackgroundActivity(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        remote_network: bool,
        user_visible: bool,
        expected_duration_seconds: u32,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = @min(expected_duration_seconds, @as(u32, 0x3fff_ffff));
        if (remote_network) code |= @as(u32, 1) << @as(u5, 31);
        if (user_visible) code |= @as(u32, 1) << @as(u5, 30);
        try self.append(.{
            .kind = .background_activity,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordResourceGovernance(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        class: accelerator_scheduler.ResourceClass,
        reason: accelerator_scheduler.DecisionReason,
        delayed: bool,
        degraded: bool,
        observed_telemetry: bool,
        hardware_evidence: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = @intFromEnum(reason);
        code |= @as(u32, @intFromEnum(class)) << @as(u5, 8);
        if (degraded) code |= @as(u32, 1) << @as(u5, 29);
        if (observed_telemetry) code |= @as(u32, 1) << @as(u5, 30);
        if (hardware_evidence) code |= @as(u32, 1) << @as(u5, 31);
        try self.append(.{
            .kind = .resource_governance,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = !delayed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordNetworkSession(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        session_id: u64,
        action: NetworkSessionAction,
        reason: NetworkSessionReason,
        allowed: bool,
        attested: bool,
        identity_pinned: bool,
        private_data: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = @intFromEnum(action);
        code |= @as(u32, @intFromEnum(reason)) << @as(u5, 8);
        if (attested) code |= @as(u32, 1) << @as(u5, 29);
        if (identity_pinned) code |= @as(u32, 1) << @as(u5, 30);
        if (private_data) code |= @as(u32, 1) << @as(u5, 31);
        try self.append(.{
            .kind = .network_session,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = session_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordPasteboardAccess(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        token_id: u64,
        allowed: bool,
        user_gesture_present: bool,
        foreground_session_present: bool,
        read_once: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (user_gesture_present) code |= 1;
        if (foreground_session_present) code |= 2;
        if (read_once) code |= 4;
        try self.append(.{
            .kind = .pasteboard_access,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = token_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordObjectResilience(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        snapshot_id: u64,
        allowed: bool,
        restore: bool,
        encrypted: bool,
        device_trust_verified: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (restore) code |= 1;
        if (encrypted) code |= 2;
        if (device_trust_verified) code |= 4;
        try self.append(.{
            .kind = .object_resilience,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = snapshot_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSemanticMemory(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        allowed: bool,
        local_model: bool,
        encrypted_index: bool,
        redacted_snippets: bool,
        query_bytes: usize,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        const capped_query_bytes = @min(query_bytes, semantic_memory_query_byte_mask);
        const query_code: u32 = @intCast(capped_query_bytes);
        var code: u32 = query_code;
        if (local_model) code |= @as(u32, 1) << @as(u5, 31);
        if (encrypted_index) code |= @as(u32, 1) << @as(u5, 30);
        if (redacted_snippets) code |= @as(u32, 1) << @as(u5, 29);
        try self.append(.{
            .kind = .semantic_memory,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSemanticMemoryReceipt(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        workspace_id: u64,
        receipt_id: u64,
        allowed: bool,
        local_model: bool,
        encrypted_index: bool,
        redacted_snippets: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = semantic_memory_flag_receipt_audit;
        if (local_model) code |= @as(u32, 1) << @as(u5, 31);
        if (encrypted_index) code |= @as(u32, 1) << @as(u5, 30);
        if (redacted_snippets) code |= @as(u32, 1) << @as(u5, 29);
        try self.append(.{
            .kind = .semantic_memory,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .workspace_id = workspace_id,
            .related_id = receipt_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordIdentityCredential(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        credential_id: u64,
        allowed: bool,
        origin_bound: bool,
        hardware_backed: bool,
        local_unlock_verified: bool,
        recovery: bool,
        revocation: bool,
        password_fallback: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (origin_bound) code |= 1;
        if (hardware_backed) code |= 2;
        if (local_unlock_verified) code |= 4;
        if (recovery) code |= 8;
        if (revocation) code |= 16;
        if (password_fallback) code |= 32;
        try self.append(.{
            .kind = .identity_credential,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = credential_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSensitiveCapture(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        session_id: u64,
        allowed: bool,
        permission_kind: ?manifest.PermissionKind,
        foreground_session_present: bool,
        indicator_visible: bool,
        background: bool,
        sample: bool,
        stopped: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (foreground_session_present) code |= 1;
        if (indicator_visible) code |= 2;
        if (background) code |= 4;
        if (sample) code |= 8;
        if (stopped) code |= 16;
        try self.append(.{
            .kind = .sensitive_capture,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = session_id,
            .permission_kind = permission_kind,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn recordSecretVault(
        self: *Ledger,
        subject: principal.PrincipalId,
        task_id: u64,
        secret_id: u64,
        handle_id: u64,
        allowed: bool,
        hardware_backed: bool,
        raw_export: bool,
        rotation: bool,
        revocation: bool,
        tick: u64,
        detail: []const u8,
    ) Error!void {
        var code: u32 = 0;
        if (hardware_backed) code |= 1;
        if (raw_export) code |= 2;
        if (rotation) code |= 4;
        if (revocation) code |= 8;
        try self.append(.{
            .kind = .secret_vault,
            .tick = tick,
            .subject = subject,
            .task_id = task_id,
            .related_id = if (handle_id != 0) handle_id else secret_id,
            .detail_code = code,
            .allowed = allowed,
            .detail_protected = true,
            .detail_len = clampedDetailLen(detail),
            .detail = copyTextInto(detail),
        });
    }

    pub fn latestKind(self: *const Ledger, kind: EventKind) ?Event {
        const event = self.latestKindPtr(kind) orelse return null;
        return event.*;
    }

    pub fn latestKindPtr(self: *const Ledger, kind: EventKind) ?*const Event {
        const tail = self.kind_index.tail(kindKey(kind));
        if (tail == indexed_arena.no_index) return null;
        return &self.events.slots[tail].event;
    }

    pub fn queryEvents(self: *const Ledger, query: Query, output: []Event) []Event {
        var count: usize = 0;
        self.visitMatching(query, output.len, &count, output);
        return output[0..count];
    }

    pub fn countMatching(self: *const Ledger, query: Query) usize {
        var count: usize = 0;
        self.visitMatching(query, std.math.maxInt(usize), &count, null);
        return count;
    }

    pub fn exportText(self: *const Ledger, buffer: []u8, options: ExportOptions) Error![]const u8 {
        var used: usize = 0;
        var index: usize = 0;
        while (index < self.events.next_unclaimed_index) : (index += 1) {
            const slot = &self.events.slots[index];
            if (!slot.in_use) continue;
            try renderTextEvent(&slot.event, buffer, &used, options.include_protected_content);
        }
        return buffer[0..used];
    }

    pub fn exportRemoteShare(
        self: *const Ledger,
        buffer: []u8,
        options: RemoteShareOptions,
    ) Error![]const u8 {
        if (options.personal_device and !options.user_opted_in) return error.ConsentRequired;
        return self.exportText(buffer, .{
            .include_protected_content = options.include_protected_content,
        });
    }

    pub fn userVisibleDiagnosticSummary(self: *const Ledger) DiagnosticSummary {
        var summary = DiagnosticSummary{};
        for (&self.events.slots) |*slot| {
            if (!slot.in_use) continue;
            const event = &slot.event;
            summary.total_events += 1;
            summary.latest_tick = @max(summary.latest_tick, event.tick);
            if (event.detail_protected) summary.protected_details_redacted += 1;

            switch (event.kind) {
                .permission_decision => {
                    if (!event.allowed) summary.capability_denials += 1;
                },
                .process_crash => summary.crashes += 1,
                .driver_restart => summary.driver_restarts += 1,
                .suspicious_app_behavior => summary.suspicious_app_behavior += 1,
                .session_posture => {
                    summary.session_posture_events += 1;
                    if (!event.allowed) summary.session_posture_denials += 1;
                },
                .sync_conflict => summary.sync_conflicts += 1,
                .device_trust_change => {
                    summary.device_trust_changes += 1;
                    if (!event.allowed) summary.device_trust_revocations += 1;
                },
                .update_transition => {
                    summary.update_health_events += 1;
                    if (!event.allowed) summary.update_rollbacks += 1;
                },
                .ai_inference => {
                    summary.ai_inference_events += 1;
                    if (!event.allowed and (event.detail_code & 1) != 0) summary.ai_remote_denials += 1;
                },
                .ai_model_attestation => {
                    summary.ai_model_attestations += 1;
                    if (!event.allowed) summary.ai_model_rejections += 1;
                },
                .data_egress => {
                    summary.data_egress_events += 1;
                    if (!event.allowed and manifest.isSensitive(std.enums.fromInt(manifest.DataSensitivity, @as(u8, @intCast(event.detail_code))) orelse .internal_data)) {
                        summary.private_egress_denials += 1;
                    }
                },
                .privacy_budget => summary.privacy_budget_events += 1,
                .data_export => {
                    summary.data_export_events += 1;
                    if (!event.allowed) summary.data_export_denials += 1;
                },
                .data_deletion => {
                    summary.data_deletion_events += 1;
                    if (!event.allowed) summary.data_deletion_denials += 1;
                    if (event.allowed and event.related_id != 0) summary.data_deletion_receipts += 1;
                },
                .retention_policy => summary.retention_policy_events += 1,
                .permission_lease => {
                    summary.permission_lease_events += 1;
                    if (event.detail_code == @intFromEnum(PermissionLeaseAction.expired)) summary.permission_lease_expirations += 1;
                },
                .consent_receipt => {
                    summary.consent_receipt_events += 1;
                    if (event.detail_code == @intFromEnum(ConsentReceiptAction.revoked)) summary.consent_receipt_revocations += 1;
                },
                .agent_delegation => {
                    summary.agent_delegation_events += 1;
                    if (!event.allowed) summary.agent_delegation_denials += 1;
                    if (event.related_id != 0) summary.agent_remote_call_events += 1;
                },
                .agent_session => {
                    summary.agent_session_events += 1;
                    if (!event.allowed) summary.agent_session_denials += 1;
                    if (!event.allowed and (event.detail_code & (@as(u32, 1) << @as(u5, 29))) != 0) {
                        summary.agent_kill_switch_denials += 1;
                    }
                },
                .task_lifecycle => {
                    summary.task_lifecycle_events += 1;
                    if (!event.allowed) summary.task_lifecycle_denials += 1;
                    if (event.allowed and taskLifecycleOperation(event.detail_code) == .terminate_task) {
                        summary.task_lifecycle_terminations += 1;
                    }
                },
                .attention_policy => {
                    summary.attention_policy_events += 1;
                    if (!event.allowed and (event.detail_code & (@as(u32, 1) << @as(u5, 31))) != 0) {
                        summary.attention_interruptions_denied += 1;
                    }
                },
                .accessibility_profile => {
                    summary.accessibility_profile_events += 1;
                    if (!event.allowed) summary.accessibility_denials += 1;
                },
                .background_activity => {
                    summary.background_activity_events += 1;
                    if (!event.allowed) summary.background_activity_denials += 1;
                },
                .resource_governance => {
                    summary.resource_governance_events += 1;
                    if (!event.allowed) summary.resource_governance_delays += 1;
                    switch (resourceGovernanceReason(event.detail_code)) {
                        .thermal_throttle => summary.resource_governance_thermal_throttles += 1,
                        .battery_preserve => summary.resource_governance_battery_preserves += 1,
                        else => {},
                    }
                    if (resourceGovernanceHardwareEvidence(event.detail_code)) {
                        summary.resource_governance_hardware_evidence += 1;
                    }
                },
                .network_session => {
                    summary.network_session_events += 1;
                    if (!event.allowed) summary.network_session_denials += 1;
                    if (networkSessionAction(event.detail_code) == .revoke) summary.network_session_revocations += 1;
                    if (networkSessionReason(event.detail_code) == .byte_limit_exceeded) summary.network_session_byte_denials += 1;
                    if (networkSessionAttested(event.detail_code)) summary.network_session_attested += 1;
                },
                .pasteboard_access => {
                    summary.pasteboard_events += 1;
                    if (!event.allowed) summary.pasteboard_denials += 1;
                },
                .object_resilience => {
                    summary.object_resilience_events += 1;
                    if (!event.allowed) summary.object_resilience_denials += 1;
                    if ((event.detail_code & 1) != 0) summary.object_restore_events += 1;
                },
                .semantic_memory => {
                    summary.semantic_memory_events += 1;
                    if (!event.allowed) summary.semantic_memory_denials += 1;
                    if (semanticMemoryReceiptAudit(event.detail_code)) {
                        summary.semantic_memory_receipt_events += 1;
                        if (!event.allowed) summary.semantic_memory_receipt_denials += 1;
                    }
                    if (!event.allowed and (event.detail_code & (@as(u32, 1) << @as(u5, 31))) == 0) {
                        summary.semantic_memory_remote_denials += 1;
                    }
                },
                .identity_credential => {
                    summary.identity_credential_events += 1;
                    if (!event.allowed) summary.identity_credential_denials += 1;
                    if ((event.detail_code & 8) != 0) summary.identity_credential_recoveries += 1;
                    if ((event.detail_code & 16) != 0) summary.identity_credential_revocations += 1;
                    if (!event.allowed and (event.detail_code & 1) == 0) {
                        summary.identity_credential_phishing_denials += 1;
                    }
                },
                .sensitive_capture => {
                    summary.sensitive_capture_events += 1;
                    if (!event.allowed) summary.sensitive_capture_denials += 1;
                    if (!event.allowed and (event.detail_code & 4) != 0) summary.sensitive_capture_background_denials += 1;
                },
                .secret_vault => {
                    summary.secret_vault_events += 1;
                    if (!event.allowed) summary.secret_vault_denials += 1;
                    if (!event.allowed and (event.detail_code & 2) != 0) summary.secret_vault_raw_export_denials += 1;
                    if ((event.detail_code & 4) != 0) summary.secret_vault_rotations += 1;
                    if ((event.detail_code & 8) != 0) summary.secret_vault_revocations += 1;
                },
                else => {},
            }
        }
        return summary;
    }

    pub fn renderUserVisibleDiagnosticsToBuffer(self: *const Ledger, buffer: []u8) Error![]const u8 {
        const summary = self.userVisibleDiagnosticSummary();
        const evidence_events = summary.evidenceEventCount();
        var used: usize = 0;
        try appendFmt(buffer, &used, "diagnostics user_visible=yes privacy=redacted evidence_of_intrusion_capable=yes total_events={d} evidence_events={d} evidence_present={s} protected_details_redacted={d} latest_tick={d}\n", .{
            summary.total_events,
            evidence_events,
            yesNo(evidence_events != 0),
            summary.protected_details_redacted,
            summary.latest_tick,
        });
        try appendFmt(buffer, &used, "diagnostic_evidence capability_denials={d} crashes={d} driver_restarts={d} suspicious_app_behavior={d} session_posture_events={d} session_posture_denials={d} sync_conflicts={d} device_trust_changes={d} device_trust_revocations={d} update_health_events={d} update_rollbacks={d} ai_inference_events={d} ai_remote_denials={d} ai_model_attestations={d} ai_model_rejections={d} data_egress_events={d} private_egress_denials={d} privacy_budget_events={d} data_export_events={d} data_export_denials={d} data_deletion_events={d} data_deletion_denials={d} data_deletion_receipts={d}", .{
            summary.capability_denials,
            summary.crashes,
            summary.driver_restarts,
            summary.suspicious_app_behavior,
            summary.session_posture_events,
            summary.session_posture_denials,
            summary.sync_conflicts,
            summary.device_trust_changes,
            summary.device_trust_revocations,
            summary.update_health_events,
            summary.update_rollbacks,
            summary.ai_inference_events,
            summary.ai_remote_denials,
            summary.ai_model_attestations,
            summary.ai_model_rejections,
            summary.data_egress_events,
            summary.private_egress_denials,
            summary.privacy_budget_events,
            summary.data_export_events,
            summary.data_export_denials,
            summary.data_deletion_events,
            summary.data_deletion_denials,
            summary.data_deletion_receipts,
        });
        try appendFmt(buffer, &used, " retention_policy_events={d} permission_lease_events={d} permission_lease_expirations={d} consent_receipt_events={d} consent_receipt_revocations={d} agent_delegation_events={d} agent_delegation_denials={d} agent_remote_call_events={d} agent_session_events={d} agent_session_denials={d} agent_kill_switch_denials={d}", .{
            summary.retention_policy_events,
            summary.permission_lease_events,
            summary.permission_lease_expirations,
            summary.consent_receipt_events,
            summary.consent_receipt_revocations,
            summary.agent_delegation_events,
            summary.agent_delegation_denials,
            summary.agent_remote_call_events,
            summary.agent_session_events,
            summary.agent_session_denials,
            summary.agent_kill_switch_denials,
        });
        try appendFmt(buffer, &used, " task_lifecycle_events={d} task_lifecycle_denials={d} task_lifecycle_terminations={d}", .{
            summary.task_lifecycle_events,
            summary.task_lifecycle_denials,
            summary.task_lifecycle_terminations,
        });
        try appendFmt(buffer, &used, " attention_policy_events={d} attention_interruptions_denied={d}", .{
            summary.attention_policy_events,
            summary.attention_interruptions_denied,
        });
        try appendFmt(buffer, &used, " accessibility_profile_events={d} accessibility_denials={d}", .{
            summary.accessibility_profile_events,
            summary.accessibility_denials,
        });
        try appendFmt(buffer, &used, " background_activity_events={d} background_activity_denials={d}", .{
            summary.background_activity_events,
            summary.background_activity_denials,
        });
        try appendFmt(buffer, &used, " resource_governance_events={d} resource_governance_delays={d} resource_governance_thermal_throttles={d} resource_governance_battery_preserves={d} resource_governance_hardware_evidence={d}", .{
            summary.resource_governance_events,
            summary.resource_governance_delays,
            summary.resource_governance_thermal_throttles,
            summary.resource_governance_battery_preserves,
            summary.resource_governance_hardware_evidence,
        });
        try appendFmt(buffer, &used, " network_session_events={d} network_session_denials={d} network_session_revocations={d} network_session_byte_denials={d} network_session_attested={d}", .{
            summary.network_session_events,
            summary.network_session_denials,
            summary.network_session_revocations,
            summary.network_session_byte_denials,
            summary.network_session_attested,
        });
        try appendFmt(buffer, &used, " pasteboard_events={d} pasteboard_denials={d}", .{
            summary.pasteboard_events,
            summary.pasteboard_denials,
        });
        try appendFmt(buffer, &used, " object_resilience_events={d} object_resilience_denials={d} object_restore_events={d}", .{
            summary.object_resilience_events,
            summary.object_resilience_denials,
            summary.object_restore_events,
        });
        try appendFmt(buffer, &used, " semantic_memory_events={d} semantic_memory_denials={d} semantic_memory_remote_denials={d} semantic_memory_receipt_events={d} semantic_memory_receipt_denials={d}", .{
            summary.semantic_memory_events,
            summary.semantic_memory_denials,
            summary.semantic_memory_remote_denials,
            summary.semantic_memory_receipt_events,
            summary.semantic_memory_receipt_denials,
        });
        try appendFmt(buffer, &used, " identity_credential_events={d} identity_credential_denials={d} identity_credential_recoveries={d} identity_credential_revocations={d} identity_credential_phishing_denials={d}", .{
            summary.identity_credential_events,
            summary.identity_credential_denials,
            summary.identity_credential_recoveries,
            summary.identity_credential_revocations,
            summary.identity_credential_phishing_denials,
        });
        try appendFmt(buffer, &used, " sensitive_capture_events={d} sensitive_capture_denials={d} sensitive_capture_background_denials={d}", .{
            summary.sensitive_capture_events,
            summary.sensitive_capture_denials,
            summary.sensitive_capture_background_denials,
        });
        try appendFmt(buffer, &used, " secret_vault_events={d} secret_vault_denials={d} secret_vault_raw_export_denials={d} secret_vault_rotations={d} secret_vault_revocations={d}", .{
            summary.secret_vault_events,
            summary.secret_vault_denials,
            summary.secret_vault_raw_export_denials,
            summary.secret_vault_rotations,
            summary.secret_vault_revocations,
        });
        return buffer[0..used];
    }

    pub fn renderAppDocumentKnowledgeToBuffer(
        self: *const Ledger,
        buffer: []u8,
        task_id: u64,
        document_resource: []const u8,
    ) Error![]const u8 {
        var prompt_count: usize = 0;
        var object_grant_count: usize = 0;
        var egress_route_count: usize = 0;
        var grant_ids: [MAX_EVENTS]u64 = [_]u64{0} ** MAX_EVENTS;
        var grant_id_count: usize = 0;
        var revocation_ids: [MAX_EVENTS]u64 = [_]u64{0} ** MAX_EVENTS;
        var revocation_id_count: usize = 0;
        var latest_object_capability: u64 = 0;
        var latest_egress_capability: u64 = 0;

        var task_cursor = self.task_index.head(taskKey(task_id));
        while (task_cursor != indexed_arena.no_index) : (task_cursor = self.task_index.next(task_cursor)) {
            const event = self.taskIndexedEvent(task_cursor);
            if (event.task_id != task_id) continue;

            switch (event.kind) {
                .capability_revocation => {
                    if (revocation_id_count < revocation_ids.len) {
                        revocation_ids[revocation_id_count] = event.related_id;
                        revocation_id_count += 1;
                    }
                },
                .permission_review, .permission_decision => {
                    if (eventMentionsDocument(event, document_resource)) prompt_count += 1;
                },
                .capability_grant => {
                    if (!eventMentionsDocument(event, document_resource)) continue;
                    if (event.permission_kind) |permission_kind| {
                        switch (permission_kind) {
                            .object_access, .contacts => {
                                object_grant_count += 1;
                                latest_object_capability = event.related_id;
                                if (grant_id_count < grant_ids.len) {
                                    grant_ids[grant_id_count] = event.related_id;
                                    grant_id_count += 1;
                                }
                            },
                            .network_egress => {
                                egress_route_count += 1;
                                latest_egress_capability = event.related_id;
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }

        var revoked_count: usize = 0;
        for (revocation_ids[0..revocation_id_count]) |revoked_id| {
            if (!containsCapabilityId(grant_ids[0..grant_id_count], revoked_id)) continue;
            revoked_count += 1;
        }

        const active_grants = if (revoked_count >= object_grant_count) 0 else object_grant_count - revoked_count;
        const knows = prompt_count != 0 or object_grant_count != 0 or egress_route_count != 0;
        var used: usize = 0;
        try appendFmt(buffer, &used, "App document knowledge: task={d} document={s} knows={s} prompts={d} object_grants={d} active_grants={d} revoked={d} egress_routes={d} data_can_leave={s}", .{
            task_id,
            document_resource,
            yesNo(knows),
            prompt_count,
            object_grant_count,
            active_grants,
            revoked_count,
            egress_route_count,
            yesNo(egress_route_count != 0),
        });
        if (latest_object_capability != 0) {
            try appendFmt(buffer, &used, " object_capability={d}", .{latest_object_capability});
        }
        if (latest_egress_capability != 0) {
            try appendFmt(buffer, &used, " egress_capability={d}", .{latest_egress_capability});
        }
        try appendFmt(buffer, &used, " revoke=Permission Review can revoke listed capability ids", .{});
        return buffer[0..used];
    }

    pub fn absorb(self: *Ledger, source: *const Ledger) Error!void {
        for (&source.events.slots) |*slot| {
            if (!slot.in_use) continue;
            var event = slot.event;
            event.sequence = 0;
            try self.append(event);
        }
    }

    fn append(self: *Ledger, event: Event) Error!void {
        try self.appendEvent(&event);
    }

    fn appendEvent(self: *Ledger, event: *const Event) Error!void {
        const sequence = self.next_sequence;
        var stored_event = event.*;
        stored_event.sequence = sequence;
        const event_slot = EventSlot{ .event = stored_event };
        const event_index = self.events.insertIndex(sequence, event_slot) orelse reserve: {
            // The live arena is a bounded most-recent-N ring: the persistence layer
            // already stages deletion of events older than MAX_PERSISTED_EVENTS
            // (see persistRange), so when the in-memory arena fills we evict the
            // oldest event rather than jamming with EventTableFull. Without this the
            // tamper-evident audit ledger would permanently stop accepting capability,
            // crash, and sensitive-capture records after MAX_EVENTS lifetime events.
            if (!self.evictOldestEvent()) return error.EventTableFull;
            break :reserve self.events.insertIndex(sequence, event_slot) orelse return error.EventTableFull;
        };
        const slot = &self.events.slots[event_index];
        self.next_sequence += 1;
        self.indexEvent(event_index) catch |err| {
            _ = self.events.removeIndex(event_index);
            try self.rebuildIndexes();
            return err;
        };
        if (self.persistence_batch_depth == 0) {
            try self.persistRange(slot.event.sequence, slot.event.sequence, slot.event.tick);
        } else {
            self.markPendingPersistence(&slot.event);
        }
    }

    fn evictOldestEvent(self: *Ledger) bool {
        var oldest_index: ?usize = null;
        var oldest_sequence: u64 = std.math.maxInt(u64);
        for (&self.events.slots, 0..) |*slot, index| {
            if (!slot.in_use) continue;
            if (slot.event.sequence < oldest_sequence) {
                oldest_sequence = slot.event.sequence;
                oldest_index = index;
            }
        }
        const index = oldest_index orelse return false;
        self.removeEventIndexes(index, &self.events.slots[index].event);
        return self.events.removeIndex(index);
    }

    fn visitMatching(
        self: *const Ledger,
        query: Query,
        limit: usize,
        count: *usize,
        output: ?[]Event,
    ) void {
        var selected_index: ?QueryIndex = null;
        var selected_count: usize = std.math.maxInt(usize);
        if (query.kind) |kind| {
            selected_index = .kind;
            selected_count = self.kind_index.count(kindKey(kind));
        }
        if (query.subject) |subject| {
            const candidate_count = self.subject_index.count(subjectKey(subject));
            if (candidate_count == 0) return;
            if (candidate_count < selected_count) {
                selected_index = .subject;
                selected_count = candidate_count;
            }
        }
        if (query.task_id) |task_id| {
            const candidate_count = self.task_index.count(taskKey(task_id));
            if (candidate_count == 0) return;
            if (candidate_count < selected_count) {
                selected_index = .task;
                selected_count = candidate_count;
            }
        }
        if (selected_index) |index_kind| {
            switch (index_kind) {
                .kind => self.visitIndex(&self.kind_index, kindKey(query.kind.?), query, limit, count, output),
                .subject => self.visitIndex(&self.subject_index, subjectKey(query.subject.?), query, limit, count, output),
                .task => self.visitIndex(&self.task_index, taskKey(query.task_id.?), query, limit, count, output),
            }
            return;
        }

        for (&self.events.slots) |*slot| {
            if (!slot.in_use) continue;
            if (!matchesQuery(&slot.event, query)) continue;
            if (count.* >= limit) break;
            if (output) |records| records[count.*] = redactedForQuery(&slot.event, query);
            count.* += 1;
        }
    }

    fn visitIndex(
        self: *const Ledger,
        index: anytype,
        key: u64,
        query: Query,
        limit: usize,
        count: *usize,
        output: ?[]Event,
    ) void {
        var cursor = index.head(key);
        while (cursor != indexed_arena.no_index and count.* < limit) : (cursor = index.next(cursor)) {
            const slot = &self.events.slots[cursor];
            if (!slot.in_use or !matchesQuery(&slot.event, query)) continue;
            if (output) |records| records[count.*] = redactedForQuery(&slot.event, query);
            count.* += 1;
        }
    }

    fn taskIndexedEvent(self: *const Ledger, cursor: usize) *const Event {
        if (cursor >= self.events.slots.len) native_util.impossibleByInvariant("event task index points outside slots");
        const slot = &self.events.slots[cursor];
        if (!slot.in_use) native_util.impossibleByInvariant("event task index points at a free slot");
        return &slot.event;
    }

    pub fn removeEventIndexes(self: *Ledger, event_index: usize, event: *const Event) void {
        if (!self.kind_index.remove(kindKey(event.kind), event_index)) {
            native_util.impossibleByInvariant("event kind index missing live event");
        }
        if (!self.subject_index.remove(subjectKey(event.subject), event_index)) {
            native_util.impossibleByInvariant("event subject index missing live event");
        }
        if (event.task_id != 0 and !self.task_index.remove(taskKey(event.task_id), event_index)) {
            native_util.impossibleByInvariant("event task index missing live event");
        }
    }

    fn indexEvent(self: *Ledger, event_index: usize) Error!void {
        const event = &self.events.slots[event_index].event;
        if (!self.kind_index.append(kindKey(event.kind), event_index)) return error.EventTableFull;
        if (!self.subject_index.append(subjectKey(event.subject), event_index)) return error.EventTableFull;
        if (event.task_id != 0 and !self.task_index.append(taskKey(event.task_id), event_index)) return error.EventTableFull;
    }

    fn rebuildIndexes(self: *Ledger) Error!void {
        self.kind_index.reset();
        self.subject_index.reset();
        self.task_index.reset();
        self.events.rebuildPrimaryIndex();
        for (self.events.slots, 0..) |slot, index| {
            if (!slot.in_use) continue;
            try self.indexEvent(index);
        }
    }

    fn markPendingPersistence(self: *Ledger, event: *const Event) void {
        if (self.storage == null) return;
        if (self.pending_persist_count == 0) {
            self.pending_persist_first_sequence = event.sequence;
        }
        self.pending_persist_count += 1;
        self.pending_persist_latest_tick = event.tick;
    }

    fn clearPendingPersistence(self: *Ledger) void {
        self.pending_persist_first_sequence = 0;
        self.pending_persist_count = 0;
        self.pending_persist_latest_tick = 0;
    }

    fn findEventBySequence(self: *const Ledger, sequence: u64) ?Event {
        const slot = self.events.getConst(sequence) orelse return null;
        return slot.event;
    }

    fn persistRange(self: *Ledger, first_sequence: u64, latest_sequence: u64, latest_tick: u64) Error!void {
        const storage = self.storage orelse return;
        var header = PersistentHeader{ .next_sequence = self.next_sequence };
        const header_payload = std.mem.asBytes(&header);
        const previous_header_version_id = if (self.header_version_id != 0)
            self.header_version_id
        else blk: {
            const existing_header = storage.resolve(self.workspace_id, state_entry_path) catch |err| switch (err) {
                error.EntryNotFound => break :blk 0,
                else => return err,
            };
            break :blk existing_header.version_id.raw();
        };

        try storage.beginTransaction(self.workspace_id);
        // A failed append must not leave the ledger workspace's transaction
        // open: every later append would then die with TransactionAlreadyOpen,
        // turning one transient storage error into a permanently wedged ledger.
        errdefer storage.abortTransaction(self.workspace_id) catch {};
        var expired_sequence = first_sequence;
        while (expired_sequence <= latest_sequence) : (expired_sequence += 1) {
            if (expired_sequence <= MAX_PERSISTED_EVENTS) continue;
            var expired_path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
            const expired_path = expired_path_buffer[0..try writeEventEntryPath(
                &expired_path_buffer,
                expired_sequence - MAX_PERSISTED_EVENTS,
            )];
            storage.stageDelete(self.workspace_id, expired_path) catch |err| switch (err) {
                error.EntryNotFound => {},
                else => return err,
            };
        }

        const header_result = try storage.putVersion(.{
            .preferred_object_id = object_store.ids.object(stateObjectId()),
            .object_type = .document,
            .payload = header_payload,
            .metadata = try signLedgerMetadata(
                self.state_signer,
                "event-ledger-state",
                "application/zigos-event-ledger",
                .document,
                header_payload,
                latest_tick,
            ),
            .parent_version_id = if (previous_header_version_id != 0) object_store.ids.version(previous_header_version_id) else null,
        });
        try storage.stagePut(self.workspace_id, state_entry_path, header_result.object_id, header_result.version_id, .document);
        self.header_version_id = header_result.version_id.raw();

        var sequence = first_sequence;
        while (sequence <= latest_sequence) : (sequence += 1) {
            const event = self.findEventBySequence(sequence) orelse return error.CorruptState;
            var event_path_buffer: [workspace.MAX_ENTRY_PATH_BYTES]u8 = undefined;
            const event_path = event_path_buffer[0..try writeEventEntryPath(&event_path_buffer, event.sequence)];
            var payload_record = PersistentEventRecord.fromEvent(PersistentEvent.fromEvent(event));
            const payload = std.mem.asBytes(&payload_record);
            const result = try storage.putVersion(.{
                .preferred_object_id = object_store.ids.object(eventObjectId(event.sequence)),
                .object_type = .document,
                .payload = payload,
                .metadata = try signLedgerMetadata(
                    self.state_signer,
                    "event-ledger-entry",
                    "application/zigos-event-ledger-entry",
                    .document,
                    payload,
                    event.tick,
                ),
                .parent_version_id = null,
            });
            try storage.stagePut(self.workspace_id, event_path, result.object_id, result.version_id, .document);
        }

        _ = try storage.commit(self.workspace_id, latest_tick);
    }

    fn loadPersistedEvents(self: *Ledger) Error!void {
        const storage = self.storage orelse return;
        self.events.reset();
        try self.rebuildIndexes();
        self.next_sequence = 1;
        self.header_version_id = 0;

        if (storage.resolve(self.workspace_id, state_entry_path)) |entry| {
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            self.next_sequence = try parseHeader(try storage.versionPayload(version));
            self.header_version_id = entry.version_id.raw();
        } else |err| switch (err) {
            error.EntryNotFound => return,
            else => return err,
        }

        const entries = try storage.entries(self.workspace_id);
        var loaded_count: usize = 0;
        for (entries) |entry| {
            if (!std.mem.startsWith(u8, entry.pathSlice(), event_entry_prefix)) continue;
            if (loaded_count >= MAX_EVENTS) break;
            const version = storage.version(entry.version_id) orelse return error.CorruptState;
            const event = (try parsePersistentEvent(try storage.versionPayload(version))).intoEvent();
            const slot_index = self.events.reserveIndexAt(event.sequence, loaded_count) orelse return error.CorruptState;
            self.events.slots[slot_index].event = event;
            loaded_count += 1;
        }

        var index: usize = 1;
        while (index < loaded_count) : (index += 1) {
            var cursor = index;
            while (cursor > 0 and self.events.slots[cursor - 1].event.sequence > self.events.slots[cursor].event.sequence) : (cursor -= 1) {
                const tmp = self.events.slots[cursor - 1];
                self.events.slots[cursor - 1] = self.events.slots[cursor];
                self.events.slots[cursor] = tmp;
            }
        }

        if (loaded_count > 0 and self.next_sequence <= self.events.slots[loaded_count - 1].event.sequence) {
            self.next_sequence = self.events.slots[loaded_count - 1].event.sequence + 1;
        }
        try self.rebuildIndexes();
    }
};

const PersistentEvent = struct {
    sequence: u64 = 0,
    kind: EventKind = .permission_decision,
    tick: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    related_id: u64 = 0,
    detail_code: u32 = 0,
    service_class: contract.ServiceClass = .task_runtime,
    permission_kind: ?manifest.PermissionKind = null,
    allowed: bool = false,
    denial_reason: abi.DenialReason = .none,
    user_approval_can_resolve: bool = false,
    retry_safe: bool = false,
    detail_protected: bool = false,
    policy_label_len: usize = 0,
    policy_label: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    missing_capability_len: usize = 0,
    missing_capability: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    detail_len: usize = 0,
    detail: [MAX_PERSISTED_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_DETAIL_BYTES,

    fn fromEvent(event: Event) PersistentEvent {
        var persisted = zeroPersistentEvent();
        persisted.sequence = event.sequence;
        persisted.kind = event.kind;
        persisted.tick = event.tick;
        persisted.subject = event.subject;
        persisted.task_id = event.task_id;
        persisted.workspace_id = event.workspace_id;
        persisted.related_id = event.related_id;
        persisted.detail_code = event.detail_code;
        persisted.service_class = event.service_class;
        persisted.permission_kind = event.permission_kind;
        persisted.allowed = event.allowed;
        persisted.denial_reason = event.denial_reason;
        persisted.user_approval_can_resolve = event.user_approval_can_resolve;
        persisted.retry_safe = event.retry_safe;
        persisted.detail_protected = event.detail_protected;
        persisted.policy_label_len = copyText(&persisted.policy_label, event.policyLabelSlice());
        persisted.missing_capability_len = copyText(&persisted.missing_capability, event.missingCapabilitySlice());
        persisted.detail_len = copyText(&persisted.detail, event.detailSlice());
        return persisted;
    }

    fn intoEvent(self: PersistentEvent) Event {
        var event = zeroEvent();
        event.sequence = self.sequence;
        event.kind = self.kind;
        event.tick = self.tick;
        event.subject = self.subject;
        event.task_id = self.task_id;
        event.workspace_id = self.workspace_id;
        event.related_id = self.related_id;
        event.detail_code = self.detail_code;
        event.service_class = self.service_class;
        event.permission_kind = self.permission_kind;
        event.allowed = self.allowed;
        event.denial_reason = self.denial_reason;
        event.user_approval_can_resolve = self.user_approval_can_resolve;
        event.retry_safe = self.retry_safe;
        event.detail_protected = self.detail_protected;
        event.policy_label_len = copyText(&event.policy_label, self.policy_label[0..self.policy_label_len]);
        event.missing_capability_len = copyText(&event.missing_capability, self.missing_capability[0..self.missing_capability_len]);
        event.detail_len = copyText(&event.detail, self.detail[0..self.detail_len]);
        return event;
    }
};

const PersistentEventRecord = extern struct {
    sequence: u64 = 0,
    kind: u8 = 0,
    subject_kind: u8 = 0,
    service_class: u8 = 0,
    permission_kind: u8 = permission_kind_none,
    denial_reason: u16 = 0,
    flags: u8 = 0,
    policy_label_len: u8 = 0,
    missing_capability_len: u8 = 0,
    detail_len: u16 = 0,
    _reserved: [PERSISTENT_EVENT_RESERVED_BYTES]u8 = [_]u8{0} ** PERSISTENT_EVENT_RESERVED_BYTES,
    tick: u64 = 0,
    subject_serial: u64 = 0,
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    related_id: u64 = 0,
    detail_code: u32 = 0,
    _tail_reserved: [PERSISTENT_EVENT_TAIL_RESERVED_BYTES]u8 = [_]u8{0} ** PERSISTENT_EVENT_TAIL_RESERVED_BYTES,
    policy_label: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    missing_capability: [MAX_PERSISTED_LABEL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_LABEL_BYTES,
    detail: [MAX_PERSISTED_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_PERSISTED_DETAIL_BYTES,

    fn fromEvent(event: PersistentEvent) PersistentEventRecord {
        var record = PersistentEventRecord{
            .sequence = event.sequence,
            .kind = @intFromEnum(event.kind),
            .subject_kind = @intFromEnum(event.subject.kind),
            .service_class = @intFromEnum(event.service_class),
            .permission_kind = if (event.permission_kind) |permission_kind| @intFromEnum(permission_kind) else permission_kind_none,
            .denial_reason = @intFromEnum(event.denial_reason),
            .tick = event.tick,
            .subject_serial = event.subject.serial,
            .task_id = event.task_id,
            .workspace_id = event.workspace_id,
            .related_id = event.related_id,
            .detail_code = event.detail_code,
            .policy_label_len = @intCast(event.policy_label_len),
            .missing_capability_len = @intCast(event.missing_capability_len),
            .detail_len = @intCast(event.detail_len),
            .policy_label = event.policy_label,
            .missing_capability = event.missing_capability,
            .detail = event.detail,
        };
        if (event.allowed) record.flags |= persistent_event_flag_allowed;
        if (event.user_approval_can_resolve) record.flags |= persistent_event_flag_user_approval_can_resolve;
        if (event.retry_safe) record.flags |= persistent_event_flag_retry_safe;
        if (event.detail_protected) record.flags |= persistent_event_flag_detail_protected;
        return record;
    }

    fn intoEvent(self: PersistentEventRecord) Error!PersistentEvent {
        var event = zeroPersistentEvent();
        event.sequence = self.sequence;
        event.kind = std.enums.fromInt(EventKind, self.kind) orelse return error.CorruptState;
        event.tick = self.tick;
        event.subject = .{
            .kind = std.enums.fromInt(principal.PrincipalKind, self.subject_kind) orelse return error.CorruptState,
            .serial = self.subject_serial,
        };
        event.task_id = self.task_id;
        event.workspace_id = self.workspace_id;
        event.related_id = self.related_id;
        event.detail_code = self.detail_code;
        event.service_class = std.enums.fromInt(contract.ServiceClass, self.service_class) orelse return error.CorruptState;
        event.permission_kind = if (self.permission_kind == permission_kind_none)
            null
        else
            (std.enums.fromInt(manifest.PermissionKind, self.permission_kind) orelse return error.CorruptState);
        event.allowed = (self.flags & persistent_event_flag_allowed) != 0;
        event.denial_reason = std.enums.fromInt(abi.DenialReason, self.denial_reason) orelse return error.CorruptState;
        event.user_approval_can_resolve = (self.flags & persistent_event_flag_user_approval_can_resolve) != 0;
        event.retry_safe = (self.flags & persistent_event_flag_retry_safe) != 0;
        event.detail_protected = (self.flags & persistent_event_flag_detail_protected) != 0;
        event.policy_label_len = @min(@as(usize, self.policy_label_len), MAX_PERSISTED_LABEL_BYTES);
        event.missing_capability_len = @min(@as(usize, self.missing_capability_len), MAX_PERSISTED_LABEL_BYTES);
        event.detail_len = @min(@as(usize, self.detail_len), MAX_PERSISTED_DETAIL_BYTES);
        event.policy_label = self.policy_label;
        event.missing_capability = self.missing_capability;
        event.detail = self.detail;
        return event;
    }
};

fn zeroEvent() Event {
    return .{
        .sequence = 0,
        .kind = .permission_decision,
        .tick = 0,
        .subject = .{ .kind = .service, .serial = 0 },
    };
}

fn zeroPersistentEvent() PersistentEvent {
    return .{};
}

fn clampedDetailLen(src: []const u8) usize {
    return @min(src.len, MAX_DETAIL_BYTES);
}

fn clampedExplanationLen(src: []const u8) usize {
    return @min(src.len, denial_explanation.MAX_LABEL_BYTES);
}

fn copyTextInto(src: []const u8) [MAX_DETAIL_BYTES]u8 {
    var out = [_]u8{0} ** MAX_DETAIL_BYTES;
    _ = copyText(&out, src);
    return out;
}

fn copyExplanationTextInto(src: []const u8) [denial_explanation.MAX_LABEL_BYTES]u8 {
    var out = [_]u8{0} ** denial_explanation.MAX_LABEL_BYTES;
    _ = copyText(&out, src);
    return out;
}

fn updateFailureLabel(code: u32) []const u8 {
    const failure = std.enums.fromInt(immutable_base.HealthFailure, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(failure);
}

fn notificationReasonLabel(code: u32) []const u8 {
    if (code > std.math.maxInt(u8)) return "corrupt";
    const reason = std.enums.fromInt(notification_center.Reason, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(reason);
}

fn flowKindLabel(code: u32) []const u8 {
    if (code > std.math.maxInt(u8)) return "corrupt";
    const kind = std.enums.fromInt(native_ux.FlowKind, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(kind);
}

fn policyChangeActionLabel(code: u32) []const u8 {
    if (code > std.math.maxInt(u8)) return "corrupt";
    const action = std.enums.fromInt(PolicyChangeAction, @as(u8, @intCast(code))) orelse return "corrupt";
    return @tagName(action);
}

fn taskLifecycleOperation(code: u32) TaskLifecycleOperation {
    return std.enums.fromInt(TaskLifecycleOperation, @as(u8, @intCast(code & 0xff))) orelse .terminate_task;
}

fn networkSessionAction(code: u32) NetworkSessionAction {
    return std.enums.fromInt(NetworkSessionAction, @as(u8, @intCast(code & 0xff))) orelse .open;
}

fn networkSessionReason(code: u32) NetworkSessionReason {
    return std.enums.fromInt(NetworkSessionReason, @as(u8, @intCast((code >> @as(u5, 8)) & 0xff))) orelse .none;
}

fn networkSessionAttested(code: u32) bool {
    return (code & (@as(u32, 1) << @as(u5, 29))) != 0;
}

fn networkSessionIdentityPinned(code: u32) bool {
    return (code & (@as(u32, 1) << @as(u5, 30))) != 0;
}

fn networkSessionPrivateData(code: u32) bool {
    return (code & (@as(u32, 1) << @as(u5, 31))) != 0;
}

fn semanticMemoryReceiptAudit(code: u32) bool {
    return (code & semantic_memory_flag_receipt_audit) != 0;
}

fn resourceGovernanceReason(code: u32) accelerator_scheduler.DecisionReason {
    return std.enums.fromInt(accelerator_scheduler.DecisionReason, @as(u8, @intCast(code & 0xff))) orelse .normal;
}

fn resourceGovernanceClass(code: u32) accelerator_scheduler.ResourceClass {
    return std.enums.fromInt(accelerator_scheduler.ResourceClass, @as(u8, @intCast((code >> @as(u5, 8)) & 0xff))) orelse .foreground_interactive;
}

fn resourceGovernanceDegraded(code: u32) bool {
    return (code & (@as(u32, 1) << @as(u5, 29))) != 0;
}

fn resourceGovernanceObservedTelemetry(code: u32) bool {
    return (code & (@as(u32, 1) << @as(u5, 30))) != 0;
}

fn resourceGovernanceHardwareEvidence(code: u32) bool {
    return (code & (@as(u32, 1) << @as(u5, 31))) != 0;
}

fn kindKey(kind: EventKind) u64 {
    return @as(u64, @intFromEnum(kind)) + 1;
}

fn subjectKey(subject: principal.PrincipalId) u64 {
    var hash: u64 = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(subject.kind));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, subject.serial);
    return indexed_arena.nonZeroKey(hash);
}

fn taskKey(task_id: u64) u64 {
    return indexed_arena.nonZeroKey(task_id);
}

fn matchesQuery(event: *const Event, query: Query) bool {
    if (query.kind) |kind| {
        if (event.kind != kind) return false;
    }
    if (query.subject) |subject| {
        if (!event.subject.eql(subject)) return false;
    }
    if (query.task_id) |task_id| {
        if (event.task_id != task_id) return false;
    }
    if (query.workspace_id) |workspace_id| {
        if (event.workspace_id != workspace_id) return false;
    }
    return true;
}

fn eventMentionsDocument(event: *const Event, document_resource: []const u8) bool {
    return document_resource.len != 0 and std.mem.indexOf(u8, event.detailSlice(), document_resource) != null;
}

fn containsCapabilityId(capability_ids: []const u64, capability_id: u64) bool {
    for (capability_ids) |candidate| {
        if (candidate == capability_id) return true;
    }
    return false;
}

fn redactedForQuery(event: *const Event, query: Query) Event {
    if (!event.detail_protected or query.include_protected_content) return event.*;
    var redacted = event.*;
    redacted.detail_len = copyText(&redacted.detail, "redacted");
    return redacted;
}

fn renderTextEvent(event: *const Event, buffer: []u8, used: *usize, include_protected_content: bool) Error!void {
    const detail = exportDetailSlice(event, include_protected_content);
    try appendText(buffer, used, "#");
    try appendUnsigned(buffer, used, event.sequence);
    try appendText(buffer, used, " tick=");
    try appendUnsigned(buffer, used, event.tick);
    try appendText(buffer, used, " kind=");
    try appendText(buffer, used, @tagName(event.kind));
    try appendText(buffer, used, " subject=");
    try appendText(buffer, used, @tagName(event.subject.kind));
    try appendText(buffer, used, ":");
    try appendUnsigned(buffer, used, event.subject.serial);
    if (event.permission_kind) |permission_kind| {
        try appendFmt(buffer, used, " permission={s} allowed={s}", .{
            @tagName(permission_kind),
            yesNo(event.allowed),
        });
        if (!event.allowed) {
            try appendFmt(buffer, used, " denial={s} policy={s} missing={s} approval={s} retry_safe={s}", .{
                @tagName(event.denial_reason),
                event.policyLabelSlice(),
                event.missingCapabilitySlice(),
                yesNo(event.user_approval_can_resolve),
                yesNo(event.retry_safe),
            });
            var blocked_buffer: [DENIAL_HELP_BUFFER_BYTES]u8 = undefined;
            const blocked = denial_explanation.renderUserHelpToBuffer(
                &blocked_buffer,
                "This app",
                permission_kind,
                detail,
                .{
                    .reason = event.denial_reason,
                    .user_approval_can_resolve = event.user_approval_can_resolve,
                    .retry_safe = event.retry_safe,
                },
            ) catch "Blocked: open Permission Review for details.";
            try appendFmt(buffer, used, " blocked_help=\"{s}\"", .{blocked});
        }
    }
    switch (event.kind) {
        .update_transition => {
            try appendText(buffer, used, " slot=");
            try appendUnsigned(buffer, used, event.related_id);
            try appendText(buffer, used, " rollback=");
            try appendText(buffer, used, yesNo(!event.allowed));
            try appendText(buffer, used, " failure=");
            try appendText(buffer, used, updateFailureLabel(event.detail_code));
        },
        .device_trust_change => {
            try appendText(buffer, used, " device=");
            try appendUnsigned(buffer, used, event.related_id);
            try appendText(buffer, used, " trusted=");
            try appendText(buffer, used, yesNo(event.allowed));
        },
        .capability_grant, .capability_revocation => {
            try appendFmt(buffer, used, " capability={d}", .{event.related_id});
        },
        .notification => {
            try appendFmt(buffer, used, " notification={d} reason={s} visible={s}", .{
                event.related_id,
                notificationReasonLabel(event.detail_code),
                yesNo(event.allowed),
            });
        },
        .task_flow => {
            try appendFmt(buffer, used, " flow={d} flow_kind={s} approved={s}", .{
                event.related_id,
                flowKindLabel(event.detail_code),
                yesNo(event.allowed),
            });
        },
        .policy_change => {
            try appendFmt(buffer, used, " policy={d} action={s}", .{
                event.related_id,
                policyChangeActionLabel(event.detail_code),
            });
        },
        .task_lifecycle => {
            try appendFmt(buffer, used, " task_lifecycle operation={s} checkpoint={s} allowed={s}", .{
                @tagName(taskLifecycleOperation(event.detail_code)),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 31))) != 0),
                yesNo(event.allowed),
            });
        },
        .attention_policy => {
            try appendFmt(buffer, used, " attention_policy interruptive={s} active_visible={d} active_interruptions={d} allowed={s}", .{
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 31))) != 0),
                (event.detail_code >> @as(u5, 16)) & 0x7fff,
                event.detail_code & 0xffff,
                yesNo(event.allowed),
            });
        },
        .agent_session => {
            try appendFmt(buffer, used, " agent_session session_bound={s} local_context={s} kill_switch_block={s} generation={d} allowed={s}", .{
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 31))) != 0),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 30))) != 0),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 29))) != 0),
                event.detail_code & 0x1fff_ffff,
                yesNo(event.allowed),
            });
        },
        .accessibility_profile => {
            try appendFmt(buffer, used, " accessibility screen_reader={s} keyboard={s} reduced_motion={s} high_contrast={s} allowed={s}", .{
                yesNo((event.detail_code & 1) != 0),
                yesNo((event.detail_code & 2) != 0),
                yesNo((event.detail_code & 4) != 0),
                yesNo((event.detail_code & 8) != 0),
                yesNo(event.allowed),
            });
        },
        .background_activity => {
            try appendFmt(buffer, used, " background_activity remote_network={s} user_visible={s} duration={d}s allowed={s}", .{
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 31))) != 0),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 30))) != 0),
                event.detail_code & 0x3fff_ffff,
                yesNo(event.allowed),
            });
        },
        .resource_governance => {
            try appendFmt(buffer, used, " resource_governance class={s} reason={s} delayed={s} degraded={s} observed_telemetry={s} hardware_evidence={s}", .{
                @tagName(resourceGovernanceClass(event.detail_code)),
                @tagName(resourceGovernanceReason(event.detail_code)),
                yesNo(!event.allowed),
                yesNo(resourceGovernanceDegraded(event.detail_code)),
                yesNo(resourceGovernanceObservedTelemetry(event.detail_code)),
                yesNo(resourceGovernanceHardwareEvidence(event.detail_code)),
            });
        },
        .network_session => {
            try appendFmt(buffer, used, " network_session action={s} reason={s} allowed={s} attested={s} identity_pinned={s} private_data={s}", .{
                @tagName(networkSessionAction(event.detail_code)),
                @tagName(networkSessionReason(event.detail_code)),
                yesNo(event.allowed),
                yesNo(networkSessionAttested(event.detail_code)),
                yesNo(networkSessionIdentityPinned(event.detail_code)),
                yesNo(networkSessionPrivateData(event.detail_code)),
            });
        },
        .semantic_memory => {
            try appendFmt(buffer, used, " semantic_memory receipt_audit={s} local_model={s} encrypted_index={s} redacted_snippets={s} query_bytes={d} allowed={s}", .{
                yesNo(semanticMemoryReceiptAudit(event.detail_code)),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 31))) != 0),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 30))) != 0),
                yesNo((event.detail_code & (@as(u32, 1) << @as(u5, 29))) != 0),
                event.detail_code & @as(u32, @intCast(semantic_memory_query_byte_mask)),
                yesNo(event.allowed),
            });
        },
        .suspicious_app_behavior => {
            try appendFmt(buffer, used, " app_behavior=suspicious", .{});
        },
        else => {},
    }
    if (event.workspace_id != 0) {
        try appendText(buffer, used, " workspace=");
        try appendUnsigned(buffer, used, event.workspace_id);
    }
    if (event.related_id != 0 and event.kind != .update_transition and event.kind != .device_trust_change) {
        try appendText(buffer, used, " related=");
        try appendUnsigned(buffer, used, event.related_id);
    }
    if (event.detail_code != 0 and event.kind != .update_transition) {
        try appendText(buffer, used, " code=");
        try appendUnsigned(buffer, used, event.detail_code);
    }
    if (event.kind == .process_crash or event.kind == .driver_restart) {
        try appendText(buffer, used, " service=");
        try appendText(buffer, used, @tagName(event.service_class));
    }
    try appendText(buffer, used, " detail=");
    try appendText(buffer, used, detail);
    try appendText(buffer, used, "\n");
}

fn exportDetailSlice(event: *const Event, include_protected_content: bool) []const u8 {
    if (event.detail_protected and !include_protected_content) return "redacted";
    return event.detailSlice();
}

fn appendText(buffer: []u8, used: *usize, value: []const u8) Error!void {
    if (value.len > buffer.len -| used.*) return error.NoSpaceLeft;
    @memcpy(buffer[used.*..][0..value.len], value);
    used.* += value.len;
}

fn appendUnsigned(buffer: []u8, used: *usize, value: anytype) Error!void {
    var number_buffer: [20]u8 = undefined;
    const number_len = std.fmt.printInt(&number_buffer, value, 10, .lower, .{});
    try appendText(buffer, used, number_buffer[0..number_len]);
}

fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) Error!void {
    const rendered = std.fmt.bufPrint(buffer[used.*..], fmt, args) catch return error.NoSpaceLeft;
    used.* += rendered.len;
}

fn signLedgerMetadata(
    identity: signing.SignerIdentity,
    label: []const u8,
    content_type: []const u8,
    object_type: object_store.ObjectType,
    payload: []const u8,
    created_at_ticks: u64,
) Error!object_store.SignedMetadata {
    return object_store.signMetadata(
        identity,
        label,
        content_type,
        object_type,
        payload,
        created_at_ticks,
    ) catch error.SigningFailed;
}

fn stateObjectId() u64 {
    return native_util.fnv1a64WithSeed(0xED6E7EEC0D000001, "platform:event-ledger:state");
}

fn eventObjectId(sequence: u64) u64 {
    const slot_index = @as(usize, @intCast((sequence - 1) % MAX_PERSISTED_EVENTS));
    return native_util.fnv1a64WithSeed(
        0xED6E7EEC0D000101 + @as(u64, @intCast(slot_index)),
        "platform:event-ledger:event-slot",
    );
}

fn parseHeader(payload: []const u8) Error!u64 {
    if (payload.len != @sizeOf(PersistentHeader)) return error.CorruptState;
    var header = std.mem.zeroes(PersistentHeader);
    @memcpy(std.mem.asBytes(&header), payload);
    if (header.magic != persistent_header_magic) return error.CorruptState;
    return header.next_sequence;
}

fn parsePersistentEvent(payload: []const u8) Error!PersistentEvent {
    if (payload.len != @sizeOf(PersistentEventRecord)) return error.CorruptState;
    var record = std.mem.zeroes(PersistentEventRecord);
    @memcpy(std.mem.asBytes(&record), payload);
    return record.intoEvent();
}

fn writeEventEntryPath(buffer: []u8, sequence: u64) Error!usize {
    const path = std.fmt.bufPrint(buffer, "{s}{d}", .{ event_entry_prefix, sequence }) catch return error.NoSpaceLeft;
    return path.len;
}
