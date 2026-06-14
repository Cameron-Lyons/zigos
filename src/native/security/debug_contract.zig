const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_DETAIL_BYTES: usize = 96;
const DENIAL_RENDER_TEST_BUFFER_BYTES: usize = 256;

pub const Decision = enum(u8) {
    allowed,
    denied,
};

pub const ProvenanceKind = enum(u8) {
    none,
    launch,
    service_call,
    syscall,
    capability_grant,
    capability_revoke,
    crash_report,
};

pub const DenialExplanation = struct {
    reason: abi.DenialReason = .none,
    subject_task_id: u64 = 0,
    capability_id: u64 = 0,
    target_id: u64 = 0,
    target_kind: ?capability.CapabilityTargetKind = null,
    operation_len: usize = 0,
    operation: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    required_authority_len: usize = 0,
    required_authority: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    blocking_policy_len: usize = 0,
    blocking_policy: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    user_action_available: bool = false,
    retry_safe: bool = false,
    fingerprint: u64 = 0,

    pub fn operationSlice(self: *const DenialExplanation) []const u8 {
        return self.operation[0..self.operation_len];
    }

    pub fn requiredAuthoritySlice(self: *const DenialExplanation) []const u8 {
        return self.required_authority[0..self.required_authority_len];
    }

    pub fn blockingPolicySlice(self: *const DenialExplanation) []const u8 {
        return self.blocking_policy[0..self.blocking_policy_len];
    }

    pub fn render(self: *const DenialExplanation, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(
            buffer,
            "reason={s} operation={s} required={s} policy={s} subject_task={d} capability={d} target={s}:{d} user_action={s} retry_safe={s} fingerprint=0x{x}",
            .{
                @tagName(self.reason),
                self.operationSlice(),
                self.requiredAuthoritySlice(),
                self.blockingPolicySlice(),
                self.subject_task_id,
                self.capability_id,
                if (self.target_kind) |kind| @tagName(kind) else "none",
                self.target_id,
                native_util.yesNo(self.user_action_available),
                native_util.yesNo(self.retry_safe),
                self.fingerprint,
            },
        ) catch "";
    }
};

pub const ProvenanceRecord = struct {
    kind: ProvenanceKind = .none,
    decision: Decision = .allowed,
    trace_id: u64 = 0,
    parent_trace_id: u64 = 0,
    task_id: u64 = 0,
    artifact_id: u64 = 0,
    service_id: u64 = 0,
    capability_id: u64 = 0,
    target_id: u64 = 0,
    target_kind: ?capability.CapabilityTargetKind = null,
    tick: u64 = 0,
    operation_len: usize = 0,
    operation: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    detail_len: usize = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,
    denial: DenialExplanation = .{},

    pub fn operationSlice(self: *const ProvenanceRecord) []const u8 {
        return self.operation[0..self.operation_len];
    }

    pub fn detailSlice(self: *const ProvenanceRecord) []const u8 {
        return self.detail[0..self.detail_len];
    }

    pub fn render(self: *const ProvenanceRecord, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(
            buffer,
            "trace=0x{x} parent=0x{x} tick={d} kind={s} decision={s} task={d} artifact={d} service={d} capability={d} target={s}:{d} operation={s} detail={s} reason={s}",
            .{
                self.trace_id,
                self.parent_trace_id,
                self.tick,
                @tagName(self.kind),
                @tagName(self.decision),
                self.task_id,
                self.artifact_id,
                self.service_id,
                self.capability_id,
                if (self.target_kind) |kind| @tagName(kind) else "none",
                self.target_id,
                self.operationSlice(),
                self.detailSlice(),
                @tagName(self.denial.reason),
            },
        ) catch "";
    }
};

pub const AuthorityGraphEdge = struct {
    task_id: u64 = 0,
    capability_id: u64 = 0,
    holder: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    issuer: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    target_kind: capability.CapabilityTargetKind = .task,
    target_id: u64 = 0,
    rights: u64 = 0,
    scope_task_id: u64 = 0,
    scope_workspace_id: u64 = 0,
    policy_generation: u32 = 0,
    source_task_id: u64 = 0,
    broker_service_id: u64 = 0,
    trace_id: u64 = 0,
    parent_trace_id: u64 = 0,
    expires_at_ticks: u64 = 0,
    revocation_generation: u32 = 0,
    usable: bool = false,

    pub fn render(self: *const AuthorityGraphEdge, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(
            buffer,
            "task={d} capability={d} holder={s}:{d} issuer={s}:{d} target={s}:{d} rights=0x{x} scope_task={d} scope_workspace={d} policy_generation={d} source_task={d} broker_service={d} trace=0x{x} parent=0x{x} expires={d} generation={d} usable={s}",
            .{
                self.task_id,
                self.capability_id,
                @tagName(self.holder.kind),
                self.holder.serial,
                @tagName(self.issuer.kind),
                self.issuer.serial,
                @tagName(self.target_kind),
                self.target_id,
                self.rights,
                self.scope_task_id,
                self.scope_workspace_id,
                self.policy_generation,
                self.source_task_id,
                self.broker_service_id,
                self.trace_id,
                self.parent_trace_id,
                self.expires_at_ticks,
                self.revocation_generation,
                native_util.yesNo(self.usable),
            },
        ) catch "";
    }
};

pub fn explainDenied(
    reason: abi.DenialReason,
    operation: []const u8,
    required_authority: []const u8,
    subject_task_id: u64,
    capability_id: u64,
    target_kind: ?capability.CapabilityTargetKind,
    target_id: u64,
) DenialExplanation {
    var explanation = DenialExplanation{
        .reason = reason,
        .subject_task_id = subject_task_id,
        .capability_id = capability_id,
        .target_id = target_id,
        .target_kind = target_kind,
        .user_action_available = userActionCanResolve(reason),
        .retry_safe = retrySafe(reason),
    };
    explanation.operation_len = native_util.copyTextWithReserve(&explanation.operation, operation, 1);
    explanation.required_authority_len = native_util.copyTextWithReserve(&explanation.required_authority, required_authority, 1);
    explanation.blocking_policy_len = native_util.copyTextWithReserve(&explanation.blocking_policy, policyLabel(reason), 1);
    explanation.fingerprint = denialFingerprint(explanation);
    return explanation;
}

pub fn provenance(
    kind: ProvenanceKind,
    decision: Decision,
    tick: u64,
    task_id: u64,
    service_id: u64,
    capability_id: u64,
    target_kind: ?capability.CapabilityTargetKind,
    target_id: u64,
    operation: []const u8,
    detail: []const u8,
    denial: DenialExplanation,
    parent_trace_id: u64,
) ProvenanceRecord {
    var record = ProvenanceRecord{
        .kind = kind,
        .decision = decision,
        .parent_trace_id = parent_trace_id,
        .task_id = task_id,
        .service_id = service_id,
        .capability_id = capability_id,
        .target_kind = target_kind,
        .target_id = target_id,
        .tick = tick,
        .denial = denial,
    };
    record.operation_len = native_util.copyTextWithReserve(&record.operation, operation, 1);
    record.detail_len = native_util.copyTextWithReserve(&record.detail, detail, 1);
    record.trace_id = provenanceFingerprint(record);
    return record;
}

pub fn launchProvenance(
    task_id: u64,
    tick: u64,
    image_id: u64,
    signed: bool,
    operation: []const u8,
    bundle_id: []const u8,
) ProvenanceRecord {
    var record = provenance(
        .launch,
        .allowed,
        tick,
        task_id,
        0,
        0,
        .task,
        task_id,
        operation,
        if (bundle_id.len != 0) bundle_id else if (signed) "signed-launch" else "direct-launch",
        .{},
        0,
    );
    record.artifact_id = image_id;
    record.trace_id = provenanceFingerprint(record);
    return record;
}

pub fn serviceCallProvenance(
    decision: Decision,
    tick: u64,
    task_id: u64,
    service_id: u64,
    capability_id: u64,
    required_right: capability.CapabilityRight,
    reason: abi.DenialReason,
    operation: []const u8,
) ProvenanceRecord {
    const explanation = if (decision == .denied)
        explainDenied(reason, operation, @tagName(required_right), task_id, capability_id, .service, service_id)
    else
        DenialExplanation{};
    return provenance(
        .service_call,
        decision,
        tick,
        task_id,
        service_id,
        capability_id,
        .service,
        service_id,
        operation,
        @tagName(required_right),
        explanation,
        0,
    );
}

pub fn capabilityGrantProvenance(task_id: u64, capability_id: u64, tick: u64) ProvenanceRecord {
    return provenance(
        .capability_grant,
        .allowed,
        tick,
        task_id,
        0,
        capability_id,
        null,
        0,
        "capability-grant",
        "task-authority-graph",
        .{},
        0,
    );
}

pub fn capabilityRevokeProvenance(task_id: u64, capability_id: u64, tick: u64) ProvenanceRecord {
    return provenance(
        .capability_revoke,
        .allowed,
        tick,
        task_id,
        0,
        capability_id,
        null,
        0,
        "capability-revoke",
        "task-authority-graph",
        .{},
        0,
    );
}

pub fn crashReportProvenance(
    task_id: u64,
    service_id: u64,
    tick: u64,
    crash_code: u32,
    redaction_policy_version: u16,
    reason_fingerprint: u64,
    redacted: bool,
) ProvenanceRecord {
    var detail_buffer: [MAX_DETAIL_BYTES]u8 = undefined;
    const detail = std.fmt.bufPrint(
        &detail_buffer,
        "code=0x{x} redaction_policy={d} redacted={s} reason_fingerprint=0x{x}",
        .{
            crash_code,
            redaction_policy_version,
            native_util.yesNo(redacted),
            reason_fingerprint,
        },
    ) catch "crash-report-redacted";
    return provenance(
        .crash_report,
        .allowed,
        tick,
        task_id,
        service_id,
        0,
        .service,
        service_id,
        "crash-report",
        detail,
        .{},
        0,
    );
}

pub fn syscallProvenance(
    decision: Decision,
    tick: u64,
    task_id: u64,
    operation: abi.NativeOperation,
    required_right: capability.CapabilityRight,
    reason: abi.DenialReason,
) ProvenanceRecord {
    const explanation = if (decision == .denied)
        explainDenied(reason, @tagName(operation), @tagName(required_right), task_id, 0, null, 0)
    else
        DenialExplanation{};
    return provenance(
        .syscall,
        decision,
        tick,
        task_id,
        0,
        0,
        null,
        0,
        @tagName(operation),
        @tagName(required_right),
        explanation,
        0,
    );
}

pub fn authorityGraphEdge(
    task_id: u64,
    owned: capability.Capability,
    now_ticks: u64,
) AuthorityGraphEdge {
    return .{
        .task_id = task_id,
        .capability_id = owned.id,
        .holder = owned.holder,
        .issuer = owned.issuer,
        .target_kind = owned.target.kind,
        .target_id = owned.target.id,
        .rights = owned.rights.toBits(),
        .scope_task_id = owned.scope.task_id orelse 0,
        .scope_workspace_id = owned.scope.workspace_id orelse 0,
        .policy_generation = owned.audit.policy_generation,
        .source_task_id = owned.audit.source_task_id,
        .broker_service_id = owned.audit.broker_service_id,
        .trace_id = owned.traceId(),
        .parent_trace_id = owned.audit.parent_trace_id,
        .expires_at_ticks = owned.lease.expires_at_ticks,
        .revocation_generation = owned.revocation_generation,
        .usable = owned.lease.isActive(now_ticks),
    };
}

pub fn denialFingerprint(explanation: DenialExplanation) u64 {
    var hash = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendU16LittleEndian(hash, @intFromEnum(explanation.reason));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, explanation.subject_task_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, explanation.capability_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, explanation.target_id);
    hash = native_util.fnv1a64AppendByte(hash, if (explanation.target_kind) |kind| @intFromEnum(kind) else 0xFF);
    hash = native_util.fnv1a64WithSeed(hash, explanation.operationSlice());
    hash = native_util.fnv1a64WithSeed(hash, explanation.requiredAuthoritySlice());
    hash = native_util.fnv1a64WithSeed(hash, explanation.blockingPolicySlice());
    return hash;
}

pub fn provenanceFingerprint(record: ProvenanceRecord) u64 {
    var hash = native_util.FNV1A_64_OFFSET_BASIS;
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(record.kind));
    hash = native_util.fnv1a64AppendByte(hash, @intFromEnum(record.decision));
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.parent_trace_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.task_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.artifact_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.service_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.capability_id);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.target_id);
    hash = native_util.fnv1a64AppendByte(hash, if (record.target_kind) |kind| @intFromEnum(kind) else 0xFF);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.tick);
    hash = native_util.fnv1a64WithSeed(hash, record.operationSlice());
    hash = native_util.fnv1a64WithSeed(hash, record.detailSlice());
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.denial.fingerprint);
    return hash;
}

fn policyLabel(reason: abi.DenialReason) []const u8 {
    return switch (reason) {
        .none => "none",
        .invalid_target => "target-routing-policy",
        .capability_missing => "capability-broker-policy",
        .capability_revoked => "capability-revocation-policy",
        .capability_expired => "capability-lease-policy",
        .scope_violation => "task-scope-policy",
        .policy_denied => "user-grant-policy",
        .budget_exhausted => "resource-budget-policy",
        .interface_not_found => "service-registry-policy",
        .unsupported_operation => "abi-surface-policy",
    };
}

fn userActionCanResolve(reason: abi.DenialReason) bool {
    return switch (reason) {
        .capability_missing,
        .capability_revoked,
        .capability_expired,
        .scope_violation,
        .policy_denied,
        => true,
        else => false,
    };
}

fn retrySafe(reason: abi.DenialReason) bool {
    return switch (reason) {
        .budget_exhausted, .interface_not_found => true,
        else => false,
    };
}

test "denial explanations render deterministic why-denied metadata" {
    const first = explainDenied(.scope_violation, "endpoint_send", "endpoint_send", 7, 11, .endpoint, 99);
    const second = explainDenied(.scope_violation, "endpoint_send", "endpoint_send", 7, 11, .endpoint, 99);
    try std.testing.expectEqual(first.fingerprint, second.fingerprint);
    try std.testing.expect(first.user_action_available);

    var buffer: [DENIAL_RENDER_TEST_BUFFER_BYTES]u8 = undefined;
    const text = first.render(&buffer);
    try std.testing.expect(std.mem.indexOf(u8, text, "reason=scope_violation") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "policy=task-scope-policy") != null);
}

test "provenance records have stable trace ids and graph edges expose capability origin" {
    const denial = explainDenied(.capability_missing, "service-call", "object_read", 3, 44, .service, 9);
    const first = provenance(.service_call, .denied, 10, 3, 9, 44, .service, 9, "object-open", "object_read", denial, 0);
    const second = provenance(.service_call, .denied, 10, 3, 9, 44, .service, 9, "object-open", "object_read", denial, 0);
    try std.testing.expectEqual(first.trace_id, second.trace_id);

    const cap = capability.Capability{
        .id = 44,
        .holder = .{ .kind = .app, .serial = 3 },
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = 9 },
        .rights = .{ .service = .{ .object_read = true } },
        .scope = .{ .task_id = 3 },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 20 },
        .revocation_generation = 1,
        .audit = .{ .policy_generation = 2, .source_task_id = 3, .broker_service_id = 9 },
    };
    const edge = authorityGraphEdge(3, cap, 10);
    try std.testing.expectEqual(@as(u64, 44), edge.capability_id);
    try std.testing.expect(edge.usable);
    try std.testing.expect(edge.trace_id != 0);
}

test "crash provenance carries deterministic redaction metadata without raw reason text" {
    const first = crashReportProvenance(5, 77, 10, 0xCA11, 1, 0x1234, true);
    const second = crashReportProvenance(5, 77, 10, 0xCA11, 1, 0x1234, true);
    try std.testing.expectEqual(first.trace_id, second.trace_id);
    try std.testing.expectEqual(ProvenanceKind.crash_report, first.kind);
    try std.testing.expectEqual(Decision.allowed, first.decision);
    try std.testing.expect(std.mem.indexOf(u8, first.detailSlice(), "redacted=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, first.detailSlice(), "reason_fingerprint=0x1234") != null);
}
