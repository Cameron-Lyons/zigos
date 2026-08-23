const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const denial_explanation = @import("../policy/denial_explanation.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_DETAIL_BYTES: usize = 96;
pub const COMPACT_DEBUG_TEXT_METADATA = true;
pub const DENIAL_EXPLANATION_SIZE_CEILING_BYTES: usize = 240;
pub const PROVENANCE_RECORD_SIZE_CEILING_BYTES: usize = 504;
const DENIAL_RENDER_TEST_BUFFER_BYTES: usize = 256;

comptime {
    if (MAX_LABEL_BYTES > std.math.maxInt(u8) or MAX_DETAIL_BYTES > std.math.maxInt(u8)) {
        @compileError("debug contract text metadata exceeds u8 capacity");
    }
}

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
    operation_len: u8 = 0,
    operation: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    required_authority_len: u8 = 0,
    required_authority: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    blocking_policy_len: u8 = 0,
    blocking_policy: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    user_action_available: bool = false,
    retry_safe: bool = false,
    fingerprint: u64 = 0,

    pub fn operationSlice(self: *const DenialExplanation) []const u8 {
        return self.operation[0..@as(usize, self.operation_len)];
    }

    pub fn requiredAuthoritySlice(self: *const DenialExplanation) []const u8 {
        return self.required_authority[0..@as(usize, self.required_authority_len)];
    }

    pub fn blockingPolicySlice(self: *const DenialExplanation) []const u8 {
        return self.blocking_policy[0..@as(usize, self.blocking_policy_len)];
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
    operation_len: u8 = 0,
    operation: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    detail_len: u8 = 0,
    detail: [MAX_DETAIL_BYTES]u8 = [_]u8{0} ** MAX_DETAIL_BYTES,
    source_identity_fingerprint: u64 = 0,
    release_transparency_sequence: u64 = 0,
    release_transparency_root_fingerprint: u64 = 0,
    release_transparency_log_head_fingerprint: u64 = 0,
    denial: DenialExplanation = .{},

    pub fn operationSlice(self: *const ProvenanceRecord) []const u8 {
        return self.operation[0..@as(usize, self.operation_len)];
    }

    pub fn detailSlice(self: *const ProvenanceRecord) []const u8 {
        return self.detail[0..@as(usize, self.detail_len)];
    }

    pub fn hasReleaseTransparency(self: *const ProvenanceRecord) bool {
        return self.release_transparency_sequence != 0 and
            self.release_transparency_root_fingerprint != 0 and
            self.release_transparency_log_head_fingerprint != 0;
    }

    pub fn render(self: *const ProvenanceRecord, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(
            buffer,
            "trace=0x{x} parent=0x{x} tick={d} kind={s} decision={s} task={d} artifact={d} service={d} capability={d} target={s}:{d} operation={s} detail={s} source_fingerprint=0x{x} seq={d} reason={s}",
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
                self.source_identity_fingerprint,
                self.release_transparency_sequence,
                @tagName(self.denial.reason),
            },
        ) catch "";
    }
};

comptime {
    if (@sizeOf(DenialExplanation) > DENIAL_EXPLANATION_SIZE_CEILING_BYTES or
        @sizeOf(ProvenanceRecord) > PROVENANCE_RECORD_SIZE_CEILING_BYTES)
    {
        @compileError("debug contract records exceed compact layout ceilings");
    }
}

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
    delegation_depth: u8 = 0,
    max_delegation_depth: u8 = 0,
    expires_at_ticks: u64 = 0,
    revocation_generation: u32 = 0,
    usable: bool = false,

    pub fn render(self: *const AuthorityGraphEdge, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(
            buffer,
            "task={d} capability={d} holder={s}:{d} issuer={s}:{d} target={s}:{d} rights=0x{x} scope_task={d} scope_workspace={d} policy_generation={d} source_task={d} broker_service={d} trace=0x{x} parent=0x{x} delegation_depth={d}/{d} expires={d} generation={d} usable={s}",
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
                self.delegation_depth,
                self.max_delegation_depth,
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
        .user_action_available = denial_explanation.approvalCanResolve(reason),
        .retry_safe = denial_explanation.retrySafe(reason),
    };
    explanation.operation_len = @intCast(native_util.copyTextWithReserve(&explanation.operation, operation, 1));
    explanation.required_authority_len = @intCast(native_util.copyTextWithReserve(&explanation.required_authority, required_authority, 1));
    explanation.blocking_policy_len = @intCast(native_util.copyTextWithReserve(&explanation.blocking_policy, denial_explanation.policyLabel(reason), 1));
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
    record.operation_len = @intCast(native_util.copyTextWithReserve(&record.operation, operation, 1));
    record.detail_len = @intCast(native_util.copyTextWithReserve(&record.detail, detail, 1));
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
    source_identity: []const u8,
    transparency_sequence: u64,
    transparency_root: crypto_hash.Digest,
    transparency_log_head: crypto_hash.Digest,
) ProvenanceRecord {
    var detail_buffer: [MAX_DETAIL_BYTES]u8 = undefined;
    const fallback_detail = if (bundle_id.len != 0) bundle_id else if (signed) "signed-launch" else "direct-launch";
    const detail = if (source_identity.len != 0 or transparency_sequence != 0)
        std.fmt.bufPrint(
            &detail_buffer,
            "bundle={s} source={s} seq={d}",
            .{ if (bundle_id.len != 0) bundle_id else "unknown", source_identity, transparency_sequence },
        ) catch fallback_detail
    else
        fallback_detail;
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
        detail,
        .{},
        0,
    );
    record.source_identity_fingerprint = if (source_identity.len == 0) 0 else native_util.fnv1a64(source_identity);
    record.release_transparency_sequence = transparency_sequence;
    record.release_transparency_root_fingerprint = digestFingerprint(transparency_root);
    record.release_transparency_log_head_fingerprint = digestFingerprint(transparency_log_head);
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
    usable: bool,
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
        .delegation_depth = owned.audit.delegation_depth,
        .max_delegation_depth = owned.audit.max_delegation_depth,
        .expires_at_ticks = owned.lease.expires_at_ticks,
        .revocation_generation = owned.revocation_generation,
        .usable = usable,
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
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.source_identity_fingerprint);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.release_transparency_sequence);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.release_transparency_root_fingerprint);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.release_transparency_log_head_fingerprint);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, record.denial.fingerprint);
    return hash;
}

fn digestFingerprint(digest: crypto_hash.Digest) u64 {
    if (std.mem.eql(u8, &digest, &crypto_hash.zero_digest)) return 0;
    return native_util.fnv1a64(&digest);
}

test "debug contract keeps bounded text metadata compact" {
    try std.testing.expectEqual(u8, @FieldType(DenialExplanation, "operation_len"));
    try std.testing.expectEqual(u8, @FieldType(DenialExplanation, "required_authority_len"));
    try std.testing.expectEqual(u8, @FieldType(DenialExplanation, "blocking_policy_len"));
    try std.testing.expectEqual(u8, @FieldType(ProvenanceRecord, "operation_len"));
    try std.testing.expectEqual(u8, @FieldType(ProvenanceRecord, "detail_len"));
    try std.testing.expectEqual(@as(usize, 240), @sizeOf(DenialExplanation));
    try std.testing.expectEqual(@as(usize, 504), @sizeOf(ProvenanceRecord));
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
    const edge = authorityGraphEdge(3, cap, cap.lease.isActive(10));
    try std.testing.expectEqual(@as(u64, 44), edge.capability_id);
    try std.testing.expect(edge.usable);
    try std.testing.expect(edge.trace_id != 0);
    try std.testing.expectEqual(@as(u8, capability.DEFAULT_MAX_DELEGATION_DEPTH), edge.max_delegation_depth);
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
