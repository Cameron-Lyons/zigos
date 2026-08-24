const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_DELEGATIONS: usize = 16;
pub const COMPACT_ACTIVE_DELEGATION_METADATA = true;
pub const BOUNDED_DELEGATION_SCAN = true;
pub const DIRECT_DELEGATION_LOOKUP = true;
pub const RECLAIMS_REVOKED_DELEGATIONS = true;
pub const ACTIVE_GENERATION_BUCKET_SIZE_CEILING_BYTES: usize = 8;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 2_616;
const NO_ACTIVE_GENERATION: u32 = std.math.maxInt(u32);

comptime {
    if (MAX_DELEGATIONS > std.math.maxInt(u8)) {
        @compileError("active delegation metadata no longer fits compact counters");
    }
}

pub const Error = event_ledger.Error || error{
    ActionBudgetExceeded,
    ContextBudgetExceeded,
    DelegationBindingMismatch,
    DelegationNotFound,
    DelegationRevoked,
    DelegationTableFull,
    KillSwitchGenerationStale,
    PolicyDenied,
    RemoteCallBudgetExceeded,
    SessionMismatch,
};

pub const DelegationId = indexed_arena.GenerationalHandle("AgentDelegation");

pub const AuthorizeRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    session_id: u64,
    autonomous_actions: u16,
    remote_calls: u16 = 0,
    user_confirmed: bool = false,
    audit_enabled: bool = false,
    local_context_only: bool = true,
    context_bytes: usize = 0,
    delegation_generation: u32 = 1,
    user_visible_plan: bool = false,
    now_tick: u64 = 0,
    detail: []const u8 = "",
};

pub const RecordActionRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    delegation_id: u64,
    session_id: u64,
    expected_generation: u32,
    action_count: u16 = 1,
    remote_call_count: u16 = 0,
    context_bytes: usize = 0,
    now_tick: u64 = 0,
    detail: []const u8 = "",
};

pub const Delegation = struct {
    id: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    task_id: u64 = 0,
    session_id: u64 = 0,
    authorized_actions: u16 = 0,
    used_actions: u16 = 0,
    authorized_remote_calls: u16 = 0,
    used_remote_calls: u16 = 0,
    max_context_bytes: usize = 0,
    used_context_bytes: usize = 0,
    delegation_generation: u32 = 0,
    local_context_only: bool = true,
    user_confirmed: bool = false,
    audit_enabled: bool = false,
    revoked: bool = false,

    pub fn remainingContextBytes(self: *const Delegation) usize {
        if (self.max_context_bytes == 0) return std.math.maxInt(usize);
        if (self.used_context_bytes >= self.max_context_bytes) return 0;
        return self.max_context_bytes - self.used_context_bytes;
    }
};

const Slot = struct {
    in_use: bool = false,
    delegation: Delegation = .{},
};

const DelegationArena = indexed_arena.GenerationalArena("AgentDelegation", Slot, MAX_DELEGATIONS);
const DelegationGenerationIndex = indexed_arena.MultimapIndex(MAX_DELEGATIONS, MAX_DELEGATIONS, MAX_DELEGATIONS * 2);

const ActiveGenerationBucket = struct {
    in_use: bool = false,
    generation: u32 = 0,
    active_count: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > ACTIVE_GENERATION_BUCKET_SIZE_CEILING_BYTES) {
            @compileError("active delegation generation bucket exceeds its compact size ceiling");
        }
    }
};

fn activeGenerationBucketKey(bucket: *const ActiveGenerationBucket) u64 {
    return generationKey(bucket.generation);
}

const ActiveGenerationBucketArena = indexed_arena.IndexedArenaWithKey(
    u64,
    ActiveGenerationBucket,
    MAX_DELEGATIONS,
    MAX_DELEGATIONS * 2,
    activeGenerationBucketKey,
);

pub const Service = struct {
    minimum_generation: u32 = 1,
    slots: DelegationArena = DelegationArena.init(),
    next_reusable_slot: u8 = 0,
    active_delegation_count: u8 = 0,
    lowest_active_generation: u32 = NO_ACTIVE_GENERATION,
    delegation_generation_index: DelegationGenerationIndex = DelegationGenerationIndex.init(),
    active_generation_buckets: ActiveGenerationBucketArena = ActiveGenerationBucketArena.init(),

    pub fn init() Service {
        return .{};
    }

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("agent delegation service exceeds its compact size ceiling");
        }
    }

    pub fn authorize(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: AuthorizeRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*Delegation {
        if (request.delegation_generation < self.minimum_generation) {
            try recordSessionBoundary(ledger, request, false, true);
            return error.KillSwitchGenerationStale;
        }

        const decision = policies.agentDelegationDecision(subjects, .{
            .enabled = true,
            .autonomous_actions = request.autonomous_actions,
            .remote_calls = request.remote_calls,
            .user_confirmed = request.user_confirmed,
            .audit_enabled = request.audit_enabled,
            .session_bound = request.session_id != 0,
            .local_context_only = request.local_context_only,
            .context_bytes = request.context_bytes,
            .delegation_generation = request.delegation_generation,
            .user_visible_plan = request.user_visible_plan,
        });
        if (!decision.allowed) {
            try recordSessionBoundary(ledger, request, false, decision.reason == .agent_kill_switch_denied);
            return error.PolicyDenied;
        }

        const slot_index = self.availableDelegationIndex() orelse return error.DelegationTableFull;
        try recordSessionBoundary(ledger, request, true, false);
        try recordAllowedDelegation(ledger, request);
        const delegation_id = self.claimDelegationId(slot_index).value;
        const delegation = Delegation{
            .id = delegation_id,
            .subject = request.subject,
            .task_id = request.task_id,
            .session_id = request.session_id,
            .authorized_actions = request.autonomous_actions,
            .authorized_remote_calls = request.remote_calls,
            .max_context_bytes = request.context_bytes,
            .delegation_generation = request.delegation_generation,
            .local_context_only = request.local_context_only,
            .user_confirmed = request.user_confirmed,
            .audit_enabled = request.audit_enabled,
        };
        const slot = &self.slots.slots[slot_index];
        slot.delegation = delegation;
        self.accountActiveDelegation(slot_index, &slot.delegation);
        self.next_reusable_slot = @intCast((slot_index + 1) % MAX_DELEGATIONS);
        return &slot.delegation;
    }

    pub fn recordAction(
        self: *Service,
        request: RecordActionRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*Delegation {
        const delegation = self.find(request.delegation_id) orelse return error.DelegationNotFound;
        if (!delegation.subject.eql(request.subject) or
            delegation.task_id != request.task_id or
            delegation.delegation_generation != request.expected_generation)
        {
            try recordDeniedActionBinding(ledger, request, delegation.local_context_only, delegation.delegation_generation);
            return error.DelegationBindingMismatch;
        }
        if (delegation.revoked) {
            try recordDeniedSessionAction(ledger, delegation, request, true);
            return error.DelegationRevoked;
        }
        if (delegation.session_id != request.session_id) {
            try recordDeniedSessionAction(ledger, delegation, request, false);
            return error.SessionMismatch;
        }
        if (delegation.delegation_generation < self.minimum_generation) {
            try recordDeniedSessionAction(ledger, delegation, request, true);
            return error.KillSwitchGenerationStale;
        }
        if (@as(u32, delegation.used_actions) + request.action_count > delegation.authorized_actions) {
            try recordDeniedAgentAction(ledger, delegation, request);
            return error.ActionBudgetExceeded;
        }
        if (@as(u32, delegation.used_remote_calls) + request.remote_call_count > delegation.authorized_remote_calls) {
            try recordDeniedAgentAction(ledger, delegation, request);
            return error.RemoteCallBudgetExceeded;
        }
        if (request.context_bytes > delegation.remainingContextBytes()) {
            try recordDeniedAgentAction(ledger, delegation, request);
            return error.ContextBudgetExceeded;
        }

        const used_actions = @as(u16, @intCast(@as(u32, delegation.used_actions) + request.action_count));
        const used_remote_calls = @as(u16, @intCast(@as(u32, delegation.used_remote_calls) + request.remote_call_count));
        const used_context_bytes = delegation.used_context_bytes + request.context_bytes;
        if (ledger) |active_ledger| {
            try active_ledger.recordAgentDelegation(
                delegation.subject,
                delegation.task_id,
                true,
                used_actions,
                used_remote_calls,
                delegation.user_confirmed,
                delegation.audit_enabled,
                request.now_tick,
                request.detail,
            );
        }
        delegation.used_actions = used_actions;
        delegation.used_remote_calls = used_remote_calls;
        delegation.used_context_bytes = used_context_bytes;
        return delegation;
    }

    pub fn killSwitch(
        self: *Service,
        minimum_generation: u32,
        ledger: ?*event_ledger.Ledger,
        subject: principal.PrincipalId,
        tick: u64,
        detail: []const u8,
    ) Error!usize {
        if (minimum_generation <= self.minimum_generation) return 0;
        self.minimum_generation = minimum_generation;
        if (self.active_delegation_count == 0 or self.lowest_active_generation >= self.minimum_generation) return 0;

        var revoked_count: usize = 0;
        for (&self.active_generation_buckets.slots) |*bucket| {
            if (!bucket.in_use) continue;
            if (bucket.generation >= self.minimum_generation) continue;
            const generation = bucket.generation;
            revoked_count += try self.revokeActiveGeneration(generation, ledger, subject, tick, detail);
        }
        return revoked_count;
    }

    pub fn find(self: *Service, delegation_id: u64) ?*Delegation {
        const slot = self.slots.getByHandle(.{ .value = delegation_id }) orelse return null;
        return &slot.delegation;
    }

    pub fn activeCount(self: *const Service) usize {
        return @intCast(self.active_delegation_count);
    }

    fn availableDelegationIndex(self: *const Service) ?usize {
        for (0..MAX_DELEGATIONS) |offset| {
            const slot_index = (@as(usize, self.next_reusable_slot) + offset) % MAX_DELEGATIONS;
            if (!self.slots.slots[slot_index].in_use) return slot_index;
        }
        for (0..MAX_DELEGATIONS) |offset| {
            const slot_index = (@as(usize, self.next_reusable_slot) + offset) % MAX_DELEGATIONS;
            if (self.slots.slots[slot_index].delegation.revoked) return slot_index;
        }
        return null;
    }

    fn claimDelegationId(self: *Service, slot_index: usize) DelegationId {
        if (self.slots.slots[slot_index].in_use) {
            return self.slots.replaceIndex(slot_index) orelse
                native_util.impossibleByInvariant("revoked delegation slot remains replaceable");
        }
        return self.slots.reserveHandleAt(slot_index) orelse
            native_util.impossibleByInvariant("available delegation slot remains reservable");
    }

    fn accountActiveDelegation(self: *Service, slot_index: usize, delegation: *const Delegation) void {
        if (delegation.revoked) return;
        if (!self.delegation_generation_index.append(generationKey(delegation.delegation_generation), slot_index)) {
            native_util.impossibleByInvariant("agent delegation generation index covers active delegations");
        }
        self.accountGeneration(delegation.delegation_generation);
        self.active_delegation_count += 1;
        self.lowest_active_generation = @min(self.lowest_active_generation, delegation.delegation_generation);
    }

    fn revokeActiveGeneration(
        self: *Service,
        delegation_generation: u32,
        ledger: ?*event_ledger.Ledger,
        subject: principal.PrincipalId,
        tick: u64,
        detail: []const u8,
    ) Error!usize {
        var revoked_count: usize = 0;
        var slot_index = self.delegation_generation_index.head(generationKey(delegation_generation));
        while (slot_index != indexed_arena.no_index) {
            const next_slot_index = self.delegation_generation_index.next(slot_index);
            if (slot_index >= MAX_DELEGATIONS) native_util.impossibleByInvariant("agent delegation generation index points outside slots");
            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use or slot.delegation.revoked) native_util.impossibleByInvariant("agent delegation generation index points at inactive delegation");
            if (slot.delegation.delegation_generation != delegation_generation) native_util.impossibleByInvariant("agent delegation generation index points at wrong generation");
            if (slot.delegation.delegation_generation >= self.minimum_generation) native_util.impossibleByInvariant("agent delegation stale-generation index selected current delegation");

            if (self.revokeDelegation(slot_index, &slot.delegation)) revoked_count += 1;
            if (ledger) |active_ledger| {
                try active_ledger.recordAgentSessionBoundary(
                    subject,
                    slot.delegation.task_id,
                    false,
                    true,
                    true,
                    true,
                    slot.delegation.delegation_generation,
                    tick,
                    detail,
                );
            }
            slot_index = next_slot_index;
        }
        return revoked_count;
    }

    fn revokeDelegation(self: *Service, slot_index: usize, delegation: *Delegation) bool {
        if (delegation.revoked) return false;
        delegation.revoked = true;
        self.unaccountActiveDelegation(slot_index, delegation);
        self.refreshLowestActiveGenerationFromBuckets();
        return true;
    }

    fn unaccountActiveDelegation(self: *Service, slot_index: usize, delegation: *const Delegation) void {
        if (!self.delegation_generation_index.remove(generationKey(delegation.delegation_generation), slot_index)) {
            native_util.impossibleByInvariant("agent delegation generation index missing active delegation");
        }
        self.unaccountGeneration(delegation.delegation_generation);
        if (self.active_delegation_count == 0) native_util.impossibleByInvariant("agent delegation active count underflow");
        self.active_delegation_count -= 1;
    }

    fn accountGeneration(self: *Service, generation: u32) void {
        const key = generationKey(generation);
        if (self.active_generation_buckets.get(key)) |bucket| {
            bucket.active_count += 1;
            return;
        }
        const bucket = self.active_generation_buckets.reserve(key) orelse
            native_util.impossibleByInvariant("agent delegation active generation buckets cover active delegations");
        bucket.generation = generation;
        bucket.active_count = 1;
    }

    fn unaccountGeneration(self: *Service, generation: u32) void {
        const key = generationKey(generation);
        const bucket = self.active_generation_buckets.get(key) orelse native_util.impossibleByInvariant("agent delegation active generation bucket missing");
        if (bucket.active_count == 0) native_util.impossibleByInvariant("agent delegation active generation bucket underflow");
        bucket.active_count -= 1;
        if (bucket.active_count == 0 and !self.active_generation_buckets.remove(key)) {
            native_util.impossibleByInvariant("agent delegation empty generation bucket remains indexed");
        }
    }

    fn refreshLowestActiveGenerationFromBuckets(self: *Service) void {
        var lowest = NO_ACTIVE_GENERATION;
        for (&self.active_generation_buckets.slots) |*bucket| {
            if (!bucket.in_use) continue;
            lowest = @min(lowest, bucket.generation);
        }
        self.lowest_active_generation = lowest;
    }
};

fn generationKey(generation: u32) u64 {
    return @as(u64, generation) + 1;
}

fn recordSessionBoundary(
    ledger: ?*event_ledger.Ledger,
    request: AuthorizeRequest,
    allowed: bool,
    generation_blocked: bool,
) event_ledger.Error!void {
    if (ledger) |active_ledger| {
        try active_ledger.recordAgentSessionBoundary(
            request.subject,
            request.task_id,
            allowed,
            request.session_id != 0,
            request.local_context_only,
            generation_blocked,
            request.delegation_generation,
            request.now_tick,
            request.detail,
        );
    }
}

fn recordAllowedDelegation(
    ledger: ?*event_ledger.Ledger,
    request: AuthorizeRequest,
) event_ledger.Error!void {
    if (ledger) |active_ledger| {
        try active_ledger.recordAgentDelegation(
            request.subject,
            request.task_id,
            true,
            request.autonomous_actions,
            request.remote_calls,
            request.user_confirmed,
            request.audit_enabled,
            request.now_tick,
            request.detail,
        );
    }
}

fn recordDeniedAgentAction(
    ledger: ?*event_ledger.Ledger,
    delegation: *const Delegation,
    request: RecordActionRequest,
) event_ledger.Error!void {
    if (ledger) |active_ledger| {
        try active_ledger.recordAgentDelegation(
            delegation.subject,
            delegation.task_id,
            false,
            request.action_count,
            request.remote_call_count,
            delegation.user_confirmed,
            delegation.audit_enabled,
            request.now_tick,
            request.detail,
        );
    }
}

fn recordDeniedSessionAction(
    ledger: ?*event_ledger.Ledger,
    delegation: *const Delegation,
    request: RecordActionRequest,
    generation_blocked: bool,
) event_ledger.Error!void {
    if (ledger) |active_ledger| {
        try active_ledger.recordAgentSessionBoundary(
            delegation.subject,
            delegation.task_id,
            false,
            request.session_id != 0,
            delegation.local_context_only,
            generation_blocked,
            delegation.delegation_generation,
            request.now_tick,
            request.detail,
        );
    }
}

fn recordDeniedActionBinding(
    ledger: ?*event_ledger.Ledger,
    request: RecordActionRequest,
    local_context_only: bool,
    delegation_generation: u32,
) event_ledger.Error!void {
    if (ledger) |active_ledger| {
        try active_ledger.recordAgentSessionBoundary(
            request.subject,
            request.task_id,
            false,
            request.session_id != 0,
            local_context_only,
            false,
            delegation_generation,
            request.now_tick,
            request.detail,
        );
    }
}

test "agent delegation service authorizes session-bound local agents and audits actions" {
    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 2030,
        .issuer = .{ .kind = .policy_authority, .serial = 2030 },
        .label = "agent-session-service",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 4,
        .max_agent_remote_calls_per_session = 1,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 4096,
        .min_agent_delegation_generation = 2,
        .require_agent_visible_plan = true,
    }, .{
        .label = "agent-service-policy-key",
        .seed = signing.seedFromByte(0xA0),
    });

    var service = Service.init();
    var ledger = event_ledger.Ledger.init();
    const subjects = policy_object.SubjectSet{ .organization_id = 2030 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 3030 };
    const delegation = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 3031,
        .session_id = 4040,
        .autonomous_actions = 3,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 2048,
        .delegation_generation = 2,
        .user_visible_plan = true,
        .now_tick = 12,
        .detail = "private agent plan",
    }, &ledger);

    try std.testing.expectEqual(@as(usize, 1), service.activeCount());
    try std.testing.expectEqual(@as(u16, 3), delegation.authorized_actions);
    try std.testing.expectError(error.DelegationBindingMismatch, service.recordAction(.{
        .subject = .{ .kind = .app, .serial = 3031 },
        .task_id = 3031,
        .delegation_id = delegation.id,
        .session_id = 4040,
        .expected_generation = 2,
        .action_count = 1,
        .now_tick = 13,
        .detail = "private wrong agent subject",
    }, &ledger));
    try std.testing.expectEqual(@as(u16, 0), delegation.used_actions);

    const after_action = try service.recordAction(.{
        .subject = subject,
        .task_id = 3031,
        .delegation_id = delegation.id,
        .session_id = 4040,
        .expected_generation = 2,
        .action_count = 2,
        .remote_call_count = 1,
        .context_bytes = 1024,
        .now_tick = 13,
        .detail = "private agent action",
    }, &ledger);
    try std.testing.expectEqual(@as(u16, 2), after_action.used_actions);
    try std.testing.expectEqual(@as(u16, 1), after_action.used_remote_calls);
    try std.testing.expectEqual(@as(usize, 1024), after_action.used_context_bytes);
    try std.testing.expectEqual(@as(usize, 1024), after_action.remainingContextBytes());
    try std.testing.expectError(error.ActionBudgetExceeded, service.recordAction(.{
        .subject = subject,
        .task_id = 3031,
        .delegation_id = delegation.id,
        .session_id = 4040,
        .expected_generation = 2,
        .action_count = 2,
    }, null));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.agent_session_events);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_delegation_events);
    try std.testing.expectEqual(@as(usize, 1), summary.agent_session_denials);
}

test "agent delegation service kill switch revokes stale generations and blocks reuse" {
    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 2031,
        .issuer = .{ .kind = .policy_authority, .serial = 2031 },
        .label = "agent-session-service-kill",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 4,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 4096,
        .min_agent_delegation_generation = 1,
        .require_agent_visible_plan = true,
    }, .{
        .label = "agent-service-policy-key",
        .seed = signing.seedFromByte(0xA1),
    });

    var service = Service.init();
    var ledger = event_ledger.Ledger.init();
    const subjects = policy_object.SubjectSet{ .organization_id = 2031 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 3032 };
    const delegation = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 3033,
        .session_id = 5050,
        .autonomous_actions = 2,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 1024,
        .delegation_generation = 1,
        .user_visible_plan = true,
        .now_tick = 20,
        .detail = "private stale delegation",
    }, &ledger);

    try std.testing.expectEqual(@as(usize, 1), try service.killSwitch(2, &ledger, subject, 21, "private kill switch"));
    try std.testing.expectEqual(@as(usize, 0), service.activeCount());
    try std.testing.expectEqual(NO_ACTIVE_GENERATION, service.lowest_active_generation);
    try std.testing.expectError(error.DelegationRevoked, service.recordAction(.{
        .subject = subject,
        .task_id = 3033,
        .delegation_id = delegation.id,
        .session_id = 5050,
        .expected_generation = 1,
    }, null));
    try std.testing.expectError(error.KillSwitchGenerationStale, service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 3034,
        .session_id = 5051,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 1,
        .user_visible_plan = true,
        .now_tick = 22,
        .detail = "private stale attempt",
    }, &ledger));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 3), summary.agent_session_events);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_session_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_kill_switch_denials);

    const current = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 3035,
        .session_id = 5052,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 3,
        .user_visible_plan = true,
        .now_tick = 23,
        .detail = "private current delegation",
    }, null);
    try std.testing.expectEqual(@as(usize, 1), service.activeCount());
    try std.testing.expectEqual(@as(u32, 3), service.lowest_active_generation);
    try std.testing.expectEqual(@as(usize, 0), try service.killSwitch(3, null, subject, 24, "private no-op kill switch"));
    try std.testing.expectEqual(@as(usize, 1), service.activeCount());
    try std.testing.expect(!current.revoked);
}

test "agent delegation service kill switch walks active generation index" {
    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 2034,
        .issuer = .{ .kind = .policy_authority, .serial = 2034 },
        .label = "agent-session-indexed-kill",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 4,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 4096,
        .min_agent_delegation_generation = 1,
        .require_agent_visible_plan = true,
    }, .{
        .label = "agent-service-index-key",
        .seed = signing.seedFromByte(0xA4),
    });

    var service = Service.init();
    var ledger = event_ledger.Ledger.init();
    const subjects = policy_object.SubjectSet{ .organization_id = 2034 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 3038 };

    const stale_one = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 6101,
        .session_id = 7101,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 1,
        .user_visible_plan = true,
    }, null);
    const stale_two_a = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 6102,
        .session_id = 7102,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 2,
        .user_visible_plan = true,
    }, null);
    const stale_two_b = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 6103,
        .session_id = 7103,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 2,
        .user_visible_plan = true,
    }, null);
    const current = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 6104,
        .session_id = 7104,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 5,
        .user_visible_plan = true,
    }, null);

    try std.testing.expectEqual(@as(usize, 4), service.activeCount());
    try std.testing.expectEqual(@as(u32, 1), service.lowest_active_generation);
    try std.testing.expectEqual(@as(usize, 1), service.delegation_generation_index.count(generationKey(1)));
    try std.testing.expectEqual(@as(usize, 2), service.delegation_generation_index.count(generationKey(2)));
    try std.testing.expectEqual(@as(usize, 1), service.delegation_generation_index.count(generationKey(5)));
    try std.testing.expectEqual(@as(usize, 3), service.active_generation_buckets.countInUse());
    try std.testing.expectEqual(@as(u8, 2), service.active_generation_buckets.get(generationKey(2)).?.active_count);
    const generation_one_bucket_slot = service.active_generation_buckets.slotIndexOf(generationKey(1)).?;
    const generation_two_bucket_slot = service.active_generation_buckets.slotIndexOf(generationKey(2)).?;

    try std.testing.expectEqual(@as(usize, 3), try service.killSwitch(3, &ledger, subject, 41, "private indexed kill switch"));
    try std.testing.expect(stale_one.revoked);
    try std.testing.expect(stale_two_a.revoked);
    try std.testing.expect(stale_two_b.revoked);
    try std.testing.expect(!current.revoked);
    try std.testing.expectEqual(@as(usize, 1), service.activeCount());
    try std.testing.expectEqual(@as(u32, 5), service.lowest_active_generation);
    try std.testing.expectEqual(@as(usize, 0), service.delegation_generation_index.count(generationKey(1)));
    try std.testing.expectEqual(@as(usize, 0), service.delegation_generation_index.count(generationKey(2)));
    try std.testing.expectEqual(@as(usize, 1), service.delegation_generation_index.count(generationKey(5)));
    try std.testing.expectEqual(@as(usize, 1), service.active_generation_buckets.countInUse());
    try std.testing.expect(service.active_generation_buckets.get(generationKey(1)) == null);
    try std.testing.expect(service.active_generation_buckets.get(generationKey(2)) == null);
    try std.testing.expectEqual(@as(u8, 1), service.active_generation_buckets.get(generationKey(5)).?.active_count);

    const reused_generation = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 6105,
        .session_id = 7105,
        .autonomous_actions = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 512,
        .delegation_generation = 7,
        .user_visible_plan = true,
    }, null);
    const generation_seven_bucket_slot = service.active_generation_buckets.slotIndexOf(generationKey(7)).?;
    try std.testing.expect(generation_seven_bucket_slot == generation_one_bucket_slot or generation_seven_bucket_slot == generation_two_bucket_slot);
    try std.testing.expect(!reused_generation.revoked);
    try std.testing.expectEqual(@as(usize, 2), service.active_generation_buckets.countInUse());
    try std.testing.expectEqual(@as(usize, 2), service.activeCount());
    try std.testing.expectEqual(@as(u32, 5), service.lowest_active_generation);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 3), summary.agent_session_events);
    try std.testing.expectEqual(@as(usize, 3), summary.agent_session_denials);
    try std.testing.expectEqual(@as(usize, 3), summary.agent_kill_switch_denials);
}

test "agent delegation service audits denied actions and enforces cumulative context budget" {
    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 2032,
        .issuer = .{ .kind = .policy_authority, .serial = 2032 },
        .label = "agent-session-denial-audit",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 5,
        .max_agent_remote_calls_per_session = 1,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 1536,
        .min_agent_delegation_generation = 1,
        .require_agent_visible_plan = true,
    }, .{
        .label = "agent-service-denial-key",
        .seed = signing.seedFromByte(0xA2),
    });

    var service = Service.init();
    var ledger = event_ledger.Ledger.init();
    const subjects = policy_object.SubjectSet{ .organization_id = 2032 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 3035 };
    const delegation = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 3036,
        .session_id = 6060,
        .autonomous_actions = 5,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 1536,
        .delegation_generation = 1,
        .user_visible_plan = true,
        .now_tick = 30,
        .detail = "private agent audit session",
    }, &ledger);

    _ = try service.recordAction(.{
        .subject = subject,
        .task_id = 3036,
        .delegation_id = delegation.id,
        .session_id = 6060,
        .expected_generation = 1,
        .action_count = 1,
        .context_bytes = 1024,
        .now_tick = 31,
        .detail = "private first context",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 512), delegation.remainingContextBytes());

    try std.testing.expectError(error.ContextBudgetExceeded, service.recordAction(.{
        .subject = subject,
        .task_id = 3036,
        .delegation_id = delegation.id,
        .session_id = 6060,
        .expected_generation = 1,
        .action_count = 1,
        .context_bytes = 600,
        .now_tick = 32,
        .detail = "private oversized cumulative context",
    }, &ledger));
    try std.testing.expectEqual(@as(usize, 1024), delegation.used_context_bytes);

    try std.testing.expectError(error.RemoteCallBudgetExceeded, service.recordAction(.{
        .subject = subject,
        .task_id = 3036,
        .delegation_id = delegation.id,
        .session_id = 6060,
        .expected_generation = 1,
        .action_count = 1,
        .remote_call_count = 2,
        .now_tick = 33,
        .detail = "private remote overrun",
    }, &ledger));
    try std.testing.expectError(error.SessionMismatch, service.recordAction(.{
        .subject = subject,
        .task_id = 3036,
        .delegation_id = delegation.id,
        .session_id = 6061,
        .expected_generation = 1,
        .action_count = 1,
        .now_tick = 34,
        .detail = "private wrong session",
    }, &ledger));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 4), summary.agent_delegation_events);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_delegation_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_remote_call_events);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_session_events);
    try std.testing.expectEqual(@as(usize, 1), summary.agent_session_denials);

    var export_buffer: [1024]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=agent_delegation") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "private oversized cumulative context") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "private wrong session") == null);
}

test "agent delegation service reclaims revoked generational slots" {
    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 2037,
        .issuer = .{ .kind = .policy_authority, .serial = 2037 },
        .label = "agent-session-id-wrap",
        .agent_delegation_allowed = true,
        .max_agent_actions_per_session = 2,
        .max_agent_remote_calls_per_session = 1,
        .require_agent_user_confirmation = true,
        .require_agent_audit = true,
        .require_agent_session_binding = true,
        .require_agent_local_context = true,
        .max_agent_context_bytes = 256,
        .min_agent_delegation_generation = 1,
        .require_agent_visible_plan = true,
    }, .{
        .label = "agent-service-id-wrap-key",
        .seed = signing.seedFromByte(0xA3),
    });

    const subjects = policy_object.SubjectSet{ .organization_id = 2037 };
    const subject = principal.PrincipalId{ .kind = .app, .serial = 3037 };
    var service = Service.init();

    var first_delegation_id: u64 = 0;
    for (0..MAX_DELEGATIONS) |index| {
        const delegation = try service.authorize(&policies, subjects, .{
            .subject = subject,
            .task_id = @intCast(7100 + index),
            .session_id = @intCast(8100 + index),
            .autonomous_actions = 1,
            .remote_calls = 1,
            .user_confirmed = true,
            .audit_enabled = true,
            .local_context_only = true,
            .context_bytes = 128,
            .delegation_generation = 1,
            .user_visible_plan = true,
            .now_tick = @intCast(50 + index),
            .detail = "private full table agent session",
        }, null);
        const delegation_id = DelegationId{ .value = delegation.id };
        try std.testing.expectEqual(index, delegation_id.slotIndex());
        try std.testing.expectEqual(@as(u32, 1), delegation_id.generation());
        if (index == 0) first_delegation_id = delegation.id;
    }
    try std.testing.expectEqual(MAX_DELEGATIONS, service.activeCount());
    try std.testing.expectEqual(
        @as(u8, MAX_DELEGATIONS),
        service.active_generation_buckets.get(generationKey(1)).?.active_count,
    );
    try std.testing.expect(service.find(0) == null);
    try std.testing.expect(service.find(DelegationId.fromParts(MAX_DELEGATIONS, 1).value) == null);
    try std.testing.expectError(error.DelegationTableFull, service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 7200,
        .session_id = 8200,
        .autonomous_actions = 1,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 128,
        .delegation_generation = 1,
        .user_visible_plan = true,
        .now_tick = 70,
        .detail = "private rejected full table agent session",
    }, null));

    try std.testing.expectEqual(MAX_DELEGATIONS, try service.killSwitch(2, null, subject, 71, "private full table kill switch"));
    try std.testing.expectEqual(@as(usize, 0), service.activeCount());
    try std.testing.expectError(error.DelegationRevoked, service.recordAction(.{
        .subject = subject,
        .task_id = 7100,
        .delegation_id = first_delegation_id,
        .session_id = 8100,
        .expected_generation = 1,
    }, null));

    const replacement = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 7201,
        .session_id = 8201,
        .autonomous_actions = 1,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 128,
        .delegation_generation = 2,
        .user_visible_plan = true,
        .now_tick = 72,
        .detail = "private replacement agent session",
    }, null);
    try std.testing.expectEqual(@as(usize, 0), (DelegationId{ .value = replacement.id }).slotIndex());
    try std.testing.expectEqual(@as(u32, 2), (DelegationId{ .value = replacement.id }).generation());
    try std.testing.expect(service.find(first_delegation_id) == null);
    try std.testing.expectError(error.DelegationNotFound, service.recordAction(.{
        .subject = subject,
        .task_id = 7100,
        .delegation_id = first_delegation_id,
        .session_id = 8100,
        .expected_generation = 1,
    }, null));
    try std.testing.expectEqual(MAX_DELEGATIONS, service.slots.countInUse());
    try std.testing.expectEqual(@as(usize, 1), service.activeCount());

    try std.testing.expectEqual(@as(usize, 1), try service.killSwitch(3, null, subject, 73, "private replacement kill switch"));
    const wrapped_from = DelegationId.fromParts(0, std.math.maxInt(u32)).value;
    service.slots.slot_generations[0] = std.math.maxInt(u32);
    service.slots.slots[0].delegation.id = wrapped_from;
    service.next_reusable_slot = 0;
    try std.testing.expect(service.find(wrapped_from) != null);

    const wrapped = try service.authorize(&policies, subjects, .{
        .subject = subject,
        .task_id = 7202,
        .session_id = 8202,
        .autonomous_actions = 1,
        .remote_calls = 1,
        .user_confirmed = true,
        .audit_enabled = true,
        .local_context_only = true,
        .context_bytes = 128,
        .delegation_generation = 3,
        .user_visible_plan = true,
        .now_tick = 74,
        .detail = "private wrapped agent session",
    }, null);
    try std.testing.expectEqual(@as(usize, 0), (DelegationId{ .value = wrapped.id }).slotIndex());
    try std.testing.expectEqual(@as(u32, 1), (DelegationId{ .value = wrapped.id }).generation());
    try std.testing.expect(service.find(wrapped_from) == null);
}
