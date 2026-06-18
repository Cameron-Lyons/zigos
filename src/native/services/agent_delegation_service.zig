const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_DELEGATIONS: usize = 16;

pub const Error = event_ledger.Error || error{
    ActionBudgetExceeded,
    ContextBudgetExceeded,
    DelegationNotFound,
    DelegationRevoked,
    DelegationTableFull,
    KillSwitchGenerationStale,
    PolicyDenied,
    RemoteCallBudgetExceeded,
    SessionMismatch,
};

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
    delegation_id: u64,
    session_id: u64,
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

pub const Service = struct {
    next_delegation_id: u64 = 1,
    minimum_generation: u32 = 1,
    slots: [MAX_DELEGATIONS]Slot = [_]Slot{Slot{}} ** MAX_DELEGATIONS,

    pub fn init() Service {
        return .{};
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

        const slot = self.firstFreeSlot() orelse return error.DelegationTableFull;
        slot.in_use = true;
        slot.delegation = .{
            .id = self.next_delegation_id,
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
        self.next_delegation_id += 1;
        try recordSessionBoundary(ledger, request, true, false);
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
        return &slot.delegation;
    }

    pub fn recordAction(
        self: *Service,
        request: RecordActionRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*Delegation {
        const delegation = self.find(request.delegation_id) orelse return error.DelegationNotFound;
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

        delegation.used_actions += request.action_count;
        delegation.used_remote_calls += request.remote_call_count;
        delegation.used_context_bytes += request.context_bytes;
        if (ledger) |active_ledger| {
            try active_ledger.recordAgentDelegation(
                delegation.subject,
                delegation.task_id,
                true,
                delegation.used_actions,
                delegation.used_remote_calls,
                delegation.user_confirmed,
                delegation.audit_enabled,
                request.now_tick,
                request.detail,
            );
        }
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
        var revoked_count: usize = 0;
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.delegation.revoked) continue;
            if (slot.delegation.delegation_generation >= self.minimum_generation) continue;
            slot.delegation.revoked = true;
            revoked_count += 1;
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
        }
        return revoked_count;
    }

    pub fn find(self: *Service, delegation_id: u64) ?*Delegation {
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.delegation.id == delegation_id) return &slot.delegation;
        }
        return null;
    }

    pub fn activeCount(self: *const Service) usize {
        var count: usize = 0;
        for (self.slots) |slot| {
            if (slot.in_use and !slot.delegation.revoked) count += 1;
        }
        return count;
    }

    fn firstFreeSlot(self: *Service) ?*Slot {
        for (&self.slots) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }
};

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
    const after_action = try service.recordAction(.{
        .delegation_id = delegation.id,
        .session_id = 4040,
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
        .delegation_id = delegation.id,
        .session_id = 4040,
        .action_count = 2,
    }, null));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 1), summary.agent_session_events);
    try std.testing.expectEqual(@as(usize, 2), summary.agent_delegation_events);
    try std.testing.expectEqual(@as(usize, 0), summary.agent_session_denials);
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
    try std.testing.expectError(error.DelegationRevoked, service.recordAction(.{
        .delegation_id = delegation.id,
        .session_id = 5050,
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
        .delegation_id = delegation.id,
        .session_id = 6060,
        .action_count = 1,
        .context_bytes = 1024,
        .now_tick = 31,
        .detail = "private first context",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 512), delegation.remainingContextBytes());

    try std.testing.expectError(error.ContextBudgetExceeded, service.recordAction(.{
        .delegation_id = delegation.id,
        .session_id = 6060,
        .action_count = 1,
        .context_bytes = 600,
        .now_tick = 32,
        .detail = "private oversized cumulative context",
    }, &ledger));
    try std.testing.expectEqual(@as(usize, 1024), delegation.used_context_bytes);

    try std.testing.expectError(error.RemoteCallBudgetExceeded, service.recordAction(.{
        .delegation_id = delegation.id,
        .session_id = 6060,
        .action_count = 1,
        .remote_call_count = 2,
        .now_tick = 33,
        .detail = "private remote overrun",
    }, &ledger));
    try std.testing.expectError(error.SessionMismatch, service.recordAction(.{
        .delegation_id = delegation.id,
        .session_id = 6061,
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
