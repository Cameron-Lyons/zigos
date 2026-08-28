const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const denial_explanation = @import("denial_explanation.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const humane_permissions = @import("humane_permissions.zig");
const manifest = @import("manifest.zig");
const manifest_fixtures = @import("manifest_fixtures.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const task_runtime = @import("../task/task_runtime.zig");
const units = @import("../core/units.zig");

pub const MAX_PERMISSION_DECISIONS: usize = 16;
pub const COMPACT_ACTIVATION_SUMMARY_METADATA = true;
pub const GRANT_RECEIPT_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const REVOCATION_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const AUTHORIZATION_TASK_INDEX_LOOKUPS: u8 = 1;
pub const MANIFEST_PERMISSION_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const ZERO_CAPABILITY_ID_IS_NONE = capability.ZERO_CAPABILITY_ID_RESERVED;
pub const PERMISSION_DECISION_SIZE_CEILING_BYTES: usize = 48;
pub const ACTIVATION_SUMMARY_SIZE_CEILING_BYTES: usize = 776;
const PERMISSION_RECEIPT_BUFFER_BYTES: usize = 512;
const REVOCATION_RECEIPT_BUFFER_BYTES: usize = 240;

comptime {
    if (MAX_PERMISSION_DECISIONS > std.math.maxInt(u8)) {
        @compileError("permission decisions exceed compact activation summary capacity");
    }
}

pub const ServiceTargets = struct {
    network_service_id: u64,
    compositor_service_id: u64,
    policy_service_id: u64,
    service_registry_id: u64,
};

pub const UserGrant = struct {
    kind: manifest.PermissionKind,
    resource: []const u8 = "",
    allow: bool = true,
    local_only: bool = false,
    expires_at_ticks: ?u64 = null,
};

pub const PermissionDecision = struct {
    kind: manifest.PermissionKind,
    allowed: bool,
    reason: abi.DenialReason = .none,
    capability_id: u64 = 0,
    local_only: bool = false,
    expires_at_ticks: u64 = 0,
    explanation: denial_explanation.Explanation = denial_explanation.none(),

    pub fn capabilityId(self: *const PermissionDecision) ?u64 {
        return if (self.capability_id == 0) null else self.capability_id;
    }
};

comptime {
    if (@sizeOf(PermissionDecision) > PERMISSION_DECISION_SIZE_CEILING_BYTES) {
        @compileError("permission decision exceeds its compact size ceiling");
    }
}

pub const GrantPlan = capability.GrantPlan;

pub const Decision = struct {
    request: manifest.PermissionRequest,
    task_id: u64,
    owner: principal.PrincipalId,
    allowed: bool,
    reason: abi.DenialReason = .none,
    grant: ?UserGrant = null,
    local_only: bool = false,
    lease_end: u64 = 0,
};

pub const ActivationSummary = struct {
    granted_count: u8 = 0,
    denied_count: u8 = 0,
    required_denials: u8 = 0,
    decision_count: u8 = 0,
    decisions: [MAX_PERMISSION_DECISIONS]PermissionDecision = [_]PermissionDecision{emptyDecision()} ** MAX_PERMISSION_DECISIONS,

    pub fn addDecision(self: *ActivationSummary, decision: PermissionDecision, required: bool) void {
        if (self.decision_count < self.decisions.len) {
            self.decisions[self.decision_count] = decision;
            self.decision_count += 1;
        }

        if (decision.allowed) {
            self.granted_count += 1;
        } else {
            self.denied_count += 1;
            if (required) self.required_denials += 1;
        }
    }

    pub fn decisionForKind(self: *const ActivationSummary, kind: manifest.PermissionKind) ?PermissionDecision {
        var index: usize = 0;
        while (index < self.decision_count) : (index += 1) {
            if (self.decisions[index].kind == kind) return self.decisions[index];
        }
        return null;
    }
};

comptime {
    if (@sizeOf(ActivationSummary) > ACTIVATION_SUMMARY_SIZE_CEILING_BYTES) {
        @compileError("policy activation summary exceeds its compact size ceiling");
    }
}

pub const Error = task_runtime.Error || capability.Error || manifest.ValidationError || event_ledger.Error;

pub const PolicyMediator = struct {
    policy_authority: principal.PrincipalId,
    capability_table: *capability.CapabilityTable,
    runtime: *task_runtime.Runtime,
    service_targets: ServiceTargets,
    policy_generation: u32 = 1,
    ledger: ?*event_ledger.Ledger = null,

    pub fn init(
        policy_authority: principal.PrincipalId,
        capability_table: *capability.CapabilityTable,
        runtime: *task_runtime.Runtime,
        service_targets: ServiceTargets,
    ) PolicyMediator {
        return .{
            .policy_authority = policy_authority,
            .capability_table = capability_table,
            .runtime = runtime,
            .service_targets = service_targets,
        };
    }

    pub fn attachLedger(self: *PolicyMediator, ledger: *event_ledger.Ledger) void {
        self.ledger = ledger;
    }

    pub fn authorizeRequest(
        self: *PolicyMediator,
        task_id: u64,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) Error!PermissionDecision {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        return self.authorizeTask(task, request, grants, now_ticks);
    }

    fn authorizeTask(
        self: *PolicyMediator,
        task: *task_runtime.TaskRecord,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) Error!PermissionDecision {
        const decision = self.evaluateTask(task, request, grants, now_ticks);
        if (!decision.allowed) {
            return self.commitDeniedDecisionForTask(task, decision, now_ticks);
        }

        const grant_plan = try self.grantPlanForTask(
            task,
            decision.request,
            decision.grant.?,
            decision.lease_end,
            now_ticks,
        );
        var minted_buffer: [capability.MAX_GRANT_PLAN_ENTRIES]capability.Capability = undefined;
        return self.commitGrantPlanForTask(task, decision, &grant_plan, &minted_buffer, now_ticks);
    }

    fn evaluateTask(
        self: *const PolicyMediator,
        task: *const task_runtime.TaskRecord,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) Decision {
        const matched_grant = self.matchGrant(request, grants, now_ticks) orelse {
            return self.denialDecision(task, request, .policy_denied);
        };
        if (!matched_grant.allow) {
            return self.denialDecision(task, request, .policy_denied);
        }
        if (matched_grant.expires_at_ticks) |expiry| {
            if (now_ticks > expiry) {
                return self.denialDecision(task, request, .capability_expired);
            }
        }
        if (request.local_only and !matched_grant.local_only) {
            return self.denialDecision(task, request, .scope_violation);
        }
        if (request.kind == .background_execution and !task.background_allowed) {
            return self.denialDecision(task, request, .budget_exhausted);
        }

        const lease_end = self.resolveLeaseEnd(request, matched_grant, now_ticks);
        if (lease_end < now_ticks) {
            return self.denialDecision(task, request, .capability_expired);
        }
        if (finiteLeaseRequired(request.kind) and lease_end == std.math.maxInt(u64)) {
            return self.denialDecision(task, request, .policy_denied);
        }

        const granted_local_only = request.local_only or matched_grant.local_only;
        return .{
            .request = request,
            .task_id = task.id,
            .owner = task.owner,
            .allowed = true,
            .grant = matched_grant,
            .local_only = granted_local_only,
            .lease_end = lease_end,
        };
    }

    fn commitGrantPlanForTask(
        self: *PolicyMediator,
        task: *task_runtime.TaskRecord,
        decision: Decision,
        grant_plan: *const GrantPlan,
        minted_buffer: []capability.Capability,
        now_ticks: u64,
    ) Error!PermissionDecision {
        const minted = try self.applyGrantPlanTransactional(task, grant_plan, minted_buffer);
        const capability_id = minted[0].id;
        task.appendAudit(.{
            .kind = .policy_allowed,
            .capability_id = capability_id,
            .detail = @intFromEnum(decision.request.kind),
            .tick = now_ticks,
        });
        try self.recordDecision(decision.owner, decision.task_id, decision.request, true, .none, now_ticks);
        if (self.ledger) |ledger| {
            var receipt_buffer: [PERMISSION_RECEIPT_BUFFER_BYTES]u8 = undefined;
            const grant_receipt = humane_permissions.renderPermissionReceiptToBuffer(&receipt_buffer, .{
                .task_id = decision.task_id,
                .bundle_id = task.launchBundleIdSlice(),
                .display_name = taskDisplayName(task),
                .capability_id = capability_id,
                .request = decision.request,
                .local_only = decision.local_only,
                .expires_at_ticks = if (decision.lease_end == std.math.maxInt(u64)) null else decision.lease_end,
                .why = "matching user grant authorized by policy",
            }, now_ticks) catch decision.request.resource;
            try ledger.recordCapabilityGrant(
                decision.owner,
                decision.task_id,
                capability_id,
                decision.request.kind,
                now_ticks,
                grant_receipt,
            );
        }

        return .{
            .kind = decision.request.kind,
            .allowed = true,
            .capability_id = capability_id,
            .local_only = decision.local_only,
            .expires_at_ticks = decision.lease_end,
            .explanation = denial_explanation.none(),
        };
    }

    pub fn commitDeniedRequestForTask(
        self: *PolicyMediator,
        task: *task_runtime.TaskRecord,
        request: manifest.PermissionRequest,
        reason: abi.DenialReason,
        now_ticks: u64,
    ) Error!PermissionDecision {
        return self.commitDeniedDecisionForTask(task, .{
            .request = request,
            .task_id = task.id,
            .owner = task.owner,
            .allowed = false,
            .reason = reason,
        }, now_ticks);
    }

    fn commitDeniedDecisionForTask(
        self: *PolicyMediator,
        task: *task_runtime.TaskRecord,
        decision: Decision,
        now_ticks: u64,
    ) Error!PermissionDecision {
        task.appendAudit(.{
            .kind = .policy_denied,
            .detail = @intFromEnum(decision.reason),
            .tick = now_ticks,
        });
        try self.recordDecision(decision.owner, decision.task_id, decision.request, false, decision.reason, now_ticks);

        return .{
            .kind = decision.request.kind,
            .allowed = false,
            .reason = decision.reason,
            .explanation = denial_explanation.forPermissionDecision(decision.request.kind, decision.reason),
        };
    }

    pub fn revokeGrantedCapability(
        self: *PolicyMediator,
        task_id: u64,
        capability_id: u64,
        permission_kind: ?manifest.PermissionKind,
        now_ticks: u64,
        detail: []const u8,
    ) Error!bool {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const detached = task_runtime.revokeCapabilityFromTask(task, capability_id);
        if (!detached) return false;
        try self.capability_table.revokeGrant(capability_id);
        task.appendAudit(.{
            .kind = .capability_revoked,
            .capability_id = capability_id,
            .tick = now_ticks,
        });
        if (self.ledger) |ledger| {
            try ledger.recordCapabilityRevocation(
                task.owner,
                task_id,
                capability_id,
                permission_kind,
                now_ticks,
                detail,
            );
        }
        return true;
    }

    fn grantPlanForTask(
        self: *const PolicyMediator,
        task: *const task_runtime.TaskRecord,
        request: manifest.PermissionRequest,
        grant: UserGrant,
        lease_end: u64,
        now_ticks: u64,
    ) Error!GrantPlan {
        const granted_local_only = request.local_only or grant.local_only;
        const target = self.resolveTarget(request);
        var plan = GrantPlan{};
        try plan.addMint(task.id, .{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = target,
            .rights = request.rights.retarget(target.kind),
            .scope = .{
                .task_id = task.id,
                .local_only = granted_local_only,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = lease_end,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = self.policy_generation,
                .source_task_id = task.id,
                .broker_service_id = self.service_targets.policy_service_id,
                .max_delegation_depth = maxDelegationDepthForRequest(request),
            },
        });
        return plan;
    }

    fn applyGrantPlanTransactional(
        self: *PolicyMediator,
        task: *task_runtime.TaskRecord,
        plan: *const GrantPlan,
        output: []capability.Capability,
    ) Error![]capability.Capability {
        const minted = try self.capability_table.applyGrantPlan(plan, output);
        var attached_count: usize = 0;
        errdefer {
            var revoke_index: usize = 0;
            while (revoke_index < attached_count) : (revoke_index += 1) {
                const entry = plan.entries[revoke_index];
                if (entry.task_id != 0) {
                    if (!task_runtime.revokeCapabilityFromTask(task, minted[revoke_index].id)) {
                        native_util.impossibleByInvariant("rollback revokes capabilities attached earlier in this grant transaction");
                    }
                }
            }
            self.capability_table.rollbackGrant(minted);
        }

        for (plan.slice(), minted) |entry, granted_capability| {
            if (entry.task_id != 0) {
                try task_runtime.grantCapabilityToTask(task, granted_capability.id);
            }
            attached_count += 1;
        }
        return minted;
    }

    pub fn applyManifest(
        self: *PolicyMediator,
        task_id: u64,
        bundle: manifest.BundleManifest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) Error!ActivationSummary {
        try manifest.validate(bundle);
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        var summary = ActivationSummary{};

        for (bundle.requested_permissions) |request| {
            const decision = try self.authorizeTask(task, request, grants, now_ticks);
            summary.addDecision(decision, request.required);
        }

        if (summary.required_denials != 0) {
            try self.rollbackActivationGrants(task.id, &summary, now_ticks);
        }
        task.state = if (summary.required_denials == 0) .active else .suspended;
        return summary;
    }

    fn matchGrant(
        self: *const PolicyMediator,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) ?UserGrant {
        _ = self;
        var expired_allow: ?UserGrant = null;
        for (grants) |grant| {
            if (grant.kind != request.kind) continue;
            if (grant.resource.len != 0 and !std.mem.eql(u8, grant.resource, request.resource)) continue;
            if (!grant.allow) return grant;
            if (grant.expires_at_ticks) |expiry| {
                if (now_ticks > expiry) {
                    if (expired_allow == null) expired_allow = grant;
                    continue;
                }
            }
            return grant;
        }
        return expired_allow;
    }

    fn resolveLeaseEnd(
        self: *const PolicyMediator,
        request: manifest.PermissionRequest,
        grant: UserGrant,
        now_ticks: u64,
    ) u64 {
        _ = self;

        var lease_end: u64 = std.math.maxInt(u64);
        if (request.max_lease_ticks != 0) {
            lease_end = std.math.add(u64, now_ticks, request.max_lease_ticks) catch std.math.maxInt(u64);
        }
        if (grant.expires_at_ticks) |expiry| {
            lease_end = @min(lease_end, expiry);
        }
        return lease_end;
    }

    fn rollbackActivationGrants(
        self: *PolicyMediator,
        task_id: u64,
        summary: *const ActivationSummary,
        now_ticks: u64,
    ) Error!void {
        var index: usize = 0;
        while (index < summary.decision_count) : (index += 1) {
            const decision = summary.decisions[index];
            if (!decision.allowed) continue;
            const capability_id = decision.capabilityId() orelse continue;
            _ = try self.revokeGrantedCapability(
                task_id,
                capability_id,
                decision.kind,
                now_ticks,
                "activation rolled back after required permission denial",
            );
        }
    }

    fn resolveTarget(self: *const PolicyMediator, request: manifest.PermissionRequest) capability.CapabilityTarget {
        return switch (request.kind) {
            .object_access => .{
                .kind = .object,
                .id = if (request.target_id != 0) request.target_id else resourceId(request.resource),
            },
            .contacts => .{
                .kind = .object,
                .id = if (request.target_id != 0) request.target_id else resourceId(request.resource),
            },
            .network_egress => .{
                .kind = .network_policy,
                .id = if (request.target_id != 0) request.target_id else resourceId(request.resource),
            },
            .clipboard, .screen_capture, .notification_post => .{
                .kind = .service,
                .id = self.service_targets.compositor_service_id,
            },
            .device_access, .camera, .mic, .sensor, .location => .{
                .kind = .device,
                .id = if (request.target_id != 0) request.target_id else resourceId(request.resource),
            },
            .background_execution => .{
                .kind = .policy,
                .id = self.service_targets.policy_service_id,
            },
            .peer_ipc => .{
                .kind = .service,
                .id = if (request.target_id != 0) request.target_id else self.service_targets.service_registry_id,
            },
        };
    }

    fn denialDecision(
        self: *const PolicyMediator,
        task: *const task_runtime.TaskRecord,
        request: manifest.PermissionRequest,
        reason: abi.DenialReason,
    ) Decision {
        _ = self;
        return .{
            .request = request,
            .task_id = task.id,
            .owner = task.owner,
            .allowed = false,
            .reason = reason,
        };
    }

    fn recordDecision(
        self: *PolicyMediator,
        owner: principal.PrincipalId,
        task_id: u64,
        request: manifest.PermissionRequest,
        allowed: bool,
        reason: abi.DenialReason,
        now_ticks: u64,
    ) Error!void {
        const ledger = self.ledger orelse return;
        try ledger.recordPermissionDecision(
            owner,
            task_id,
            request.kind,
            allowed,
            reason,
            now_ticks,
            request.resource,
            request.kind == .object_access or request.kind == .contacts or request.kind == .location,
        );
    }
};

fn emptyDecision() PermissionDecision {
    return .{
        .kind = .object_access,
        .allowed = false,
    };
}

fn resourceId(resource: []const u8) u64 {
    return native_util.fnv1a64(resource);
}

fn taskDisplayName(task: *const task_runtime.TaskRecord) []const u8 {
    const components = task.executionComponents();
    if (components.len != 0 and components[0].labelSlice().len != 0) return components[0].labelSlice();
    if (task.launchBundleIdSlice().len != 0) return task.launchBundleIdSlice();
    return "app";
}

fn maxDelegationDepthForRequest(request: manifest.PermissionRequest) u8 {
    return switch (request.kind) {
        .device_access,
        .clipboard,
        .camera,
        .mic,
        .sensor,
        .location,
        .contacts,
        .screen_capture,
        .notification_post,
        => 0,
        .peer_ipc => 1,
        .object_access, .network_egress, .background_execution => capability.DEFAULT_MAX_DELEGATION_DEPTH,
    };
}

fn finiteLeaseRequired(kind: manifest.PermissionKind) bool {
    return switch (kind) {
        .device_access,
        .clipboard,
        .camera,
        .mic,
        .sensor,
        .location,
        .contacts,
        .screen_capture,
        => true,
        .object_access, .network_egress, .notification_post, .background_execution, .peer_ipc => false,
    };
}

fn createMediationTestTask(
    runtime: *task_runtime.Runtime,
    owner_serial: u64,
    local_only: bool,
) !*task_runtime.TaskRecord {
    return runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = owner_serial },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = local_only,
    });
}

test "policy activation summary keeps bounded counters compact" {
    try std.testing.expect(ZERO_CAPABILITY_ID_IS_NONE);
    try std.testing.expectEqual(u64, @FieldType(PermissionDecision, "capability_id"));
    try std.testing.expect(@sizeOf(PermissionDecision) <= PERMISSION_DECISION_SIZE_CEILING_BYTES);
    try std.testing.expectEqual(@as(?u64, null), emptyDecision().capabilityId());
    try std.testing.expectEqual(u8, @FieldType(ActivationSummary, "granted_count"));
    try std.testing.expectEqual(u8, @FieldType(ActivationSummary, "denied_count"));
    try std.testing.expectEqual(u8, @FieldType(ActivationSummary, "required_denials"));
    try std.testing.expectEqual(u8, @FieldType(ActivationSummary, "decision_count"));
    try std.testing.expect(@sizeOf(ActivationSummary) <= ACTIVATION_SUMMARY_SIZE_CEILING_BYTES);
}

test "policy mediation denies zero-authority requests without user grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 1, true);
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 11,
            .compositor_service_id = 12,
            .policy_service_id = 13,
            .service_registry_id = 14,
        },
    );
    var ledger = event_ledger.Ledger.init();
    mediator.attachLedger(&ledger);

    const decision = try mediator.authorizeRequest(task.id, .{
        .kind = .network_egress,
        .resource = "lan.sync",
        .rights = .{ .network_policy = .{ .network_local = true } },
        .required = false,
        .local_only = true,
    }, &.{}, 10);

    try std.testing.expect(!decision.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, decision.reason);
    try std.testing.expectEqualStrings("user-grant-policy", decision.explanation.policySlice());
    try std.testing.expect(decision.explanation.userApprovalCanResolve());
    try std.testing.expectEqual(event_ledger.EventKind.permission_decision, ledger.latestKind(.permission_decision).?.kind);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, ledger.latestKind(.permission_decision).?.denial_reason);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
}

test "policy mediation grants local-only object and network capabilities" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
    });
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 21,
            .compositor_service_id = 22,
            .policy_service_id = 23,
            .service_registry_id = 24,
        },
    );
    var ledger = event_ledger.Ledger.init();
    mediator.attachLedger(&ledger);

    const requests = [_]manifest.PermissionRequest{
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
            .max_lease_ticks = 25,
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace:notes",
                .principal = "trusted-devices",
            },
        },
    };
    const bundle = manifest_fixtures.basicNotesBundle(&requests);
    const grants = [_]UserGrant{
        .{ .kind = .object_access, .resource = "workspace:notes", .local_only = true, .expires_at_ticks = 200 },
        .{ .kind = .network_egress, .resource = "lan.sync", .local_only = true, .expires_at_ticks = 40 },
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 10);

    try std.testing.expectEqual(@as(u8, 2), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 0), summary.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);
    try std.testing.expect(summary.decisionForKind(.network_egress).?.local_only);
    try std.testing.expectEqual(@as(u64, 35), summary.decisionForKind(.network_egress).?.expires_at_ticks);
    const network_capability = capability_table.query(summary.decisionForKind(.network_egress).?.capabilityId().?).?;
    try std.testing.expectEqual(capability.CapabilityTargetKind.network_policy, network_capability.target.kind);
    try std.testing.expectEqual(resourceId("lan.sync"), network_capability.target.id);
    try std.testing.expect(ledger.latestKind(.permission_decision).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.none, ledger.latestKind(.permission_decision).?.denial_reason);
    try std.testing.expect(std.mem.indexOf(u8, ledger.latestKind(.capability_grant).?.detailSlice(), "Permission receipt") != null);
    try std.testing.expect(std.mem.indexOf(u8, ledger.latestKind(.capability_grant).?.detailSlice(), "capability=") != null);
    try std.testing.expect(std.mem.indexOf(u8, ledger.latestKind(.capability_grant).?.detailSlice(), "revoke:") != null);
    try std.testing.expectEqual(task_runtime.AuditEventKind.policy_allowed, task.latestAuditEvent().?.kind);

    const revoked_capability_id = summary.decisionForKind(.network_egress).?.capabilityId().?;
    try std.testing.expect(try mediator.revokeGrantedCapability(task.id, revoked_capability_id, .network_egress, 20, "data route grant revoked"));
    try std.testing.expect(!runtime.hasCapability(task.id, revoked_capability_id));
    try std.testing.expect(capability_table.query(revoked_capability_id) == null);
    try std.testing.expectEqual(task_runtime.AuditEventKind.capability_revoked, task.latestAuditEvent().?.kind);
    try std.testing.expectEqual(event_ledger.EventKind.capability_revocation, ledger.latestKind(.capability_revocation).?.kind);
    var revoke_buffer: [REVOCATION_RECEIPT_BUFFER_BYTES]u8 = undefined;
    const revoke_receipt = try humane_permissions.renderRevocationReceiptToBuffer(
        &revoke_buffer,
        revoked_capability_id,
        .network_egress,
        "lan.sync",
        20,
        "data route grant revoked",
    );
    try std.testing.expect(std.mem.indexOf(u8, revoke_receipt, "is off now") != null);
    try std.testing.expect(std.mem.indexOf(u8, revoke_receipt, "approve a new permission review") != null);
}

test "policy mediation rolls back minted capability when task attachment fails" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 20, false);
    var existing_id: u64 = 10;
    while (existing_id < 10 + task_runtime.MAX_TASK_CAPABILITIES) : (existing_id += 1) {
        try runtime.grantCapability(task.id, existing_id);
    }
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 21,
            .compositor_service_id = 22,
            .policy_service_id = 23,
            .service_registry_id = 24,
        },
    );

    try std.testing.expectError(error.CapabilityTableFull, mediator.authorizeRequest(task.id, .{
        .kind = .object_access,
        .resource = "workspace:notes",
        .rights = .{ .object = .{ .object_read = true } },
    }, &.{
        .{ .kind = .object_access, .resource = "workspace:notes", .expires_at_ticks = 100 },
    }, 10));

    try std.testing.expectEqual(@as(usize, task_runtime.MAX_TASK_CAPABILITIES), task.capability_count);
    try std.testing.expect(capability_table.query(1) == null);
    try std.testing.expect(!runtime.hasCapability(task.id, 1));
}

test "policy mediation suspends tasks when required background permission is denied" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
            .background_allowed = false,
        },
    });
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 31,
            .compositor_service_id = 32,
            .policy_service_id = 33,
            .service_registry_id = 34,
        },
    );

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .task = .{ .background_run = true } },
        },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
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
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_tasks = &background_tasks,
    };
    const grants = [_]UserGrant{
        .{ .kind = .background_execution, .resource = "sync", .expires_at_ticks = 30 },
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 5);

    try std.testing.expectEqual(@as(u8, 0), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 1), summary.required_denials);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, summary.decisionForKind(.background_execution).?.reason);
    try std.testing.expectEqualStrings("resource-budget-policy", summary.decisionForKind(.background_execution).?.explanation.policySlice());
    try std.testing.expect(summary.decisionForKind(.background_execution).?.explanation.retryIsSafe());
    try std.testing.expectEqual(task_runtime.TaskState.suspended, task.state);
}

test "policy mediation reports expired grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 4, false);
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 41,
            .compositor_service_id = 42,
            .policy_service_id = 43,
            .service_registry_id = 44,
        },
    );

    const decision = try mediator.authorizeRequest(task.id, .{
        .kind = .network_egress,
        .resource = "lan.sync",
        .rights = .{ .network_policy = .{ .network_local = true } },
        .local_only = true,
    }, &.{
        .{ .kind = .network_egress, .resource = "lan.sync", .local_only = true, .expires_at_ticks = 5 },
    }, 10);

    try std.testing.expect(!decision.allowed);
    try std.testing.expectEqual(abi.DenialReason.capability_expired, decision.reason);
}

test "policy mediation ignores expired allow grants when a later valid grant matches" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 45, true);
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 41,
            .compositor_service_id = 42,
            .policy_service_id = 43,
            .service_registry_id = 44,
        },
    );

    const decision = try mediator.authorizeRequest(task.id, .{
        .kind = .object_access,
        .resource = "workspace:notes",
        .rights = .{ .object = .{ .object_read = true } },
        .local_only = true,
        .max_lease_ticks = 20,
    }, &.{
        .{ .kind = .object_access, .resource = "workspace:notes", .local_only = true, .expires_at_ticks = 5 },
        .{ .kind = .object_access, .resource = "workspace:notes", .local_only = true, .expires_at_ticks = 40 },
    }, 10);

    try std.testing.expect(decision.allowed);
    try std.testing.expectEqual(@as(u64, 30), decision.expires_at_ticks);
    try std.testing.expectEqual(@as(usize, 1), task.capability_count);
}

test "policy mediation validates manifests before granting capabilities" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 5, false);
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 51,
            .compositor_service_id = 52,
            .policy_service_id = 53,
            .service_registry_id = 54,
        },
    );

    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .push_event,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = units.kibibytes(1),
            },
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .background_tasks = &background_tasks,
    };

    try std.testing.expectError(error.MissingBackgroundPermission, mediator.applyManifest(task.id, bundle, &.{}, 10));
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
}

test "policy mediation rolls back activation grants when a required permission fails" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 46 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
            .background_allowed = false,
        },
        .local_only = true,
    });
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 51,
            .compositor_service_id = 52,
            .policy_service_id = 53,
            .service_registry_id = 54,
        },
    );

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 20,
        },
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .task = .{ .background_run = true } },
        },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
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
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.rollback",
        .display_name = "Rollback",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_tasks = &background_tasks,
    };

    const summary = try mediator.applyManifest(task.id, bundle, &.{
        .{ .kind = .object_access, .resource = "workspace:notes", .local_only = true, .expires_at_ticks = 30 },
        .{ .kind = .background_execution, .resource = "sync", .expires_at_ticks = 30 },
    }, 10);

    try std.testing.expectEqual(@as(u8, 1), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 1), summary.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, task.state);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(capability_table.query(summary.decisionForKind(.object_access).?.capabilityId().?) == null);
}

test "policy mediation covers device camera mic sensor and peer ipc permissions" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
    });
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 61,
            .compositor_service_id = 62,
            .policy_service_id = 63,
            .service_registry_id = 64,
        },
    );

    const bundle = manifest_fixtures.captureBundle();
    const grants = [_]UserGrant{
        .{ .kind = .device_access, .resource = "capture.card0", .local_only = true, .expires_at_ticks = 50 },
        .{ .kind = .camera, .resource = "camera.front", .local_only = true, .expires_at_ticks = 45 },
        .{ .kind = .sensor, .resource = "sensor.lid", .local_only = true, .expires_at_ticks = 40 },
        .{ .kind = .peer_ipc, .resource = "zigos.peer.share", .local_only = true, .expires_at_ticks = 30 },
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 10);

    try std.testing.expectEqual(@as(u8, 4), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 1), summary.denied_count);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expect(summary.decisionForKind(.device_access).?.allowed);
    try std.testing.expect(summary.decisionForKind(.camera).?.allowed);
    try std.testing.expect(!summary.decisionForKind(.mic).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, summary.decisionForKind(.mic).?.reason);
    try std.testing.expect(summary.decisionForKind(.sensor).?.allowed);
    try std.testing.expect(summary.decisionForKind(.peer_ipc).?.allowed);

    const device_capability = capability_table.query(summary.decisionForKind(.device_access).?.capabilityId().?).?;
    const camera_capability = capability_table.query(summary.decisionForKind(.camera).?.capabilityId().?).?;
    const sensor_capability = capability_table.query(summary.decisionForKind(.sensor).?.capabilityId().?).?;
    const peer_capability = capability_table.query(summary.decisionForKind(.peer_ipc).?.capabilityId().?).?;

    try std.testing.expectEqual(capability.CapabilityTargetKind.device, device_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 700), device_capability.target.id);
    try std.testing.expectEqual(@as(u64, 701), camera_capability.target.id);
    try std.testing.expectEqual(@as(u8, 0), device_capability.audit.max_delegation_depth);
    try std.testing.expectEqual(@as(u8, 0), camera_capability.audit.max_delegation_depth);
    try std.testing.expectEqual(@as(u64, 703), sensor_capability.target.id);
    try std.testing.expectEqual(@as(u8, 0), sensor_capability.audit.max_delegation_depth);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, peer_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 64), peer_capability.target.id);
    try std.testing.expectEqual(@as(u8, 1), peer_capability.audit.max_delegation_depth);
}

test "policy mediation maps location contacts screen capture and notification capabilities" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 41 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 8,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
    });
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 42 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 88,
            .compositor_service_id = 89,
            .policy_service_id = 90,
            .service_registry_id = 91,
        },
    );

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .location,
            .resource = "location.current",
            .rights = .{ .device = .{ .location_read = true } },
            .local_only = true,
        },
        .{
            .kind = .contacts,
            .resource = "contacts://personal",
            .rights = .{ .object = .{ .contacts_read = true } },
            .local_only = true,
            .target_id = 3_001,
        },
        .{
            .kind = .screen_capture,
            .resource = "display:main",
            .rights = .{ .device = .{ .screen_capture = true } },
            .required = false,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .task = .{ .notification_post = true } },
            .required = false,
        },
    };
    const grants = [_]UserGrant{
        .{ .kind = .location, .resource = "location.current", .local_only = true, .expires_at_ticks = 50 },
        .{ .kind = .contacts, .resource = "contacts://personal", .local_only = true, .expires_at_ticks = 50 },
        .{ .kind = .screen_capture, .resource = "display:main", .expires_at_ticks = 50 },
        .{ .kind = .notification_post, .resource = "notifications://task", .expires_at_ticks = 50 },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.organizer",
        .display_name = "Organizer",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 10);
    try std.testing.expect(summary.decisionForKind(.location).?.allowed);
    try std.testing.expect(summary.decisionForKind(.contacts).?.allowed);
    try std.testing.expect(summary.decisionForKind(.screen_capture).?.allowed);
    try std.testing.expect(summary.decisionForKind(.notification_post).?.allowed);

    const location_capability = capability_table.query(summary.decisionForKind(.location).?.capabilityId().?).?;
    const contacts_capability = capability_table.query(summary.decisionForKind(.contacts).?.capabilityId().?).?;
    const capture_capability = capability_table.query(summary.decisionForKind(.screen_capture).?.capabilityId().?).?;
    const notification_capability = capability_table.query(summary.decisionForKind(.notification_post).?.capabilityId().?).?;

    try std.testing.expectEqual(capability.CapabilityTargetKind.device, location_capability.target.kind);
    try std.testing.expect(location_capability.rights.has(.location_read));
    try std.testing.expectEqual(@as(u8, 0), location_capability.audit.max_delegation_depth);
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, contacts_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 3_001), contacts_capability.target.id);
    try std.testing.expect(contacts_capability.rights.has(.contacts_read));
    try std.testing.expectEqual(@as(u8, 0), contacts_capability.audit.max_delegation_depth);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, capture_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 89), capture_capability.target.id);
    try std.testing.expect(capture_capability.rights.has(.screen_capture));
    try std.testing.expectEqual(@as(u8, 0), capture_capability.audit.max_delegation_depth);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, notification_capability.target.kind);
    try std.testing.expect(notification_capability.rights.has(.notification_post));
    try std.testing.expectEqual(@as(u8, 0), notification_capability.audit.max_delegation_depth);
}

test "policy mediation seals sensory grants against transitive delegation" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 42, true);
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 43 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 88,
            .compositor_service_id = 89,
            .policy_service_id = 90,
            .service_registry_id = 91,
        },
    );

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device = .{
                .capability_derive = true,
                .device_use = true,
            } },
            .local_only = true,
            .target_id = 4_200,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.camera-delegation-attempt",
        .display_name = "Camera Delegation Attempt",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    };
    const grants = [_]UserGrant{
        .{ .kind = .camera, .resource = "camera.front", .local_only = true, .expires_at_ticks = 50 },
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 10);
    const camera_capability = capability_table.query(summary.decisionForKind(.camera).?.capabilityId().?).?;
    try std.testing.expect(camera_capability.rights.has(.capability_derive));
    try std.testing.expectEqual(@as(u8, 0), camera_capability.audit.max_delegation_depth);
    try std.testing.expectError(error.DelegationDepthExceeded, capability_table.derive(.{
        .parent_capability_id = camera_capability.id,
        .holder = .{ .kind = .app, .serial = 4201 },
        .rights = .{ .device = .{ .device_use = true } },
        .scope = camera_capability.scope,
        .lease = .{ .issued_at_ticks = 11, .expires_at_ticks = 40, .renewable = false },
    }));
}

test "policy mediation requires finite leases for sensory grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try createMediationTestTask(&runtime, 43, true);
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 44 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 88,
            .compositor_service_id = 89,
            .policy_service_id = 90,
            .service_registry_id = 91,
        },
    );

    const camera_request = manifest.PermissionRequest{
        .kind = .camera,
        .resource = "camera.front",
        .rights = .{ .device = .{ .device_use = true } },
        .local_only = true,
        .target_id = 4_300,
    };
    const unbounded = try mediator.authorizeRequest(task.id, camera_request, &.{
        .{ .kind = .camera, .resource = "camera.front", .local_only = true },
    }, 10);
    try std.testing.expect(!unbounded.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, unbounded.reason);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);

    const bounded = try mediator.authorizeRequest(task.id, camera_request, &.{
        .{ .kind = .camera, .resource = "camera.front", .local_only = true, .expires_at_ticks = 30 },
    }, 10);
    try std.testing.expect(bounded.allowed);
    try std.testing.expectEqual(@as(u64, 30), bounded.expires_at_ticks);
    try std.testing.expectEqual(@as(usize, 1), task.capability_count);
}

test "policy mediation denies clipboard and screen capture without explicit grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 77 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(2),
            .endpoint_slots = 8,
            .shared_memory_bytes = units.kibibytes(2),
        },
        .local_only = true,
    });
    var mediator = PolicyMediator.init(
        .{ .kind = .policy_authority, .serial = 78 },
        &capability_table,
        &runtime,
        .{
            .network_service_id = 88,
            .compositor_service_id = 89,
            .policy_service_id = 90,
            .service_registry_id = 91,
        },
    );

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .workspace = .{ .clipboard_read = true } },
            .required = false,
        },
        .{
            .kind = .screen_capture,
            .resource = "display:main",
            .rights = .{ .device = .{ .screen_capture = true } },
            .required = false,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.scrape-attempt",
        .display_name = "Scrape Attempt",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    };

    const summary = try mediator.applyManifest(task.id, bundle, &.{}, 10);

    try std.testing.expectEqual(@as(u8, 0), summary.granted_count);
    try std.testing.expectEqual(@as(u8, 2), summary.denied_count);
    try std.testing.expectEqual(@as(u8, 0), summary.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(!summary.decisionForKind(.clipboard).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, summary.decisionForKind(.clipboard).?.reason);
    try std.testing.expect(!summary.decisionForKind(.screen_capture).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, summary.decisionForKind(.screen_capture).?.reason);
    try std.testing.expect(capability_table.query(1) == null);
}
