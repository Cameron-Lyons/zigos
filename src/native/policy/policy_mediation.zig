const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const denial_explanation = @import("denial_explanation.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub const MAX_PERMISSION_DECISIONS: usize = 16;

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
    capability_id: ?u64 = null,
    local_only: bool = false,
    expires_at_ticks: u64 = 0,
    explanation: denial_explanation.Explanation = denial_explanation.none(),
};

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
    granted_count: usize = 0,
    denied_count: usize = 0,
    required_denials: usize = 0,
    decision_count: usize = 0,
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
        const decision = try self.evaluate(task_id, request, grants, now_ticks);
        if (!decision.allowed) {
            return self.commitDeniedDecision(decision, now_ticks);
        }

        const grant_plan = try self.planGrant(decision, now_ticks);
        var minted_buffer: [capability.MAX_GRANT_PLAN_ENTRIES]capability.Capability = undefined;
        return self.commitGrantPlan(decision, &grant_plan, &minted_buffer, now_ticks);
    }

    pub fn evaluate(
        self: *const PolicyMediator,
        task_id: u64,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) Error!Decision {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
        const matched_grant = self.matchGrant(request, grants) orelse {
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

    pub fn planGrant(
        self: *const PolicyMediator,
        decision: Decision,
        now_ticks: u64,
    ) Error!GrantPlan {
        if (!decision.allowed) return GrantPlan{};
        return self.grantPlanForRequest(
            decision.task_id,
            decision.request,
            decision.grant.?,
            decision.lease_end,
            now_ticks,
        );
    }

    pub fn commitGrantPlan(
        self: *PolicyMediator,
        decision: Decision,
        grant_plan: *const GrantPlan,
        minted_buffer: []capability.Capability,
        now_ticks: u64,
    ) Error!PermissionDecision {
        const minted = try self.applyGrantPlanTransactional(grant_plan, minted_buffer);
        const capability_id = minted[0].id;
        try self.runtime.audit(decision.task_id, .{
            .kind = .policy_allowed,
            .capability_id = capability_id,
            .detail = @intFromEnum(decision.request.kind),
            .tick = now_ticks,
        });
        try self.recordDecision(decision.owner, decision.task_id, decision.request, true, .none, now_ticks);
        if (self.ledger) |ledger| {
            try ledger.recordCapabilityGrant(
                decision.owner,
                decision.task_id,
                capability_id,
                decision.request.kind,
                now_ticks,
                decision.request.resource,
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

    pub fn commitDeniedDecision(
        self: *PolicyMediator,
        decision: Decision,
        now_ticks: u64,
    ) Error!PermissionDecision {
        try self.runtime.audit(decision.task_id, .{
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
        const detached = try self.runtime.revokeCapability(task_id, capability_id);
        if (!detached) return false;
        try self.capability_table.revokeGrant(capability_id);
        try self.runtime.audit(task_id, .{
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

    pub fn grantPlanForRequest(
        self: *const PolicyMediator,
        task_id: u64,
        request: manifest.PermissionRequest,
        grant: UserGrant,
        lease_end: u64,
        now_ticks: u64,
    ) Error!GrantPlan {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;
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
            },
        });
        return plan;
    }

    fn applyGrantPlanTransactional(
        self: *PolicyMediator,
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
                    _ = self.runtime.revokeCapability(entry.task_id, minted[revoke_index].id) catch |err|
                        native_util.impossibleByInvariantError("rollback revokes capabilities attached earlier in this grant transaction", err);
                }
            }
            self.capability_table.rollbackGrant(minted);
        }

        for (plan.slice(), minted) |entry, granted_capability| {
            if (entry.task_id != 0) {
                try self.runtime.grantCapability(entry.task_id, granted_capability.id);
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
            const decision = try self.authorizeRequest(task_id, request, grants, now_ticks);
            summary.addDecision(decision, request.required);
        }

        task.state = if (summary.required_denials == 0) .active else .suspended;
        return summary;
    }

    fn matchGrant(
        self: *const PolicyMediator,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
    ) ?UserGrant {
        _ = self;
        for (grants) |grant| {
            if (grant.kind != request.kind) continue;
            if (grant.resource.len != 0 and !std.mem.eql(u8, grant.resource, request.resource)) continue;
            return grant;
        }
        return null;
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
            lease_end = now_ticks + request.max_lease_ticks;
        }
        if (grant.expires_at_ticks) |expiry| {
            lease_end = @min(lease_end, expiry);
        }
        return lease_end;
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

const std = @import("std");

test "policy mediation denies zero-authority requests without user grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
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
    try std.testing.expect(decision.explanation.user_approval_can_resolve);
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
            .memory_bytes = 2048,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
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
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    };
    const grants = [_]UserGrant{
        .{ .kind = .object_access, .resource = "workspace:notes", .local_only = true, .expires_at_ticks = 200 },
        .{ .kind = .network_egress, .resource = "lan.sync", .local_only = true, .expires_at_ticks = 40 },
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 10);

    try std.testing.expectEqual(@as(usize, 2), summary.granted_count);
    try std.testing.expectEqual(@as(usize, 0), summary.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);
    try std.testing.expect(summary.decisionForKind(.network_egress).?.local_only);
    try std.testing.expectEqual(@as(u64, 35), summary.decisionForKind(.network_egress).?.expires_at_ticks);
    const network_capability = capability_table.query(summary.decisionForKind(.network_egress).?.capability_id.?).?;
    try std.testing.expectEqual(capability.CapabilityTargetKind.network_policy, network_capability.target.kind);
    try std.testing.expectEqual(resourceId("lan.sync"), network_capability.target.id);
    try std.testing.expect(ledger.latestKind(.permission_decision).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.none, ledger.latestKind(.permission_decision).?.denial_reason);

    const revoked_capability_id = summary.decisionForKind(.network_egress).?.capability_id.?;
    try std.testing.expect(try mediator.revokeGrantedCapability(task.id, revoked_capability_id, .network_egress, 20, "network grant revoked"));
    try std.testing.expect(!runtime.hasCapability(task.id, revoked_capability_id));
    try std.testing.expect(capability_table.query(revoked_capability_id) == null);
    try std.testing.expectEqual(event_ledger.EventKind.capability_revocation, ledger.latestKind(.capability_revocation).?.kind);
}

test "policy mediation rolls back minted capability when task attachment fails" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 20 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
    });
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
            .memory_bytes = 2048,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
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
                .memory_bytes = 1024,
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

    try std.testing.expectEqual(@as(usize, 0), summary.granted_count);
    try std.testing.expectEqual(@as(usize, 1), summary.required_denials);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, summary.decisionForKind(.background_execution).?.reason);
    try std.testing.expectEqualStrings("resource-budget-policy", summary.decisionForKind(.background_execution).?.explanation.policySlice());
    try std.testing.expect(summary.decisionForKind(.background_execution).?.explanation.retry_safe);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, task.state);
}

test "policy mediation reports expired grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
    });
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

test "policy mediation validates manifests before granting capabilities" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 5 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
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

    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .push_event,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 100,
                .memory_bytes = 1024,
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

test "policy mediation covers device camera mic sensor and peer ipc permissions" {
    const manifest_fixtures = @import("manifest_fixtures.zig");

    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 2048,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
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

    try std.testing.expectEqual(@as(usize, 4), summary.granted_count);
    try std.testing.expectEqual(@as(usize, 1), summary.denied_count);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expect(summary.decisionForKind(.device_access).?.allowed);
    try std.testing.expect(summary.decisionForKind(.camera).?.allowed);
    try std.testing.expect(!summary.decisionForKind(.mic).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, summary.decisionForKind(.mic).?.reason);
    try std.testing.expect(summary.decisionForKind(.sensor).?.allowed);
    try std.testing.expect(summary.decisionForKind(.peer_ipc).?.allowed);

    const device_capability = capability_table.query(summary.decisionForKind(.device_access).?.capability_id.?).?;
    const camera_capability = capability_table.query(summary.decisionForKind(.camera).?.capability_id.?).?;
    const sensor_capability = capability_table.query(summary.decisionForKind(.sensor).?.capability_id.?).?;
    const peer_capability = capability_table.query(summary.decisionForKind(.peer_ipc).?.capability_id.?).?;

    try std.testing.expectEqual(capability.CapabilityTargetKind.device, device_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 700), device_capability.target.id);
    try std.testing.expectEqual(@as(u64, 701), camera_capability.target.id);
    try std.testing.expectEqual(@as(u64, 703), sensor_capability.target.id);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, peer_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 64), peer_capability.target.id);
}

test "policy mediation maps location contacts screen capture and notification capabilities" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 41 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 2048,
            .endpoint_slots = 8,
            .shared_memory_bytes = 2048,
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

    const location_capability = capability_table.query(summary.decisionForKind(.location).?.capability_id.?).?;
    const contacts_capability = capability_table.query(summary.decisionForKind(.contacts).?.capability_id.?).?;
    const capture_capability = capability_table.query(summary.decisionForKind(.screen_capture).?.capability_id.?).?;
    const notification_capability = capability_table.query(summary.decisionForKind(.notification_post).?.capability_id.?).?;

    try std.testing.expectEqual(capability.CapabilityTargetKind.device, location_capability.target.kind);
    try std.testing.expect(location_capability.rights.has(.location_read));
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, contacts_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 3_001), contacts_capability.target.id);
    try std.testing.expect(contacts_capability.rights.has(.contacts_read));
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, capture_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 89), capture_capability.target.id);
    try std.testing.expect(capture_capability.rights.has(.screen_capture));
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, notification_capability.target.kind);
    try std.testing.expect(notification_capability.rights.has(.notification_post));
}

test "policy mediation denies clipboard and screen capture without explicit grants" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 77 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 2048,
            .endpoint_slots = 8,
            .shared_memory_bytes = 2048,
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

    try std.testing.expectEqual(@as(usize, 0), summary.granted_count);
    try std.testing.expectEqual(@as(usize, 2), summary.denied_count);
    try std.testing.expectEqual(@as(usize, 0), summary.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, task.state);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(!summary.decisionForKind(.clipboard).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, summary.decisionForKind(.clipboard).?.reason);
    try std.testing.expect(!summary.decisionForKind(.screen_capture).?.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, summary.decisionForKind(.screen_capture).?.reason);
    try std.testing.expect(capability_table.query(1) == null);
}
