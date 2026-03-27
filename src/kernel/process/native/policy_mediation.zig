const abi = @import("abi.zig");
const capability = @import("capability.zig");
const manifest = @import("manifest.zig");
const principal = @import("principal.zig");
const task_runtime = @import("task_runtime.zig");

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

pub const Error = task_runtime.Error || capability.Error || manifest.ValidationError;

pub const PolicyMediator = struct {
    policy_authority: principal.PrincipalId,
    capability_table: *capability.CapabilityTable,
    runtime: *task_runtime.Runtime,
    service_targets: ServiceTargets,
    policy_generation: u32 = 1,

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

    pub fn authorizeRequest(
        self: *PolicyMediator,
        task_id: u64,
        request: manifest.PermissionRequest,
        grants: []const UserGrant,
        now_ticks: u64,
    ) Error!PermissionDecision {
        const task = self.runtime.find(task_id) orelse return error.TaskNotFound;

        const matched_grant = self.matchGrant(request, grants) orelse {
            return self.deny(task.id, request.kind, .policy_denied, now_ticks);
        };
        if (!matched_grant.allow) {
            return self.deny(task.id, request.kind, .policy_denied, now_ticks);
        }
        if (matched_grant.expires_at_ticks) |expiry| {
            if (now_ticks > expiry) {
                return self.deny(task.id, request.kind, .capability_expired, now_ticks);
            }
        }
        if (request.local_only and !matched_grant.local_only) {
            return self.deny(task.id, request.kind, .scope_violation, now_ticks);
        }
        if (request.kind == .background_execution and !task.background_allowed) {
            return self.deny(task.id, request.kind, .budget_exhausted, now_ticks);
        }

        const lease_end = self.resolveLeaseEnd(request, matched_grant, now_ticks);
        if (lease_end < now_ticks) {
            return self.deny(task.id, request.kind, .capability_expired, now_ticks);
        }

        const granted_local_only = request.local_only or matched_grant.local_only;
        const target = self.resolveTarget(request);
        const minted = try self.capability_table.mint(.{
            .holder = task.owner,
            .issuer = self.policy_authority,
            .target = target,
            .rights = request.rights,
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
        try self.runtime.grantCapability(task.id, minted.id);
        try self.runtime.audit(task.id, .{
            .kind = .policy_allowed,
            .capability_id = minted.id,
            .detail = @intFromEnum(request.kind),
            .tick = now_ticks,
        });

        return .{
            .kind = request.kind,
            .allowed = true,
            .capability_id = minted.id,
            .local_only = granted_local_only,
            .expires_at_ticks = lease_end,
        };
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
                .kind = .service,
                .id = self.service_targets.network_service_id,
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

    fn deny(
        self: *PolicyMediator,
        task_id: u64,
        kind: manifest.PermissionKind,
        reason: abi.DenialReason,
        now_ticks: u64,
    ) Error!PermissionDecision {
        try self.runtime.audit(task_id, .{
            .kind = .policy_denied,
            .detail = @intFromEnum(reason),
            .tick = now_ticks,
        });

        return .{
            .kind = kind,
            .allowed = false,
            .reason = reason,
        };
    }
};

fn emptyDecision() PermissionDecision {
    return .{
        .kind = .object_access,
        .allowed = false,
    };
}

fn resourceId(resource: []const u8) u64 {
    var hash: u64 = 1469598103934665603;
    for (resource) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return hash;
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

    const decision = try mediator.authorizeRequest(task.id, .{
        .kind = .network_egress,
        .resource = "lan.sync",
        .rights = .{ .network_local = true },
        .required = false,
        .local_only = true,
    }, &.{}, 10);

    try std.testing.expect(!decision.allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, decision.reason);
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

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
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
            .rights = .{ .background_run = true },
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
        .background_triggers = &.{.scheduled_sync},
    };
    const grants = [_]UserGrant{
        .{ .kind = .background_execution, .resource = "sync", .expires_at_ticks = 30 },
    };

    const summary = try mediator.applyManifest(task.id, bundle, &grants, 5);

    try std.testing.expectEqual(@as(usize, 0), summary.granted_count);
    try std.testing.expectEqual(@as(usize, 1), summary.required_denials);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, summary.decisionForKind(.background_execution).?.reason);
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
        .rights = .{ .network_local = true },
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

    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .background_triggers = &.{.scheduled_sync},
    };

    try std.testing.expectError(error.MissingBackgroundPermission, mediator.applyManifest(task.id, bundle, &.{}, 10));
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
}

test "policy mediation covers device camera mic sensor and peer ipc permissions" {
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

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .device_access,
            .resource = "capture.card0",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 30,
            .target_id = 700,
        },
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 701,
        },
        .{
            .kind = .mic,
            .resource = "mic.array",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 702,
        },
        .{
            .kind = .sensor,
            .resource = "sensor.lid",
            .rights = .{ .sensor_read = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 25,
            .target_id = 703,
        },
        .{
            .kind = .peer_ipc,
            .resource = "zigos.peer.share",
            .rights = .{ .ipc_peer = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 15,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.capture",
        .display_name = "Capture",
        .publisher = "zigos.dev",
        .requested_permissions = &requests,
    };
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
            .rights = .{ .location_read = true },
            .local_only = true,
        },
        .{
            .kind = .contacts,
            .resource = "contacts://personal",
            .rights = .{ .contacts_read = true },
            .local_only = true,
            .target_id = 3_001,
        },
        .{
            .kind = .screen_capture,
            .resource = "display:main",
            .rights = .{ .screen_capture = true },
            .required = false,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .notification_post = true },
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
    try std.testing.expect(location_capability.rights.location_read);
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, contacts_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 3_001), contacts_capability.target.id);
    try std.testing.expect(contacts_capability.rights.contacts_read);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, capture_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 89), capture_capability.target.id);
    try std.testing.expect(capture_capability.rights.screen_capture);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, notification_capability.target.kind);
    try std.testing.expect(notification_capability.rights.notification_post);
}
