const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const generated_image_fixtures = if (@import("builtin").is_test) @import("generated_image_fixtures.zig") else struct {};
const principal = @import("../core/principal.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");

pub const Operation = enum(u8) {
    inspect_memory,
    inject_code,
    scrape_window,
    watch_clipboard,
    register_global_hook,
};

pub const TASK_INDEX_LOOKUPS_PER_UNIQUE_TASK: u8 = 1;
pub const AUDIT_TASK_INDEX_RELOOKUPS: u8 = 0;

pub const Request = struct {
    caller_task_id: u64,
    target_task_id: u64 = 0,
    capability_id: u64,
    operation: Operation,
    user_visible: bool,
    privacy_indicator_id: u64 = 0,
    privacy_indicator_expires_at_ticks: u64 = 0,
    hidden: bool = false,
    continuous: bool = false,
    now_ticks: u64,
};

pub const Decision = struct {
    allowed: bool,
    operation: Operation,
    caller_task_id: u64,
    target_task_id: u64,
    capability_id: u64,
    privacy_indicator_id: u64 = 0,
    reason: abi.DenialReason = .none,
};

pub const Error = task_runtime.Error || capability.Error || error{
    ActivePrivacyIndicatorRequired,
    ContinuousOperationDenied,
    HiddenOperationDenied,
    InvalidIsolationTarget,
    PermissionDenied,
    ScopeViolation,
    SubjectTaskMismatch,
    TaskNotFound,
    VisibleEntitlementRequired,
};

pub const Broker = struct {
    runtime: *task_runtime.Runtime,
    capability_table: *const capability.CapabilityTable,

    pub fn init(runtime: *task_runtime.Runtime, capability_table: *const capability.CapabilityTable) Broker {
        return .{
            .runtime = runtime,
            .capability_table = capability_table,
        };
    }

    pub fn authorize(self: *Broker, request: Request) Error!Decision {
        const caller = self.runtime.find(request.caller_task_id) orelse return error.TaskNotFound;
        const target_task_id = try requiredTargetTaskId(request);
        const target = if (target_task_id == caller.id)
            caller
        else
            self.runtime.find(target_task_id) orelse return error.TaskNotFound;

        if (isCrossTaskOperation(request.operation)) {
            if (target_task_id == request.caller_task_id) {
                auditDenied(caller, request, 0, .invalid_target);
                return error.InvalidIsolationTarget;
            }
            if (!tasksAreProcessSeparated(caller, target)) {
                auditDenied(caller, request, 0, .scope_violation);
                return error.ScopeViolation;
            }
        }

        if (request.hidden) {
            auditDenied(caller, request, 0, .policy_denied);
            return error.HiddenOperationDenied;
        }
        if (request.continuous and !operationSupportsContinuous(request.operation)) {
            auditDenied(caller, request, 0, .policy_denied);
            return error.ContinuousOperationDenied;
        }

        const owned = self.capability_table.requireUsable(request.capability_id, request.now_ticks) catch |err| switch (err) {
            error.CapabilityNotFound => {
                auditDenied(caller, request, 0, .capability_missing);
                return error.CapabilityNotFound;
            },
            error.CapabilityRevoked => {
                auditDenied(caller, request, request.capability_id, .capability_revoked);
                return error.CapabilityRevoked;
            },
        };
        if (!caller.hasCapability(owned.id)) {
            auditDenied(caller, request, owned.id, .capability_missing);
            return error.CapabilityNotFound;
        }
        if (!caller.owner.eql(owned.holder)) {
            auditDenied(caller, request, owned.id, .policy_denied);
            return error.PermissionDenied;
        }
        if (owned.target.kind != .task or owned.target.id != target_task_id) {
            auditDenied(caller, request, owned.id, .invalid_target);
            return error.InvalidIsolationTarget;
        }
        if (!owned.rights.has(.process_control)) {
            auditDenied(caller, request, owned.id, .policy_denied);
            return error.PermissionDenied;
        }
        if (owned.scope.task_id == null or owned.scope.task_id.? != request.caller_task_id) {
            auditDenied(caller, request, owned.id, .scope_violation);
            return error.ScopeViolation;
        }
        if (!owned.audit.user_visible_entitlement or !request.user_visible) {
            auditDenied(caller, request, owned.id, .policy_denied);
            return error.VisibleEntitlementRequired;
        }
        if (!privacyIndicatorActive(request)) {
            auditDenied(caller, request, owned.id, .policy_denied);
            return error.ActivePrivacyIndicatorRequired;
        }

        caller.appendAudit(.{
            .kind = .policy_allowed,
            .capability_id = owned.id,
            .detail = allowedAuditDetail(request),
            .tick = request.now_ticks,
        });
        return .{
            .allowed = true,
            .operation = request.operation,
            .caller_task_id = request.caller_task_id,
            .target_task_id = target_task_id,
            .capability_id = owned.id,
            .privacy_indicator_id = request.privacy_indicator_id,
        };
    }

};

fn auditDenied(caller: *task_runtime.TaskRecord, request: Request, capability_id: u64, reason: abi.DenialReason) void {
    caller.appendAudit(.{
        .kind = .policy_denied,
        .capability_id = capability_id,
        .detail = (@as(u32, @intFromEnum(reason)) << 8) | @as(u32, @intFromEnum(request.operation)),
        .tick = request.now_ticks,
    });
}

fn tasksAreProcessSeparated(left: *const task_runtime.TaskRecord, right: *const task_runtime.TaskRecord) bool {
    return left.process_id != right.process_id and
        left.address_space_id != right.address_space_id and
        left.namespace_id != right.namespace_id;
}

fn privacyIndicatorActive(request: Request) bool {
    return request.privacy_indicator_id != 0 and request.privacy_indicator_expires_at_ticks > request.now_ticks;
}

fn allowedAuditDetail(request: Request) u32 {
    return (@as(u32, @truncate(request.privacy_indicator_id)) << 8) | @as(u32, @intFromEnum(request.operation));
}

fn requiredTargetTaskId(request: Request) Error!u64 {
    return switch (request.operation) {
        .inspect_memory, .inject_code, .scrape_window => blk: {
            if (request.target_task_id == 0) return error.InvalidIsolationTarget;
            break :blk request.target_task_id;
        },
        .watch_clipboard, .register_global_hook => if (request.target_task_id == 0)
            request.caller_task_id
        else
            request.target_task_id,
    };
}

fn isCrossTaskOperation(operation: Operation) bool {
    return switch (operation) {
        .inspect_memory, .inject_code, .scrape_window => true,
        .watch_clipboard, .register_global_hook => false,
    };
}

fn operationSupportsContinuous(operation: Operation) bool {
    return switch (operation) {
        .watch_clipboard, .register_global_hook => true,
        .inspect_memory, .inject_code, .scrape_window => false,
    };
}

fn visibleProcessControlCapability(
    table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    caller_task_id: u64,
    target_task_id: u64,
    visible: bool,
    tick: u64,
) !capability.Capability {
    return table.mintBootRoot(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = target_task_id },
        .rights = .{ .task = .{ .process_control = true } },
        .scope = .{
            .task_id = caller_task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = tick,
            .expires_at_ticks = tick + 100,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = caller_task_id,
            .broker_service_id = 77,
            .user_visible_entitlement = visible,
        },
    });
}

fn createApp(runtime: *task_runtime.Runtime, owner: principal.PrincipalId) !*task_runtime.TaskRecord {
    const image = try generated_image_fixtures.appImage();
    return runtime.createTask(.{
        .owner = owner,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(64),
            .endpoint_slots = 4,
            .shared_memory_bytes = shared_memory.PAGE_SIZE,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = owner.serial,
            .component_abi_version = abi.ABI_VERSION,
            .signed = true,
            .bundle_id = "app.process-isolation-test",
        },
        .userspace_image = &image,
    });
}

test "process isolation denies memory injection window clipboard and hook bypasses without visible entitlements" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var broker = Broker.init(&runtime, &capabilities);

    const attacker = try createApp(&runtime, .{ .kind = .app, .serial = 501 });
    const victim = try createApp(&runtime, .{ .kind = .app, .serial = 502 });
    try std.testing.expect(runtime.processSeparated(attacker.id, victim.id));

    try std.testing.expectError(error.CapabilityNotFound, broker.authorize(.{
        .caller_task_id = attacker.id,
        .target_task_id = victim.id,
        .capability_id = 999,
        .operation = .inspect_memory,
        .user_visible = true,
        .now_ticks = 10,
    }));

    const ordinary = try capabilities.mintBootRoot(.{
        .holder = attacker.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = victim.id },
        .rights = .{ .task = .{ .capability_query = true } },
        .scope = .{ .task_id = attacker.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 100 },
        .audit = .{ .policy_generation = 1, .source_task_id = attacker.id, .broker_service_id = 77, .user_visible_entitlement = true },
    });
    try runtime.grantCapability(attacker.id, ordinary.id);
    try std.testing.expectError(error.PermissionDenied, broker.authorize(.{
        .caller_task_id = attacker.id,
        .target_task_id = victim.id,
        .capability_id = ordinary.id,
        .operation = .inject_code,
        .user_visible = true,
        .now_ticks = 11,
    }));

    const invisible = try visibleProcessControlCapability(&capabilities, attacker.owner, attacker.id, victim.id, false, 12);
    try runtime.grantCapability(attacker.id, invisible.id);
    try std.testing.expectError(error.VisibleEntitlementRequired, broker.authorize(.{
        .caller_task_id = attacker.id,
        .target_task_id = victim.id,
        .capability_id = invisible.id,
        .operation = .scrape_window,
        .user_visible = true,
        .now_ticks = 13,
    }));

    const visible_cross_task = try visibleProcessControlCapability(&capabilities, attacker.owner, attacker.id, victim.id, true, 14);
    try runtime.grantCapability(attacker.id, visible_cross_task.id);
    try std.testing.expectError(error.HiddenOperationDenied, broker.authorize(.{
        .caller_task_id = attacker.id,
        .target_task_id = victim.id,
        .capability_id = visible_cross_task.id,
        .operation = .scrape_window,
        .user_visible = true,
        .privacy_indicator_id = 44,
        .privacy_indicator_expires_at_ticks = 100,
        .hidden = true,
        .now_ticks = 15,
    }));
    try std.testing.expectError(error.ContinuousOperationDenied, broker.authorize(.{
        .caller_task_id = attacker.id,
        .target_task_id = victim.id,
        .capability_id = visible_cross_task.id,
        .operation = .inspect_memory,
        .user_visible = true,
        .privacy_indicator_id = 44,
        .privacy_indicator_expires_at_ticks = 100,
        .continuous = true,
        .now_ticks = 16,
    }));
    inline for (.{ Operation.inspect_memory, Operation.inject_code, Operation.scrape_window }) |operation| {
        const decision = try broker.authorize(.{
            .caller_task_id = attacker.id,
            .target_task_id = victim.id,
            .capability_id = visible_cross_task.id,
            .operation = operation,
            .user_visible = true,
            .privacy_indicator_id = 44,
            .privacy_indicator_expires_at_ticks = 100,
            .now_ticks = 20 + @intFromEnum(operation),
        });
        try std.testing.expect(decision.allowed);
        try std.testing.expectEqual(victim.id, decision.target_task_id);
        try std.testing.expectEqual(@as(u64, 44), decision.privacy_indicator_id);
    }

    const visible_self = try visibleProcessControlCapability(&capabilities, attacker.owner, attacker.id, attacker.id, true, 30);
    try runtime.grantCapability(attacker.id, visible_self.id);
    try std.testing.expectError(error.VisibleEntitlementRequired, broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = false,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 100,
        .now_ticks = 31,
    }));
    try std.testing.expectError(error.ActivePrivacyIndicatorRequired, broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .now_ticks = 31,
    }));
    try std.testing.expectError(error.ActivePrivacyIndicatorRequired, broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 31,
        .now_ticks = 31,
    }));
    try std.testing.expectError(error.ActivePrivacyIndicatorRequired, broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 31,
        .now_ticks = 32,
    }));
    try std.testing.expect((try broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 100,
        .now_ticks = 32,
    })).allowed);
    try std.testing.expectError(error.HiddenOperationDenied, broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .register_global_hook,
        .user_visible = true,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 100,
        .hidden = true,
        .now_ticks = 33,
    }));
    try std.testing.expectError(error.HiddenOperationDenied, broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 100,
        .hidden = true,
        .now_ticks = 34,
    }));
    try std.testing.expect((try broker.authorize(.{
        .caller_task_id = attacker.id,
        .capability_id = visible_self.id,
        .operation = .register_global_hook,
        .user_visible = true,
        .privacy_indicator_id = 55,
        .privacy_indicator_expires_at_ticks = 100,
        .now_ticks = 35,
    })).allowed);

    const latest = attacker.latestAuditEvent().?;
    try std.testing.expectEqual(task_runtime.AuditEventKind.policy_allowed, latest.kind);
    try std.testing.expectEqual((@as(u32, 55) << 8) | @as(u32, @intFromEnum(Operation.register_global_hook)), latest.detail);
}
