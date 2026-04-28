const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("task_runtime.zig");

const copyText = native_util.copyText;

pub const MAX_RECORDS: usize = 16;
pub const MAX_TASK_ID_BYTES: usize = 48;

pub const RecordState = enum(u8) {
    running,
    delayed,
    denied,
    completed,
};

pub const DecisionReason = enum(u8) {
    allowed,
    task_not_found,
    task_not_active,
    task_terminated,
    background_not_allowed,
    bundle_mismatch,
    task_not_declared,
    background_permission_missing,
    trigger_mismatch,
    budget_exceeded,
    network_denied,
    visibility_denied,
    throttled,
};

pub const DispatchPolicy = struct {
    max_active_jobs: usize = 2,
    max_expected_duration_seconds: u32 = 300,
    max_cpu_time_ticks: u64 = 10_000,
    max_memory_bytes: usize = 512 * 1024,
    max_shared_memory_bytes: usize = 64 * 1024,
};

pub const DispatchRecord = struct {
    id: u64,
    task_id: u64,
    background_task_id_len: usize = 0,
    background_task_id: [MAX_TASK_ID_BYTES]u8 = [_]u8{0} ** MAX_TASK_ID_BYTES,
    trigger: manifest.BackgroundTrigger,
    expected_duration_seconds: u32,
    budget: manifest.BackgroundResourceBudget,
    network: manifest.BackgroundNetworkMode,
    visibility: manifest.BackgroundVisibility,
    state: RecordState,
    tick: u64,

    pub fn backgroundTaskIdSlice(self: *const DispatchRecord) []const u8 {
        return self.background_task_id[0..self.background_task_id_len];
    }
};

pub const DispatchDecision = struct {
    allowed: bool,
    delayed: bool,
    reason: DecisionReason,
    record_id: ?u64 = null,
    expected_duration_seconds: u32 = 0,
    budget: manifest.BackgroundResourceBudget = .{},
    network: manifest.BackgroundNetworkMode = .none,
    visibility: manifest.BackgroundVisibility = .status_only,
};

pub const Error = task_runtime.Error || error{
    DispatchTableFull,
    DispatchRecordNotFound,
};

const RecordSlot = struct {
    in_use: bool = false,
    record: DispatchRecord = zeroRecord(),
};

pub const Controller = struct {
    policy: DispatchPolicy = .{},
    next_record_id: u64 = 1,
    records: [MAX_RECORDS]RecordSlot = [_]RecordSlot{RecordSlot{}} ** MAX_RECORDS,

    pub fn init() Controller {
        return .{};
    }

    pub fn configure(self: *Controller, policy: DispatchPolicy) void {
        self.policy = policy;
    }

    pub fn dispatch(
        self: *Controller,
        runtime: *task_runtime.Runtime,
        task_id: u64,
        bundle: manifest.BundleManifest,
        background_task_id: []const u8,
        trigger: manifest.BackgroundTrigger,
        tick: u64,
    ) Error!DispatchDecision {
        const task = runtime.find(task_id) orelse {
            return self.recordDecision(task_id, background_task_id, trigger, null, .task_not_found, tick);
        };
        if (task.state == .terminated) {
            return self.recordDecision(task_id, background_task_id, trigger, null, .task_terminated, tick);
        }
        if (task.state == .staged) {
            return self.recordDecision(task_id, background_task_id, trigger, null, .task_not_active, tick);
        }
        if (!task.background_allowed) {
            return self.recordDecision(task_id, background_task_id, trigger, null, .background_not_allowed, tick);
        }
        if (task.launchBundleIdSlice().len == 0 or !std.mem.eql(u8, task.launchBundleIdSlice(), bundle.bundle_id)) {
            return self.recordDecision(task_id, background_task_id, trigger, null, .bundle_mismatch, tick);
        }

        const background_task = manifest.findBackgroundTask(bundle, background_task_id) orelse {
            return self.recordDecision(task_id, background_task_id, trigger, null, .task_not_declared, tick);
        };
        const permission = manifest.findBackgroundPermission(bundle, background_task_id) orelse {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .background_permission_missing, tick);
        };
        if (!permission.rights.has(.background_run)) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .background_permission_missing, tick);
        }
        if (background_task.trigger != trigger) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .trigger_mismatch, tick);
        }
        if (!budgetWithinPolicy(background_task, self.policy)) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .budget_exceeded, tick);
        }
        if (!networkAllowed(task, background_task.network)) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .network_denied, tick);
        }
        if (!visibilityAllowed(task, background_task.visibility)) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .visibility_denied, tick);
        }
        if (!runtime.canReserveBackgroundWork(task.id, background_task.budget)) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .budget_exceeded, tick);
        }
        if (self.activeRecordCount() >= self.policy.max_active_jobs) {
            return self.recordDecision(task_id, background_task_id, trigger, background_task, .throttled, tick);
        }

        const decision = try self.recordDecision(task_id, background_task_id, trigger, background_task, .allowed, tick);
        const reserved = try runtime.reserveBackgroundWork(
            task.id,
            background_task.budget,
            background_task.network,
            background_task.visibility,
            tick,
        );
        std.debug.assert(reserved);
        try runtime.audit(task_id, .{
            .kind = .background_dispatched,
            .detail = @intFromEnum(trigger),
            .tick = tick,
        });
        return decision;
    }

    pub fn complete(self: *Controller, runtime: *task_runtime.Runtime, record_id: u64) Error!bool {
        for (&self.records) |*slot| {
            if (!slot.in_use or slot.record.id != record_id) continue;
            if (slot.record.state != .running) return false;
            slot.record.state = .completed;
            if (!try runtime.releaseBackgroundWork(slot.record.task_id, slot.record.budget)) {
                slot.record.state = .running;
                return false;
            }
            return true;
        }
        return error.DispatchRecordNotFound;
    }

    pub fn activeRecordCount(self: *const Controller) usize {
        var count: usize = 0;
        for (self.records) |slot| {
            if (!slot.in_use) continue;
            if (slot.record.state == .running) count += 1;
        }
        return count;
    }

    pub fn latestRecord(self: *const Controller) ?DispatchRecord {
        var latest: ?DispatchRecord = null;
        for (self.records) |slot| {
            if (!slot.in_use) continue;
            if (latest == null or slot.record.id > latest.?.id) {
                latest = slot.record;
            }
        }
        return latest;
    }

    fn recordDecision(
        self: *Controller,
        task_id: u64,
        background_task_id: []const u8,
        trigger: manifest.BackgroundTrigger,
        background_task: ?manifest.BackgroundTaskDecl,
        reason: DecisionReason,
        tick: u64,
    ) Error!DispatchDecision {
        const record = try self.appendRecord(task_id, background_task_id, trigger, background_task, reason, tick);
        return .{
            .allowed = reason == .allowed,
            .delayed = reason == .throttled,
            .reason = reason,
            .record_id = record.id,
            .expected_duration_seconds = if (background_task) |task| task.expected_duration_seconds else 0,
            .budget = if (background_task) |task| task.budget else .{},
            .network = if (background_task) |task| task.network else .none,
            .visibility = if (background_task) |task| task.visibility else .status_only,
        };
    }

    fn appendRecord(
        self: *Controller,
        task_id: u64,
        background_task_id: []const u8,
        trigger: manifest.BackgroundTrigger,
        background_task: ?manifest.BackgroundTaskDecl,
        reason: DecisionReason,
        tick: u64,
    ) Error!DispatchRecord {
        const slot = self.allocateRecordSlot() orelse return error.DispatchTableFull;
        slot.in_use = true;
        slot.record = zeroRecord();
        slot.record.id = self.next_record_id;
        self.next_record_id += 1;
        slot.record.task_id = task_id;
        slot.record.background_task_id_len = copyText(&slot.record.background_task_id, background_task_id);
        slot.record.trigger = trigger;
        slot.record.state = switch (reason) {
            .allowed => .running,
            .throttled => .delayed,
            else => .denied,
        };
        slot.record.tick = tick;
        if (background_task) |task| {
            slot.record.expected_duration_seconds = task.expected_duration_seconds;
            slot.record.budget = task.budget;
            slot.record.network = task.network;
            slot.record.visibility = task.visibility;
        }
        return slot.record;
    }

    fn allocateRecordSlot(self: *Controller) ?*RecordSlot {
        for (&self.records) |*slot| {
            if (!slot.in_use) return slot;
        }
        for (&self.records) |*slot| {
            if (slot.record.state != .running) return slot;
        }
        return null;
    }
};

fn budgetWithinPolicy(task: manifest.BackgroundTaskDecl, policy: DispatchPolicy) bool {
    return task.expected_duration_seconds <= policy.max_expected_duration_seconds and
        task.budget.cpu_time_ticks <= policy.max_cpu_time_ticks and
        task.budget.memory_bytes <= policy.max_memory_bytes and
        task.budget.shared_memory_bytes <= policy.max_shared_memory_bytes;
}

fn networkAllowed(task: *const task_runtime.TaskRecord, network: manifest.BackgroundNetworkMode) bool {
    return switch (network) {
        .unspecified => false,
        .none, .local_network_only => true,
        .named_service_identities, .named_domains, .unrestricted_internet => !task.local_only,
    };
}

fn visibilityAllowed(task: *const task_runtime.TaskRecord, visibility: manifest.BackgroundVisibility) bool {
    return switch (visibility) {
        .unspecified => false,
        .hidden, .status_only, .audit_only => true,
        .user_visible => task.ui_surface_id != null,
    };
}

fn zeroRecord() DispatchRecord {
    return .{
        .id = 0,
        .task_id = 0,
        .trigger = .user_approved_scheduled_job,
        .expected_duration_seconds = 0,
        .budget = .{},
        .network = .none,
        .visibility = .status_only,
        .state = .completed,
        .tick = 0,
    };
}

test "background dispatch accepts declared triggers and preserves task metadata" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 300 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .ui_surface_id = 9,
        .local_only = false,
        .launch = .{
            .bundle_id = "app.background",
        },
    });
    task.state = .active;

    const permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "schedule", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "push", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "change", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "proximity", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "sensor", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "sync", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "media", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "policy", .rights = .{ .task = .{ .background_run = true } } },
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "schedule", .trigger = .user_approved_scheduled_job, .expected_duration_seconds = 30, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 64 * 1024 }, .network = .none, .visibility = .status_only },
        .{ .id = "push", .trigger = .push_event, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 800, .memory_bytes = 32 * 1024 }, .network = .named_service_identities, .visibility = .hidden },
        .{ .id = "change", .trigger = .local_object_change, .expected_duration_seconds = 15, .budget = .{ .cpu_time_ticks = 900, .memory_bytes = 16 * 1024 }, .network = .none, .visibility = .audit_only },
        .{ .id = "proximity", .trigger = .device_proximity, .expected_duration_seconds = 10, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = 16 * 1024 }, .network = .none, .visibility = .user_visible },
        .{ .id = "sensor", .trigger = .sensor_rule, .expected_duration_seconds = 25, .budget = .{ .cpu_time_ticks = 700, .memory_bytes = 24 * 1024 }, .network = .none, .visibility = .status_only },
        .{ .id = "sync", .trigger = .sync_completion, .expected_duration_seconds = 40, .budget = .{ .cpu_time_ticks = 1_200, .memory_bytes = 96 * 1024 }, .network = .local_network_only, .visibility = .status_only },
        .{ .id = "media", .trigger = .media_export_completion, .expected_duration_seconds = 35, .budget = .{ .cpu_time_ticks = 1_100, .memory_bytes = 48 * 1024 }, .network = .named_domains, .visibility = .status_only },
        .{ .id = "policy", .trigger = .organization_policy_task, .expected_duration_seconds = 45, .budget = .{ .cpu_time_ticks = 1_300, .memory_bytes = 80 * 1024 }, .network = .none, .visibility = .audit_only },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.background",
        .display_name = "Background",
        .publisher = "zigos.test",
        .requested_permissions = &permissions,
        .background_tasks = &background_tasks,
    };

    var controller = Controller.init();
    for (background_tasks) |background_task| {
        const decision = try controller.dispatch(&runtime, task.id, bundle, background_task.id, background_task.trigger, 10);
        try std.testing.expect(decision.allowed);
        try std.testing.expect(!decision.delayed);
        try std.testing.expectEqual(background_task.expected_duration_seconds, decision.expected_duration_seconds);
        try std.testing.expectEqual(background_task.network, decision.network);
        try std.testing.expectEqual(background_task.visibility, decision.visibility);
        try std.testing.expectEqual(background_task.budget.cpu_time_ticks, decision.budget.cpu_time_ticks);
        try std.testing.expect(try controller.complete(&runtime, decision.record_id.?));
    }

    try std.testing.expectEqual(@as(u16, 0), task.background_active_count);
    try std.testing.expectEqual(@as(u64, 7_500), task.background_cpu_consumed_ticks);
    try std.testing.expectEqual(@as(usize, 0), task.background_reserved_memory_bytes);
    try std.testing.expectEqual(manifest.BackgroundNetworkMode.none, task.last_background_network);
    try std.testing.expectEqual(manifest.BackgroundVisibility.audit_only, task.last_background_visibility);
    try std.testing.expectEqual(task_runtime.AuditEventKind.background_dispatched, task.latestAuditEvent().?.kind);
}

test "background dispatch throttles delayed work and denies abusive budgets" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 301 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .local_only = false,
        .launch = .{
            .bundle_id = "app.safe",
        },
    });
    task.state = .active;

    const safe_permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "sync", .rights = .{ .task = .{ .background_run = true } } },
    };
    const abusive_permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "heavy", .rights = .{ .task = .{ .background_run = true } } },
    };
    const safe_tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "sync", .trigger = .sync_completion, .expected_duration_seconds = 30, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 64 * 1024 }, .network = .local_network_only, .visibility = .status_only },
    };
    const abusive_tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "heavy", .trigger = .media_export_completion, .expected_duration_seconds = 900, .budget = .{ .cpu_time_ticks = 50_000, .memory_bytes = 8 * 1024 * 1024, .shared_memory_bytes = 256 * 1024 }, .network = .named_domains, .visibility = .status_only },
    };

    const safe_bundle = manifest.BundleManifest{
        .bundle_id = "app.safe",
        .display_name = "Safe",
        .publisher = "zigos.test",
        .requested_permissions = &safe_permissions,
        .background_tasks = &safe_tasks,
    };
    const abusive_bundle = manifest.BundleManifest{
        .bundle_id = "app.safe",
        .display_name = "Safe",
        .publisher = "zigos.test",
        .requested_permissions = &abusive_permissions,
        .background_tasks = &abusive_tasks,
    };

    var controller = Controller.init();
    const first = try controller.dispatch(&runtime, task.id, safe_bundle, "sync", .sync_completion, 20);
    const second = try controller.dispatch(&runtime, task.id, safe_bundle, "sync", .sync_completion, 21);
    const third = try controller.dispatch(&runtime, task.id, safe_bundle, "sync", .sync_completion, 22);
    const heavy = try controller.dispatch(&runtime, task.id, abusive_bundle, "heavy", .media_export_completion, 23);

    try std.testing.expect(first.allowed);
    try std.testing.expect(second.allowed);
    try std.testing.expect(third.delayed);
    try std.testing.expectEqual(DecisionReason.throttled, third.reason);
    try std.testing.expect(!heavy.allowed);
    try std.testing.expectEqual(DecisionReason.budget_exceeded, heavy.reason);

    const no_background_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 302 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = false,
        },
        .local_only = true,
    });
    no_background_task.state = .active;
    const denied = try controller.dispatch(&runtime, no_background_task.id, safe_bundle, "sync", .sync_completion, 24);
    try std.testing.expectEqual(DecisionReason.background_not_allowed, denied.reason);
}

test "background dispatch denies remote work for local-only tasks and user-visible work without a surface" {
    var runtime = task_runtime.Runtime.init();
    const local_only = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 311 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 5_000,
            .memory_bytes = 512 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .bundle_id = "app.safe",
        },
    });
    local_only.state = .active;

    const no_surface = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 312 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 5_000,
            .memory_bytes = 512 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .local_only = false,
        .launch = .{
            .bundle_id = "app.safe",
        },
    });
    no_surface.state = .active;

    const permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "remote", .rights = .{ .task = .{ .background_run = true } } },
        .{ .kind = .background_execution, .resource = "visible", .rights = .{ .task = .{ .background_run = true } } },
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "remote", .trigger = .push_event, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 64 * 1024 }, .network = .named_domains, .visibility = .status_only },
        .{ .id = "visible", .trigger = .device_proximity, .expected_duration_seconds = 10, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = 32 * 1024 }, .network = .none, .visibility = .user_visible },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.safe",
        .display_name = "Safe",
        .publisher = "zigos.test",
        .requested_permissions = &permissions,
        .background_tasks = &tasks,
    };

    var controller = Controller.init();
    const remote_denied = try controller.dispatch(&runtime, local_only.id, bundle, "remote", .push_event, 25);
    try std.testing.expectEqual(DecisionReason.network_denied, remote_denied.reason);

    const visible_denied = try controller.dispatch(&runtime, no_surface.id, bundle, "visible", .device_proximity, 26);
    try std.testing.expectEqual(DecisionReason.visibility_denied, visible_denied.reason);
}

test "background dispatch requires the launched bundle and explicit run rights" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 303 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .bundle_id = "app.safe",
        },
    });
    task.state = .active;

    const safe_permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "sync", .rights = .{ .task = .{ .background_run = true } } },
    };
    const missing_right_permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "sync", .rights = .{ .policy = .{} } },
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "sync", .trigger = .sync_completion, .expected_duration_seconds = 30, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 64 * 1024 }, .network = .local_network_only, .visibility = .status_only },
    };

    const foreign_bundle = manifest.BundleManifest{
        .bundle_id = "app.foreign",
        .display_name = "Foreign",
        .publisher = "zigos.test",
        .requested_permissions = &safe_permissions,
        .background_tasks = &tasks,
    };
    const missing_right_bundle = manifest.BundleManifest{
        .bundle_id = "app.safe",
        .display_name = "Safe",
        .publisher = "zigos.test",
        .requested_permissions = &missing_right_permissions,
        .background_tasks = &tasks,
    };

    var controller = Controller.init();
    const mismatch = try controller.dispatch(&runtime, task.id, foreign_bundle, "sync", .sync_completion, 30);
    try std.testing.expectEqual(DecisionReason.bundle_mismatch, mismatch.reason);

    const missing_right = try controller.dispatch(&runtime, task.id, missing_right_bundle, "sync", .sync_completion, 31);
    try std.testing.expectEqual(DecisionReason.background_permission_missing, missing_right.reason);
}

test "background dispatch reuses completed and denied record slots" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 304 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 20_000,
            .memory_bytes = 2 * 1024 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .bundle_id = "app.safe",
        },
    });
    task.state = .active;

    const permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = "sync", .rights = .{ .task = .{ .background_run = true } } },
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = 64 * 1024 },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.safe",
        .display_name = "Safe",
        .publisher = "zigos.test",
        .requested_permissions = &permissions,
        .background_tasks = &tasks,
    };

    var controller = Controller.init();
    var iteration: usize = 0;
    while (iteration < MAX_RECORDS + 4) : (iteration += 1) {
        const decision = try controller.dispatch(&runtime, task.id, bundle, "sync", .sync_completion, 40 + iteration);
        try std.testing.expect(decision.allowed);
        try std.testing.expect(try controller.complete(&runtime, decision.record_id.?));
    }
    try std.testing.expectEqual(@as(usize, 0), controller.activeRecordCount());
    try std.testing.expectEqual(task.budget.cpu_time_ticks, task.background_cpu_consumed_ticks);
}
