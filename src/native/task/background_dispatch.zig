const std = @import("std");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const policy_object = @import("../policy/policy_object.zig");
const signing = @import("../core/signing.zig");
const units = @import("../core/units.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("task_runtime.zig");

const copyTextExact = native_util.copyTextExact;
const kibibytes = units.kibibytes;
const mebibytes = units.mebibytes;

pub const MAX_RECORDS: usize = 16;
pub const MAX_TASK_ID_BYTES: usize = 48;

pub const RecordState = enum(u8) {
    running,
    delayed,
    denied,
    expired,
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
    policy_denied,
    trigger_mismatch,
    budget_exceeded,
    network_denied,
    visibility_denied,
    throttled,
    expired,
};

pub const DispatchPolicy = struct {
    max_active_jobs: usize = 2,
    max_expected_duration_seconds: u32 = 300,
    max_cpu_time_ticks: u64 = 10_000,
    max_memory_bytes: usize = kibibytes(512),
    max_shared_memory_bytes: usize = kibibytes(64),
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
    reason: DecisionReason = .allowed,
    tick: u64,
    completed_tick: u64 = 0,

    pub fn backgroundTaskIdSlice(self: *const DispatchRecord) []const u8 {
        return self.background_task_id[0..self.background_task_id_len];
    }

    pub fn deadlineTick(self: *const DispatchRecord) u64 {
        return std.math.add(u64, self.tick, @as(u64, self.expected_duration_seconds)) catch std.math.maxInt(u64);
    }

    pub fn isOverdue(self: *const DispatchRecord, now_tick: u64) bool {
        return self.state == .running and now_tick >= self.deadlineTick();
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
    policy_reason: policy_object.DecisionReason = .none,
    blocking_policy_id: u64 = 0,
    blocking_policy_generation: u32 = 0,
};

pub const CompleteRequest = struct {
    record_id: u64,
    expected_task_id: u64,
    expected_background_task_id: []const u8,
    expected_trigger: manifest.BackgroundTrigger,
    tick: u64 = 0,
};

pub const Error = task_runtime.Error || error{
    BackgroundTaskIdTooLong,
    DispatchTableFull,
    DispatchRecordNotFound,
    DispatchRecordBindingMismatch,
};

const RecordSlot = struct {
    in_use: bool = false,
    record: DispatchRecord = zeroRecord(),
};

fn recordSlotId(slot: *const RecordSlot) u64 {
    return slot.record.id;
}

const RecordArena = indexed_arena.IndexedArenaWithKey(u64, RecordSlot, MAX_RECORDS, MAX_RECORDS * 2, recordSlotId);
const ActiveRecordIndex = indexed_arena.MultimapIndex(MAX_RECORDS, 1, 2);
const ReusableRecordIndex = indexed_arena.MultimapIndex(MAX_RECORDS, 1, 2);
const ACTIVE_RECORD_KEY: u64 = 1;
const REUSABLE_RECORD_KEY: u64 = 2;

pub const Controller = struct {
    policy: DispatchPolicy = .{},
    policy_directory: ?*const policy_object.Directory = null,
    policy_subjects: policy_object.SubjectSet = .{},
    next_record_id: u64 = 1,
    active_count: usize = 0,
    latest_record_id: u64 = 0,
    records: RecordArena = RecordArena.init(),
    active_record_index: ActiveRecordIndex = ActiveRecordIndex.init(),
    reusable_record_index: ReusableRecordIndex = ReusableRecordIndex.init(),

    pub fn init() Controller {
        return .{};
    }

    pub fn configure(self: *Controller, policy: DispatchPolicy) void {
        self.policy = policy;
    }

    pub fn configurePolicy(
        self: *Controller,
        directory: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
    ) void {
        self.policy_directory = directory;
        self.policy_subjects = subjects;
    }

    pub fn clearPolicy(self: *Controller) void {
        self.policy_directory = null;
        self.policy_subjects = .{};
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
        if (self.policyDecision(background_task)) |policy_decision| {
            if (!policy_decision.allowed) {
                return self.recordPolicyDecision(task_id, background_task_id, trigger, background_task, policy_decision, tick);
            }
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

    pub fn complete(self: *Controller, runtime: *task_runtime.Runtime, request: CompleteRequest) Error!bool {
        const slot_index = self.findRecordSlotIndex(request.record_id) orelse return error.DispatchRecordNotFound;
        const slot = &self.records.slots[slot_index];
        if (slot.record.state != .running) return false;
        if (slot.record.task_id != request.expected_task_id or
            slot.record.trigger != request.expected_trigger or
            !std.mem.eql(u8, slot.record.backgroundTaskIdSlice(), request.expected_background_task_id))
        {
            return error.DispatchRecordBindingMismatch;
        }
        if (!try runtime.releaseBackgroundWork(slot.record.task_id, slot.record.budget)) {
            return false;
        }
        self.deactivateRunningRecord(slot_index, slot);
        slot.record.state = .completed;
        slot.record.completed_tick = request.tick;
        self.indexReusableRecord(slot_index, slot);
        return true;
    }

    pub fn expireOverdue(self: *Controller, runtime: *task_runtime.Runtime, now_tick: u64) Error!usize {
        var expired_count: usize = 0;
        var slot_index = self.active_record_index.head(ACTIVE_RECORD_KEY);
        while (slot_index != indexed_arena.no_index) {
            const next_slot_index = self.active_record_index.next(slot_index);
            const slot = self.activeRecordSlotAt(slot_index);
            if (!slot.record.isOverdue(now_tick)) {
                slot_index = next_slot_index;
                continue;
            }
            if (!try runtime.releaseBackgroundWork(slot.record.task_id, slot.record.budget)) {
                slot_index = next_slot_index;
                continue;
            }
            self.deactivateRunningRecord(slot_index, slot);
            slot.record.state = .expired;
            slot.record.reason = .expired;
            slot.record.completed_tick = now_tick;
            self.indexReusableRecord(slot_index, slot);
            expired_count += 1;
            try runtime.audit(slot.record.task_id, .{
                .kind = .background_expired,
                .detail = @intFromEnum(slot.record.trigger),
                .tick = now_tick,
            });
            slot_index = next_slot_index;
        }
        return expired_count;
    }

    pub fn activeRecordCount(self: *const Controller) usize {
        return self.active_count;
    }

    pub fn latestRecord(self: *const Controller) ?DispatchRecord {
        if (self.latest_record_id == 0) return null;
        const slot = self.records.getConst(self.latest_record_id) orelse {
            native_util.impossibleByInvariant("background dispatch latest record id points at a live record");
        };
        return slot.record;
    }

    pub fn findRecord(self: *Controller, record_id: u64) ?*DispatchRecord {
        const slot = self.findRecordSlot(record_id) orelse return null;
        return &slot.record;
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

    fn recordPolicyDecision(
        self: *Controller,
        task_id: u64,
        background_task_id: []const u8,
        trigger: manifest.BackgroundTrigger,
        background_task: manifest.BackgroundTaskDecl,
        policy_decision: policy_object.PolicyDecision,
        tick: u64,
    ) Error!DispatchDecision {
        const record = try self.appendRecord(task_id, background_task_id, trigger, background_task, .policy_denied, tick);
        return .{
            .allowed = false,
            .delayed = false,
            .reason = .policy_denied,
            .record_id = record.id,
            .expected_duration_seconds = background_task.expected_duration_seconds,
            .budget = background_task.budget,
            .network = background_task.network,
            .visibility = background_task.visibility,
            .policy_reason = policy_decision.reason,
            .blocking_policy_id = policy_decision.blocking_policy_id,
            .blocking_policy_generation = policy_decision.blocking_generation,
        };
    }

    fn policyDecision(
        self: *const Controller,
        background_task: manifest.BackgroundTaskDecl,
    ) ?policy_object.PolicyDecision {
        const directory = self.policy_directory orelse return null;
        return directory.backgroundActivityDecision(self.policy_subjects, .{
            .expected_duration_seconds = background_task.expected_duration_seconds,
            .cpu_time_ticks = background_task.budget.cpu_time_ticks,
            .memory_bytes = background_task.budget.memory_bytes,
            .shared_memory_bytes = background_task.budget.shared_memory_bytes,
            .network = background_task.network,
            .visibility = background_task.visibility,
        });
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
        const record_id = self.nextReservableRecordId() orelse return error.DispatchTableFull;
        const record = try makeRecord(record_id, task_id, background_task_id, trigger, background_task, reason, tick);
        const slot_index = self.reserveRecordSlot(record_id) orelse return error.DispatchTableFull;
        const slot = &self.records.slots[slot_index];
        slot.record = record;
        if (slot.record.state == .running) {
            self.activateRecord(slot_index, slot);
        } else {
            self.indexReusableRecord(slot_index, slot);
        }
        self.latest_record_id = record_id;
        self.advanceNextRecordIdFrom(record_id);
        return slot.record;
    }

    fn findRecordSlot(self: *Controller, record_id: u64) ?*RecordSlot {
        return self.records.get(record_id);
    }

    fn findRecordSlotIndex(self: *const Controller, record_id: u64) ?usize {
        const slot_index = self.records.slotIndexOf(record_id) orelse return null;
        if (slot_index >= MAX_RECORDS) native_util.impossibleByInvariant("background dispatch record index points outside slots");
        const slot = &self.records.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("background dispatch record index points at free slot");
        if (slot.record.id != record_id) native_util.impossibleByInvariant("background dispatch record index points at wrong record");
        return slot_index;
    }

    fn reserveRecordSlot(self: *Controller, record_id: u64) ?usize {
        if (self.records.reserveIndex(record_id)) |slot_index| return slot_index;
        const slot_index = self.reusableRecordSlotIndex() orelse return null;
        self.unindexReusableRecord(slot_index, &self.records.slots[slot_index]);
        _ = self.records.removeIndex(slot_index);
        return self.records.reserveIndexAt(record_id, slot_index);
    }

    fn reusableRecordSlotIndex(self: *const Controller) ?usize {
        const slot_index = self.reusable_record_index.head(REUSABLE_RECORD_KEY);
        if (slot_index == indexed_arena.no_index) return null;
        if (slot_index >= MAX_RECORDS) native_util.impossibleByInvariant("background dispatch reusable-record index points outside slots");
        const slot = &self.records.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("background dispatch reusable-record index points at free slot");
        if (slot.record.state == .running) native_util.impossibleByInvariant("background dispatch reusable-record index points at running record");
        return slot_index;
    }

    fn activateRecord(self: *Controller, slot_index: usize, slot: *const RecordSlot) void {
        if (!slot.in_use or slot.record.state != .running) {
            native_util.impossibleByInvariant("background dispatch only indexes running records as active");
        }
        if (!self.active_record_index.append(ACTIVE_RECORD_KEY, slot_index)) {
            native_util.impossibleByInvariant("background dispatch active-record index covers record slots");
        }
        self.active_count += 1;
    }

    fn deactivateRunningRecord(self: *Controller, slot_index: usize, slot: *const RecordSlot) void {
        if (!slot.in_use or slot.record.state != .running) {
            native_util.impossibleByInvariant("background dispatch active-record index points at running records");
        }
        if (!self.active_record_index.remove(ACTIVE_RECORD_KEY, slot_index)) {
            native_util.impossibleByInvariant("background dispatch active-record index missing running record");
        }
        self.decrementActiveRecordCount();
    }

    fn indexReusableRecord(self: *Controller, slot_index: usize, slot: *const RecordSlot) void {
        if (!slot.in_use or slot.record.state == .running) {
            native_util.impossibleByInvariant("background dispatch only indexes inactive records as reusable");
        }
        if (!self.reusable_record_index.append(REUSABLE_RECORD_KEY, slot_index)) {
            native_util.impossibleByInvariant("background dispatch reusable-record index covers record slots");
        }
    }

    fn unindexReusableRecord(self: *Controller, slot_index: usize, slot: *const RecordSlot) void {
        if (!slot.in_use or slot.record.state == .running) {
            native_util.impossibleByInvariant("background dispatch reusable-record index points at inactive records");
        }
        if (!self.reusable_record_index.remove(REUSABLE_RECORD_KEY, slot_index)) {
            native_util.impossibleByInvariant("background dispatch reusable-record index missing inactive record");
        }
    }

    fn activeRecordSlotAt(self: *Controller, slot_index: usize) *RecordSlot {
        if (slot_index >= MAX_RECORDS) native_util.impossibleByInvariant("background dispatch active-record index points outside slots");
        const slot = &self.records.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("background dispatch active-record index points at free slot");
        if (slot.record.state != .running) native_util.impossibleByInvariant("background dispatch active-record index points at inactive record");
        return slot;
    }

    fn decrementActiveRecordCount(self: *Controller) void {
        if (self.active_count == 0) native_util.impossibleByInvariant("background dispatch active record count underflow");
        self.active_count -= 1;
    }

    fn nextReservableRecordId(self: *Controller) ?u64 {
        if (!self.hasReusableRecordSlot()) return null;

        var record_id = normalizeRecordId(self.next_record_id);
        var attempts: usize = 0;
        while (attempts <= MAX_RECORDS) : (attempts += 1) {
            if (self.findActiveRecord(record_id) == null) return record_id;
            record_id = nextRecordIdAfter(record_id);
        }
        return null;
    }

    fn advanceNextRecordIdFrom(self: *Controller, record_id: u64) void {
        self.next_record_id = nextRecordIdAfter(record_id);
    }

    fn hasReusableRecordSlot(self: *const Controller) bool {
        return self.records.countInUse() < MAX_RECORDS or self.reusableRecordSlotIndex() != null;
    }

    fn findActiveRecord(self: *Controller, record_id: u64) ?*DispatchRecord {
        const slot = self.records.get(record_id) orelse return null;
        if (slot.record.state != .running) return null;
        return &slot.record;
    }
};

fn normalizeRecordId(record_id: u64) u64 {
    return if (record_id == 0) 1 else record_id;
}

fn nextRecordIdAfter(record_id: u64) u64 {
    const next = record_id +% 1;
    return normalizeRecordId(next);
}

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
        .reason = .allowed,
        .tick = 0,
    };
}

fn makeRecord(
    record_id: u64,
    task_id: u64,
    background_task_id: []const u8,
    trigger: manifest.BackgroundTrigger,
    background_task: ?manifest.BackgroundTaskDecl,
    reason: DecisionReason,
    tick: u64,
) Error!DispatchRecord {
    var record = zeroRecord();
    record.id = record_id;
    record.task_id = task_id;
    record.background_task_id_len = copyTextExact(&record.background_task_id, background_task_id) catch return error.BackgroundTaskIdTooLong;
    record.trigger = trigger;
    record.state = switch (reason) {
        .allowed => .running,
        .throttled => .delayed,
        .expired => .expired,
        else => .denied,
    };
    record.reason = reason;
    record.tick = tick;
    if (background_task) |task| {
        record.expected_duration_seconds = task.expected_duration_seconds;
        record.budget = task.budget;
        record.network = task.network;
        record.visibility = task.visibility;
    }
    return record;
}

const TEST_APP_MEMORY_BYTES: usize = mebibytes(2);
const TEST_APP_SHARED_MEMORY_BYTES: usize = kibibytes(64);
const TEST_SMALL_APP_MEMORY_BYTES: usize = kibibytes(512);
const TEST_SYNC_BACKGROUND_MEMORY_BYTES: usize = kibibytes(64);
const TEST_SAFE_BUNDLE_ID = "app.safe";
const TEST_SYNC_BACKGROUND_ID = "sync";

const TestTaskSpec = struct {
    serial: u64,
    bundle_id: []const u8 = TEST_SAFE_BUNDLE_ID,
    cpu_time_ticks: u64 = 20_000,
    memory_bytes: usize = TEST_APP_MEMORY_BYTES,
    shared_memory_bytes: usize = TEST_APP_SHARED_MEMORY_BYTES,
    ui_surface_id: ?u64 = null,
    local_only: bool = false,
    background_allowed: bool = true,
};

fn createActiveTestTask(runtime: *task_runtime.Runtime, spec: TestTaskSpec) !*task_runtime.TaskRecord {
    return runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = spec.serial },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = spec.cpu_time_ticks,
            .memory_bytes = spec.memory_bytes,
            .endpoint_slots = 4,
            .shared_memory_bytes = spec.shared_memory_bytes,
            .background_allowed = spec.background_allowed,
        },
        .ui_surface_id = spec.ui_surface_id,
        .local_only = spec.local_only,
        .launch = .{
            .bundle_id = spec.bundle_id,
        },
    });
}

fn backgroundRunPermission(resource: []const u8) manifest.PermissionRequest {
    return .{
        .kind = .background_execution,
        .resource = resource,
        .rights = .{ .task = .{ .background_run = true } },
    };
}

fn syncBackgroundTask() manifest.BackgroundTaskDecl {
    return .{
        .id = TEST_SYNC_BACKGROUND_ID,
        .trigger = .sync_completion,
        .expected_duration_seconds = 30,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = TEST_SYNC_BACKGROUND_MEMORY_BYTES,
        },
        .network = .local_network_only,
        .visibility = .status_only,
    };
}

fn testBundle(
    bundle_id: []const u8,
    display_name: []const u8,
    permissions: []const manifest.PermissionRequest,
    background_tasks: []const manifest.BackgroundTaskDecl,
) manifest.BundleManifest {
    return .{
        .bundle_id = bundle_id,
        .display_name = display_name,
        .publisher = "zigos.test",
        .requested_permissions = permissions,
        .background_tasks = background_tasks,
    };
}

test "background dispatch accepts declared triggers and preserves task metadata" {
    var runtime = task_runtime.Runtime.init();
    const task = try createActiveTestTask(&runtime, .{
        .serial = 300,
        .bundle_id = "app.background",
        .ui_surface_id = 9,
        .local_only = false,
    });

    const permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission("schedule"),
        backgroundRunPermission("push"),
        backgroundRunPermission("change"),
        backgroundRunPermission("proximity"),
        backgroundRunPermission("sensor"),
        backgroundRunPermission(TEST_SYNC_BACKGROUND_ID),
        backgroundRunPermission("media"),
        backgroundRunPermission("policy"),
    };
    const background_tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "schedule", .trigger = .user_approved_scheduled_job, .expected_duration_seconds = 30, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = TEST_SYNC_BACKGROUND_MEMORY_BYTES }, .network = .none, .visibility = .status_only },
        .{ .id = "push", .trigger = .push_event, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 800, .memory_bytes = kibibytes(32) }, .network = .named_service_identities, .visibility = .hidden },
        .{ .id = "change", .trigger = .local_object_change, .expected_duration_seconds = 15, .budget = .{ .cpu_time_ticks = 900, .memory_bytes = kibibytes(16) }, .network = .none, .visibility = .audit_only },
        .{ .id = "proximity", .trigger = .device_proximity, .expected_duration_seconds = 10, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = kibibytes(16) }, .network = .none, .visibility = .user_visible },
        .{ .id = "sensor", .trigger = .sensor_rule, .expected_duration_seconds = 25, .budget = .{ .cpu_time_ticks = 700, .memory_bytes = kibibytes(24) }, .network = .none, .visibility = .status_only },
        .{ .id = TEST_SYNC_BACKGROUND_ID, .trigger = .sync_completion, .expected_duration_seconds = 40, .budget = .{ .cpu_time_ticks = 1_200, .memory_bytes = kibibytes(96) }, .network = .local_network_only, .visibility = .status_only },
        .{ .id = "media", .trigger = .media_export_completion, .expected_duration_seconds = 35, .budget = .{ .cpu_time_ticks = 1_100, .memory_bytes = kibibytes(48) }, .network = .named_domains, .visibility = .status_only },
        .{ .id = "policy", .trigger = .organization_policy_task, .expected_duration_seconds = 45, .budget = .{ .cpu_time_ticks = 1_300, .memory_bytes = kibibytes(80) }, .network = .none, .visibility = .audit_only },
    };
    const bundle = testBundle("app.background", "Background", &permissions, &background_tasks);

    var controller = Controller.init();
    for (background_tasks) |background_task| {
        const decision = try controller.dispatch(&runtime, task.id, bundle, background_task.id, background_task.trigger, 10);
        try std.testing.expect(decision.allowed);
        try std.testing.expect(!decision.delayed);
        try std.testing.expectEqual(background_task.expected_duration_seconds, decision.expected_duration_seconds);
        try std.testing.expectEqual(background_task.network, decision.network);
        try std.testing.expectEqual(background_task.visibility, decision.visibility);
        try std.testing.expectEqual(background_task.budget.cpu_time_ticks, decision.budget.cpu_time_ticks);
        try std.testing.expect(try controller.complete(&runtime, .{
            .record_id = decision.record_id.?,
            .expected_task_id = task.id,
            .expected_background_task_id = background_task.id,
            .expected_trigger = background_task.trigger,
            .tick = 11 + decision.record_id.?,
        }));
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
    const task = try createActiveTestTask(&runtime, .{ .serial = 301, .local_only = false });

    const safe_permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission(TEST_SYNC_BACKGROUND_ID),
    };
    const abusive_permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission("heavy"),
    };
    const safe_tasks = [_]manifest.BackgroundTaskDecl{
        syncBackgroundTask(),
    };
    const abusive_tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "heavy", .trigger = .media_export_completion, .expected_duration_seconds = 900, .budget = .{ .cpu_time_ticks = 50_000, .memory_bytes = mebibytes(8), .shared_memory_bytes = kibibytes(256) }, .network = .named_domains, .visibility = .status_only },
    };

    const safe_bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &safe_permissions, &safe_tasks);
    const abusive_bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &abusive_permissions, &abusive_tasks);

    var controller = Controller.init();
    const first = try controller.dispatch(&runtime, task.id, safe_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 20);
    const second = try controller.dispatch(&runtime, task.id, safe_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 21);
    const third = try controller.dispatch(&runtime, task.id, safe_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 22);
    const heavy = try controller.dispatch(&runtime, task.id, abusive_bundle, "heavy", .media_export_completion, 23);

    try std.testing.expect(first.allowed);
    try std.testing.expect(second.allowed);
    try std.testing.expectEqual(@as(usize, 2), controller.active_record_index.count(ACTIVE_RECORD_KEY));
    try std.testing.expect(third.delayed);
    try std.testing.expectEqual(DecisionReason.throttled, third.reason);
    try std.testing.expect(!heavy.allowed);
    try std.testing.expectEqual(DecisionReason.budget_exceeded, heavy.reason);
    try std.testing.expectEqual(@as(usize, 2), controller.reusable_record_index.count(REUSABLE_RECORD_KEY));
    try std.testing.expectError(error.DispatchRecordBindingMismatch, controller.complete(&runtime, .{
        .record_id = first.record_id.?,
        .expected_task_id = task.id + 1,
        .expected_background_task_id = TEST_SYNC_BACKGROUND_ID,
        .expected_trigger = .sync_completion,
        .tick = 24,
    }));
    try std.testing.expectEqual(@as(u16, 2), task.background_active_count);

    const no_background_task = try createActiveTestTask(&runtime, .{
        .serial = 302,
        .local_only = true,
        .background_allowed = false,
    });
    const denied = try controller.dispatch(&runtime, no_background_task.id, safe_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 24);
    try std.testing.expectEqual(DecisionReason.background_not_allowed, denied.reason);
    try std.testing.expectEqual(@as(usize, 3), controller.reusable_record_index.count(REUSABLE_RECORD_KEY));
}

test "background dispatch denies remote work for local-only tasks and user-visible work without a surface" {
    var runtime = task_runtime.Runtime.init();
    const local_only = try createActiveTestTask(&runtime, .{
        .serial = 311,
        .cpu_time_ticks = 5_000,
        .memory_bytes = TEST_SMALL_APP_MEMORY_BYTES,
        .local_only = true,
    });

    const no_surface = try createActiveTestTask(&runtime, .{
        .serial = 312,
        .cpu_time_ticks = 5_000,
        .memory_bytes = TEST_SMALL_APP_MEMORY_BYTES,
        .local_only = false,
    });

    const permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission("remote"),
        backgroundRunPermission("visible"),
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "remote", .trigger = .push_event, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 1_000, .memory_bytes = TEST_SYNC_BACKGROUND_MEMORY_BYTES }, .network = .named_domains, .visibility = .status_only },
        .{ .id = "visible", .trigger = .device_proximity, .expected_duration_seconds = 10, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = kibibytes(32) }, .network = .none, .visibility = .user_visible },
    };
    const bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &permissions, &tasks);

    var controller = Controller.init();
    const remote_denied = try controller.dispatch(&runtime, local_only.id, bundle, "remote", .push_event, 25);
    try std.testing.expectEqual(DecisionReason.network_denied, remote_denied.reason);

    const visible_denied = try controller.dispatch(&runtime, no_surface.id, bundle, "visible", .device_proximity, 26);
    try std.testing.expectEqual(DecisionReason.visibility_denied, visible_denied.reason);
}

test "background dispatch enforces signed background activity policy before reserving work" {
    var runtime = task_runtime.Runtime.init();
    const task = try createActiveTestTask(&runtime, .{
        .serial = 313,
        .bundle_id = "app.policy-background",
        .cpu_time_ticks = 5_000,
        .memory_bytes = TEST_SMALL_APP_MEMORY_BYTES,
        .local_only = false,
    });

    var policies = policy_object.Directory.init();
    const policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 313,
        .issuer = .{ .kind = .policy_authority, .serial = 313 },
        .label = "background-activity-policy",
        .max_background_duration_seconds = 30,
        .max_background_cpu_time_ticks = 1_000,
        .max_background_memory_bytes = TEST_SYNC_BACKGROUND_MEMORY_BYTES,
        .max_background_shared_memory_bytes = kibibytes(8),
        .allow_remote_background_network = false,
        .require_visible_background_activity = true,
    }, .{
        .label = "background-policy-key",
        .seed = signing.seedFromByte(0xD1),
    });

    const permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission("safe"),
        backgroundRunPermission("remote"),
        backgroundRunPermission("hidden"),
        backgroundRunPermission("slow"),
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        .{ .id = "safe", .trigger = .sync_completion, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = kibibytes(32), .shared_memory_bytes = kibibytes(4) }, .network = .local_network_only, .visibility = .status_only },
        .{ .id = "remote", .trigger = .push_event, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = kibibytes(32), .shared_memory_bytes = kibibytes(4) }, .network = .named_domains, .visibility = .status_only },
        .{ .id = "hidden", .trigger = .local_object_change, .expected_duration_seconds = 20, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = kibibytes(32), .shared_memory_bytes = kibibytes(4) }, .network = .none, .visibility = .hidden },
        .{ .id = "slow", .trigger = .media_export_completion, .expected_duration_seconds = 31, .budget = .{ .cpu_time_ticks = 500, .memory_bytes = kibibytes(32), .shared_memory_bytes = kibibytes(4) }, .network = .none, .visibility = .status_only },
    };
    const bundle = testBundle("app.policy-background", "Policy Background", &permissions, &tasks);

    var controller = Controller.init();
    controller.configurePolicy(&policies, .{ .organization_id = 313 });

    const safe = try controller.dispatch(&runtime, task.id, bundle, "safe", .sync_completion, 27);
    try std.testing.expect(safe.allowed);
    try std.testing.expect(try controller.complete(&runtime, .{
        .record_id = safe.record_id.?,
        .expected_task_id = task.id,
        .expected_background_task_id = "safe",
        .expected_trigger = .sync_completion,
        .tick = 42,
    }));

    const remote = try controller.dispatch(&runtime, task.id, bundle, "remote", .push_event, 28);
    try std.testing.expectEqual(DecisionReason.policy_denied, remote.reason);
    try std.testing.expectEqual(policy_object.DecisionReason.background_network_denied, remote.policy_reason);
    try std.testing.expectEqual(policy.id, remote.blocking_policy_id);
    try std.testing.expectEqual(policy.generation, remote.blocking_policy_generation);

    const hidden = try controller.dispatch(&runtime, task.id, bundle, "hidden", .local_object_change, 29);
    try std.testing.expectEqual(DecisionReason.policy_denied, hidden.reason);
    try std.testing.expectEqual(policy_object.DecisionReason.background_visibility_denied, hidden.policy_reason);

    const slow = try controller.dispatch(&runtime, task.id, bundle, "slow", .media_export_completion, 30);
    try std.testing.expectEqual(DecisionReason.policy_denied, slow.reason);
    try std.testing.expectEqual(policy_object.DecisionReason.background_duration_denied, slow.policy_reason);

    try std.testing.expectEqual(@as(u16, 0), task.background_active_count);
}

test "background dispatch requires the launched bundle and explicit run rights" {
    var runtime = task_runtime.Runtime.init();
    const task = try createActiveTestTask(&runtime, .{ .serial = 303, .local_only = true });

    const safe_permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission(TEST_SYNC_BACKGROUND_ID),
    };
    const missing_right_permissions = [_]manifest.PermissionRequest{
        .{ .kind = .background_execution, .resource = TEST_SYNC_BACKGROUND_ID, .rights = .{ .policy = .{} } },
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        syncBackgroundTask(),
    };

    const foreign_bundle = testBundle("app.foreign", "Foreign", &safe_permissions, &tasks);
    const missing_right_bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &missing_right_permissions, &tasks);

    var controller = Controller.init();
    const mismatch = try controller.dispatch(&runtime, task.id, foreign_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 30);
    try std.testing.expectEqual(DecisionReason.bundle_mismatch, mismatch.reason);

    const missing_right = try controller.dispatch(&runtime, task.id, missing_right_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 31);
    try std.testing.expectEqual(DecisionReason.background_permission_missing, missing_right.reason);
}

test "background dispatch rejects overlong task ids without publishing records" {
    var runtime = task_runtime.Runtime.init();
    var controller = Controller.init();
    const oversized_id = [_]u8{'b'} ** (MAX_TASK_ID_BYTES + 1);
    const empty_bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &.{}, &.{});

    try std.testing.expectError(error.BackgroundTaskIdTooLong, controller.dispatch(
        &runtime,
        404,
        empty_bundle,
        oversized_id[0..],
        .sync_completion,
        32,
    ));
    try std.testing.expectEqual(@as(u64, 1), controller.next_record_id);
    try std.testing.expectEqual(@as(usize, 0), controller.activeRecordCount());
    try std.testing.expectEqual(@as(usize, 0), controller.records.countInUse());

    const missing = try controller.dispatch(&runtime, 404, empty_bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 33);
    try std.testing.expectEqual(DecisionReason.task_not_found, missing.reason);
    try std.testing.expectEqual(@as(u64, 1), missing.record_id.?);
}

test "background dispatch reuses completed and denied record slots" {
    var runtime = task_runtime.Runtime.init();
    const task = try createActiveTestTask(&runtime, .{ .serial = 304, .local_only = true });

    const permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission(TEST_SYNC_BACKGROUND_ID),
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        syncBackgroundTask(),
    };
    const bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &permissions, &tasks);

    var controller = Controller.init();
    var iteration: usize = 0;
    while (iteration < MAX_RECORDS + 4) : (iteration += 1) {
        const decision = try controller.dispatch(&runtime, task.id, bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 40 + iteration);
        try std.testing.expect(decision.allowed);
        try std.testing.expectEqual(@as(usize, 1), controller.active_record_index.count(ACTIVE_RECORD_KEY));
        try std.testing.expectEqual(@min(iteration, MAX_RECORDS - 1), controller.reusable_record_index.count(REUSABLE_RECORD_KEY));
        try std.testing.expect(try controller.complete(&runtime, .{
            .record_id = decision.record_id.?,
            .expected_task_id = task.id,
            .expected_background_task_id = TEST_SYNC_BACKGROUND_ID,
            .expected_trigger = .sync_completion,
            .tick = 50 + iteration,
        }));
        try std.testing.expectEqual(@as(usize, 0), controller.active_record_index.count(ACTIVE_RECORD_KEY));
        try std.testing.expectEqual(@min(iteration + 1, MAX_RECORDS), controller.reusable_record_index.count(REUSABLE_RECORD_KEY));
        try std.testing.expectEqual(RecordState.completed, controller.findRecord(decision.record_id.?).?.state);
        try std.testing.expectEqual(decision.record_id.?, controller.latestRecord().?.id);
    }
    try std.testing.expectEqual(@as(usize, MAX_RECORDS), controller.records.countInUse());
    try std.testing.expectEqual(@as(usize, 0), controller.activeRecordCount());
    try std.testing.expectEqual(task.budget.cpu_time_ticks, task.background_cpu_consumed_ticks);
}

test "background dispatch record ids wrap without zero and skip active records" {
    var runtime = task_runtime.Runtime.init();
    const task = try createActiveTestTask(&runtime, .{ .serial = 306, .local_only = true });

    const permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission(TEST_SYNC_BACKGROUND_ID),
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        syncBackgroundTask(),
    };
    const bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &permissions, &tasks);

    var controller = Controller.init();
    controller.next_record_id = std.math.maxInt(u64);
    const max = try controller.dispatch(&runtime, task.id, bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 60);
    try std.testing.expectEqual(std.math.maxInt(u64), max.record_id.?);
    try std.testing.expectEqual(@as(u64, 1), controller.next_record_id);
    try std.testing.expect(controller.findActiveRecord(0) == null);

    const wrapped = try controller.dispatch(&runtime, task.id, bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 61);
    try std.testing.expectEqual(@as(u64, 1), wrapped.record_id.?);
    try std.testing.expectEqual(@as(u64, 2), controller.next_record_id);
    try std.testing.expect(controller.findActiveRecord(0) == null);

    controller.next_record_id = 1;
    const skipped = try controller.dispatch(&runtime, task.id, bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 62);
    try std.testing.expectEqual(@as(u64, 2), skipped.record_id.?);
    try std.testing.expectEqual(@as(u64, 3), controller.next_record_id);
    try std.testing.expect(controller.findActiveRecord(0) == null);

    var full_controller = Controller.init();
    var full_runtime = task_runtime.Runtime.init();
    const full_task = try createActiveTestTask(&full_runtime, .{
        .serial = 307,
        .local_only = true,
        .memory_bytes = mebibytes(64),
    });
    full_controller.configure(.{ .max_active_jobs = MAX_RECORDS });
    for (0..MAX_RECORDS) |index| {
        const decision = try full_controller.dispatch(&full_runtime, full_task.id, bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 70 + index);
        try std.testing.expect(decision.allowed);
    }
    const next_before_full = full_controller.next_record_id;
    try std.testing.expectError(error.DispatchTableFull, full_controller.dispatch(
        &full_runtime,
        full_task.id,
        bundle,
        TEST_SYNC_BACKGROUND_ID,
        .sync_completion,
        90,
    ));
    try std.testing.expectEqual(next_before_full, full_controller.next_record_id);
    try std.testing.expectEqual(MAX_RECORDS, full_controller.activeRecordCount());
}

test "background dispatch expires overdue work and releases reservations" {
    var runtime = task_runtime.Runtime.init();
    const task = try createActiveTestTask(&runtime, .{
        .serial = 305,
        .local_only = false,
    });

    const permissions = [_]manifest.PermissionRequest{
        backgroundRunPermission(TEST_SYNC_BACKGROUND_ID),
    };
    const tasks = [_]manifest.BackgroundTaskDecl{
        syncBackgroundTask(),
    };
    const bundle = testBundle(TEST_SAFE_BUNDLE_ID, "Safe", &permissions, &tasks);

    var controller = Controller.init();
    const decision = try controller.dispatch(&runtime, task.id, bundle, TEST_SYNC_BACKGROUND_ID, .sync_completion, 100);
    try std.testing.expect(decision.allowed);
    try std.testing.expectEqual(@as(u16, 1), task.background_active_count);
    try std.testing.expectEqual(TEST_SYNC_BACKGROUND_MEMORY_BYTES, task.background_reserved_memory_bytes);
    try std.testing.expectEqual(@as(usize, 1), controller.active_record_index.count(ACTIVE_RECORD_KEY));
    try std.testing.expectEqual(@as(usize, 0), controller.reusable_record_index.count(REUSABLE_RECORD_KEY));
    try std.testing.expectEqual(decision.record_id.?, controller.latest_record_id);

    try std.testing.expectEqual(@as(usize, 0), try controller.expireOverdue(&runtime, 129));
    try std.testing.expectEqual(@as(u16, 1), task.background_active_count);
    try std.testing.expectEqual(@as(usize, 1), controller.active_record_index.count(ACTIVE_RECORD_KEY));

    try std.testing.expectEqual(@as(usize, 1), try controller.expireOverdue(&runtime, 130));
    try std.testing.expectEqual(@as(usize, 0), controller.activeRecordCount());
    try std.testing.expectEqual(@as(usize, 0), controller.active_record_index.count(ACTIVE_RECORD_KEY));
    try std.testing.expectEqual(@as(usize, 1), controller.reusable_record_index.count(REUSABLE_RECORD_KEY));
    try std.testing.expectEqual(@as(u16, 0), task.background_active_count);
    try std.testing.expectEqual(@as(usize, 0), task.background_reserved_memory_bytes);
    try std.testing.expectEqual(task_runtime.AuditEventKind.background_expired, task.latestAuditEvent().?.kind);

    const latest = controller.latestRecord().?;
    try std.testing.expectEqual(RecordState.expired, latest.state);
    try std.testing.expectEqual(DecisionReason.expired, latest.reason);
    try std.testing.expectEqual(@as(u64, 130), latest.completed_tick);
    try std.testing.expect(!try controller.complete(&runtime, .{
        .record_id = decision.record_id.?,
        .expected_task_id = task.id,
        .expected_background_task_id = TEST_SYNC_BACKGROUND_ID,
        .expected_trigger = .sync_completion,
        .tick = 131,
    }));
}
