const std = @import("std");
const principal = @import("principal.zig");

pub const MAX_TASKS: usize = 32;
pub const MAX_TASK_CAPABILITIES: usize = 24;
pub const MAX_TASK_COMPONENTS: usize = 8;
pub const MAX_AUDIT_EVENTS: usize = 16;

pub const TaskState = enum(u8) {
    staged,
    active,
    suspended,
    terminated,
};

pub const ComponentClass = enum(u8) {
    session_manager,
    app_component,
    service_component,
};

pub const ExecutionSubstrate = enum(u8) {
    typed_component_abi,
    early_elf_runner,
};

pub const ExecutionComponentSpec = struct {
    substrate: ExecutionSubstrate = .typed_component_abi,
    label: []const u8 = "",
    entry: []const u8 = "",
};

pub const ExecutionComponentRecord = struct {
    id: u64,
    substrate: ExecutionSubstrate,
    label_len: usize,
    label: [48]u8,
    entry_len: usize,
    entry: [64]u8,

    pub fn labelSlice(self: *const ExecutionComponentRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn entrySlice(self: *const ExecutionComponentRecord) []const u8 {
        return self.entry[0..self.entry_len];
    }
};

pub const ResourceBudget = struct {
    cpu_time_ticks: u64,
    memory_bytes: usize,
    endpoint_slots: u16,
    shared_memory_bytes: usize,
    background_allowed: bool = false,
};

pub const AuditEventKind = enum(u8) {
    created,
    terminated,
    capability_granted,
    capability_revoked,
    component_attached,
    permission_prompted,
    permission_reviewed,
    policy_allowed,
    policy_denied,
    service_connected,
    service_restarted,
};

pub const AuditEvent = struct {
    kind: AuditEventKind,
    capability_id: u64 = 0,
    detail: u32 = 0,
    tick: u64 = 0,
};

pub const TaskCreateRequest = struct {
    owner: principal.PrincipalId,
    component_class: ComponentClass,
    budget: ResourceBudget,
    ui_surface_id: ?u64 = null,
    local_only: bool = false,
    initial_component: ExecutionComponentSpec = .{},
};

pub const TaskRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    state: TaskState,
    component_class: ComponentClass,
    execution_components: [MAX_TASK_COMPONENTS]ExecutionComponentRecord,
    execution_component_count: usize,
    capability_ids: [MAX_TASK_CAPABILITIES]u64,
    capability_count: usize,
    budget: ResourceBudget,
    audit_trail: [MAX_AUDIT_EVENTS]AuditEvent,
    audit_count: usize,
    ui_surface_id: ?u64,
    background_allowed: bool,
    zero_ambient_authority: bool,
    local_only: bool,
};

pub const Error = error{
    ComponentTableFull,
    CapabilityTableFull,
    TaskNotFound,
    TaskTableFull,
};

const TaskSlot = struct {
    in_use: bool = false,
    task: TaskRecord = zeroTask(),
};

pub const Runtime = struct {
    next_task_id: u64 = 1,
    next_component_id: u64 = 1,
    tasks: [MAX_TASKS]TaskSlot = [_]TaskSlot{TaskSlot{}} ** MAX_TASKS,

    pub fn init() Runtime {
        return Runtime{};
    }

    pub fn createTask(self: *Runtime, request: TaskCreateRequest) Error!*TaskRecord {
        for (&self.tasks) |*slot| {
            if (slot.in_use) continue;
            const task_id = self.next_task_id;
            self.next_task_id += 1;
            const initial_component = makeExecutionComponent(self, defaultInitialComponent(request));

            slot.in_use = true;
            slot.task = .{
                .id = task_id,
                .owner = request.owner,
                .state = .active,
                .component_class = request.component_class,
                .execution_components = [_]ExecutionComponentRecord{zeroExecutionComponent()} ** MAX_TASK_COMPONENTS,
                .execution_component_count = 1,
                .capability_ids = [_]u64{0} ** MAX_TASK_CAPABILITIES,
                .capability_count = 0,
                .budget = request.budget,
                .audit_trail = [_]AuditEvent{AuditEvent{ .kind = .created }} ** MAX_AUDIT_EVENTS,
                .audit_count = 0,
                .ui_surface_id = request.ui_surface_id,
                .background_allowed = request.budget.background_allowed,
                .zero_ambient_authority = true,
                .local_only = request.local_only,
            };
            slot.task.execution_components[0] = initial_component;
            return &slot.task;
        }
        return error.TaskTableFull;
    }

    pub fn find(self: *Runtime, task_id: u64) ?*TaskRecord {
        for (&self.tasks) |*slot| {
            if (slot.in_use and slot.task.id == task_id) return &slot.task;
        }
        return null;
    }

    pub fn grantCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.capability_count >= MAX_TASK_CAPABILITIES) return error.CapabilityTableFull;
        task.capability_ids[task.capability_count] = capability_id;
        task.capability_count += 1;
    }

    pub fn attachComponent(
        self: *Runtime,
        task_id: u64,
        component: ExecutionComponentSpec,
        tick: u64,
    ) Error!ExecutionComponentRecord {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.execution_component_count >= MAX_TASK_COMPONENTS) return error.ComponentTableFull;

        const record = makeExecutionComponent(self, component);
        task.execution_components[task.execution_component_count] = record;
        task.execution_component_count += 1;
        try self.audit(task_id, .{
            .kind = .component_attached,
            .detail = @intFromEnum(record.substrate),
            .tick = tick,
        });
        return record;
    }

    pub fn revokeCapability(self: *Runtime, task_id: u64, capability_id: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        var index: usize = 0;
        while (index < task.capability_count) : (index += 1) {
            if (task.capability_ids[index] != capability_id) continue;

            var tail = index;
            while (tail + 1 < task.capability_count) : (tail += 1) {
                task.capability_ids[tail] = task.capability_ids[tail + 1];
            }
            task.capability_count -= 1;
            task.capability_ids[task.capability_count] = 0;
            return true;
        }
        return false;
    }

    pub fn audit(self: *Runtime, task_id: u64, event: AuditEvent) Error!void {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.audit_count < MAX_AUDIT_EVENTS) {
            task.audit_trail[task.audit_count] = event;
            task.audit_count += 1;
            return;
        }

        var index: usize = 1;
        while (index < MAX_AUDIT_EVENTS) : (index += 1) {
            task.audit_trail[index - 1] = task.audit_trail[index];
        }
        task.audit_trail[MAX_AUDIT_EVENTS - 1] = event;
    }

    pub fn terminateTask(self: *Runtime, task_id: u64, tick: u64) Error!bool {
        const task = self.find(task_id) orelse return error.TaskNotFound;
        if (task.state == .terminated) return false;

        task.state = .terminated;
        task.execution_components = [_]ExecutionComponentRecord{zeroExecutionComponent()} ** MAX_TASK_COMPONENTS;
        task.execution_component_count = 0;
        task.capability_ids = [_]u64{0} ** MAX_TASK_CAPABILITIES;
        task.capability_count = 0;
        try self.audit(task_id, .{
            .kind = .terminated,
            .tick = tick,
        });
        return true;
    }
};

fn zeroTask() TaskRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .state = .staged,
        .component_class = .service_component,
        .execution_components = [_]ExecutionComponentRecord{zeroExecutionComponent()} ** MAX_TASK_COMPONENTS,
        .execution_component_count = 0,
        .capability_ids = [_]u64{0} ** MAX_TASK_CAPABILITIES,
        .capability_count = 0,
        .budget = .{
            .cpu_time_ticks = 0,
            .memory_bytes = 0,
            .endpoint_slots = 0,
            .shared_memory_bytes = 0,
            .background_allowed = false,
        },
        .audit_trail = [_]AuditEvent{AuditEvent{ .kind = .created }} ** MAX_AUDIT_EVENTS,
        .audit_count = 0,
        .ui_surface_id = null,
        .background_allowed = false,
        .zero_ambient_authority = true,
        .local_only = false,
    };
}

fn zeroExecutionComponent() ExecutionComponentRecord {
    return .{
        .id = 0,
        .substrate = .typed_component_abi,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .entry_len = 0,
        .entry = [_]u8{0} ** 64,
    };
}

fn componentClassLabel(component_class: ComponentClass) []const u8 {
    return switch (component_class) {
        .session_manager => "session-manager",
        .app_component => "app-component",
        .service_component => "service-component",
    };
}

fn componentClassEntry(component_class: ComponentClass) []const u8 {
    return switch (component_class) {
        .session_manager => "zigos.session.manager",
        .app_component => "zigos.app.component",
        .service_component => "zigos.service.component",
    };
}

fn defaultInitialComponent(request: TaskCreateRequest) ExecutionComponentSpec {
    var component = request.initial_component;
    if (component.label.len == 0) {
        component.label = componentClassLabel(request.component_class);
    }
    if (component.entry.len == 0) {
        component.entry = componentClassEntry(request.component_class);
    }
    return component;
}

fn copyTruncated(buffer: []u8, source: []const u8) usize {
    const len = @min(buffer.len - 1, source.len);
    @memcpy(buffer[0..len], source[0..len]);
    return len;
}

fn makeExecutionComponent(self: *Runtime, component: ExecutionComponentSpec) ExecutionComponentRecord {
    var record = zeroExecutionComponent();
    record.id = self.next_component_id;
    self.next_component_id += 1;
    record.substrate = component.substrate;
    record.label_len = copyTruncated(record.label[0..], component.label);
    record.entry_len = copyTruncated(record.entry[0..], component.entry);
    return record;
}

test "new tasks start with zero ambient authority and no capabilities" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .session_manager,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 2048,
            .background_allowed = false,
        },
        .ui_surface_id = 7,
        .local_only = true,
    });

    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(task.zero_ambient_authority);
    try std.testing.expect(task.local_only);
    try std.testing.expectEqual(@as(?u64, 7), task.ui_surface_id);
    try std.testing.expectEqual(@as(usize, 1), task.execution_component_count);
    try std.testing.expectEqual(ExecutionSubstrate.typed_component_abi, task.execution_components[0].substrate);
    try std.testing.expectEqualStrings("session-manager", task.execution_components[0].labelSlice());
}

test "granting and revoking capabilities updates the task table" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 2 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 5_000,
            .memory_bytes = 4096,
            .endpoint_slots = 8,
            .shared_memory_bytes = 8192,
            .background_allowed = true,
        },
    });

    try runtime.grantCapability(task.id, 11);
    try runtime.grantCapability(task.id, 12);
    try std.testing.expectEqual(@as(usize, 2), task.capability_count);

    try std.testing.expect(try runtime.revokeCapability(task.id, 11));
    try std.testing.expectEqual(@as(usize, 1), task.capability_count);
    try std.testing.expectEqual(@as(u64, 12), task.capability_ids[0]);
}

test "audit trail keeps the most recent events" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 256,
            .endpoint_slots = 2,
            .shared_memory_bytes = 512,
        },
    });

    var index: usize = 0;
    while (index < MAX_AUDIT_EVENTS + 2) : (index += 1) {
        try runtime.audit(task.id, .{
            .kind = .policy_allowed,
            .detail = @intCast(index),
            .tick = index,
        });
    }

    try std.testing.expectEqual(@as(usize, MAX_AUDIT_EVENTS), task.audit_count);
    try std.testing.expectEqual(@as(u32, 2), task.audit_trail[0].detail);
    try std.testing.expectEqual(@as(u32, MAX_AUDIT_EVENTS + 1), task.audit_trail[MAX_AUDIT_EVENTS - 1].detail);
}

test "tasks can attach execution components while preserving launch substrate" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 500,
            .memory_bytes = 4096,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .initial_component = .{
            .substrate = .typed_component_abi,
            .label = "notes-ui",
            .entry = "app.notes.ui",
        },
    });

    const helper = try runtime.attachComponent(task.id, .{
        .substrate = .early_elf_runner,
        .label = "notes-sync-helper",
        .entry = "/system/components/notes-sync.elf",
    }, 12);

    try std.testing.expectEqual(@as(usize, 2), task.execution_component_count);
    try std.testing.expectEqualStrings("notes-ui", task.execution_components[0].labelSlice());
    try std.testing.expectEqual(ExecutionSubstrate.early_elf_runner, helper.substrate);
    try std.testing.expectEqualStrings("notes-sync-helper", helper.labelSlice());
    try std.testing.expectEqualStrings("/system/components/notes-sync.elf", helper.entrySlice());
    try std.testing.expectEqual(AuditEventKind.component_attached, task.audit_trail[task.audit_count - 1].kind);
}

test "terminating a task clears its capabilities and marks the state" {
    var runtime = Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .service, .serial = 8 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 512,
        },
    });

    try runtime.grantCapability(task.id, 77);
    try std.testing.expect(try runtime.terminateTask(task.id, 44));
    try std.testing.expectEqual(TaskState.terminated, task.state);
    try std.testing.expectEqual(@as(usize, 0), task.execution_component_count);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expectEqual(AuditEventKind.terminated, task.audit_trail[task.audit_count - 1].kind);
}
