const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_loader = @import("userspace_loader.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const DISPATCH_CPU_TICK_COST: u64 = 1_000;

const Slot = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    dispatch_count: u64 = 0,
    last_dispatch_tick: u64 = 0,
    cpu_ticks_consumed: u64 = 0,
};

pub const Scheduler = struct {
    executor: *userspace_executor.Executor,
    initialized: bool = false,
    catalog_ptr: ?*userspace_loader.Catalog = null,
    runtime_ptr: ?*task_runtime.Runtime = null,
    capability_table_ptr: ?*const capability.CapabilityTable = null,
    slots: [task_runtime.MAX_TASKS]Slot = [_]Slot{Slot{}} ** task_runtime.MAX_TASKS,
    next_index: usize = 0,
    last_dispatch_tick: u64 = 0,
    ready_marker_printed: bool = false,
    active_marker_printed: bool = false,

    pub fn init(executor: *userspace_executor.Executor) Scheduler {
        return .{ .executor = executor };
    }

    pub fn reset(self: *Scheduler) void {
        self.initialized = false;
        self.catalog_ptr = null;
        self.runtime_ptr = null;
        self.capability_table_ptr = null;
        self.slots = [_]Slot{Slot{}} ** task_runtime.MAX_TASKS;
        self.next_index = 0;
        self.last_dispatch_tick = 0;
        self.ready_marker_printed = false;
        self.active_marker_printed = false;
        self.executor.reset();
    }

    pub fn bind(
        self: *Scheduler,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
    ) void {
        self.catalog_ptr = catalog;
        self.runtime_ptr = runtime;
        self.capability_table_ptr = capability_table;
        self.initialized = true;
        self.next_index = 0;
        self.last_dispatch_tick = 0;
        self.executor.init();
        if (builtin.target.os.tag == .freestanding and !self.ready_marker_printed) {
            common.printBootMarker(boot_markers.userspace_scheduler_ready);
            self.ready_marker_printed = true;
        }
    }

    pub fn registerTask(self: *Scheduler, task_id: u64) bool {
        if (!self.initialized) return false;
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.task_id == task_id) return false;
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.* = .{
                .in_use = true,
                .task_id = task_id,
            };
            return true;
        }
        return false;
    }

    pub fn executeTask(self: *Scheduler, task_id: u64, now_ticks: u64) bool {
        if (!self.initialized) return false;
        const catalog = self.catalog_ptr orelse return false;
        const runtime = self.runtime_ptr orelse return false;
        const capability_table = self.capability_table_ptr orelse return false;
        return self.executor.executeTask(catalog, runtime, capability_table, task_id, now_ticks);
    }

    pub fn runNext(self: *Scheduler, now_ticks: u64) bool {
        if (!self.initialized) return false;

        const runtime = self.runtime_ptr orelse return false;

        var attempts: usize = 0;
        while (attempts < self.slots.len) : (attempts += 1) {
            const index = (self.next_index + attempts) % self.slots.len;
            const slot = &self.slots[index];
            if (!slot.in_use) continue;

            const task = runtime.find(slot.task_id) orelse {
                slot.in_use = false;
                continue;
            };
            if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) {
                continue;
            }
            if (!hasDispatchBudget(slot, task)) continue;

            self.last_dispatch_tick = now_ticks;
            self.next_index = (index + 1) % self.slots.len;
            const yielded = self.executeTask(slot.task_id, now_ticks);
            slot.dispatch_count += 1;
            slot.last_dispatch_tick = now_ticks;
            slot.cpu_ticks_consumed += DISPATCH_CPU_TICK_COST;
            if (builtin.target.os.tag == .freestanding and yielded and !self.active_marker_printed) {
                common.printBootMarker(boot_markers.userspace_scheduler_active);
                self.active_marker_printed = true;
            }
            return yielded;
        }

        self.last_dispatch_tick = now_ticks;
        return false;
    }
};

fn hasDispatchBudget(slot: *const Slot, task: *const task_runtime.TaskRecord) bool {
    const next = std.math.add(u64, slot.cpu_ticks_consumed, DISPATCH_CPU_TICK_COST) catch return false;
    return next <= task.budget.cpu_time_ticks;
}

test "userspace scheduler stops dispatching tasks after their cpu budget is consumed" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = task_runtime.syntheticUserspaceImage("budgeted", "app.example.budgeted");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = 1024,
            .endpoint_slots = 2,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 1,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.budgeted",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(!scheduler.runNext(1));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots[0].dispatch_count);
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, scheduler.slots[0].cpu_ticks_consumed);

    try std.testing.expect(!scheduler.runNext(2));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots[0].dispatch_count);
}
