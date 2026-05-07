const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const accelerator_scheduler = @import("accelerator_scheduler.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
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
const RESOURCE_CLASS_COUNT: usize = std.meta.fields(accelerator_scheduler.ResourceClass).len;
const ENGINE_COUNT: usize = std.meta.fields(accelerator_scheduler.Engine).len;
const MAX_ACCELERATOR_CLAIMS: usize = task_runtime.MAX_TASKS;
const EMERGENCY_DEADLINE_DELTA_TICKS: u64 = 1_000;
const FOREGROUND_DEADLINE_DELTA_TICKS: u64 = 5_000;
const MEDIA_EXPORT_DEADLINE_DELTA_TICKS: u64 = 20_000;
const BACKGROUND_DEADLINE_DELTA_TICKS: u64 = 50_000;
const BATCH_DEADLINE_DELTA_TICKS: u64 = 100_000;
const TEST_TASK_MEMORY_BYTES: usize = 1024;
const TEST_TASK_ENDPOINT_SLOTS: u16 = 2;
const TEST_TASK_SHARED_MEMORY_BYTES: usize = 1024;
const TEST_ACCELERATOR_SHARED_MEMORY_BYTES: usize = 4096;
const TEST_ACCELERATOR_DEADLINE_TICKS: u64 = 20;
const no_index = indexed_arena.no_index;

pub const WakeReason = enum(u8) {
    registered,
    ipc_message,
    timer,
    accelerator_available,
    budget_refill,
    external_event,
};

pub const AcceleratorClaimRequest = struct {
    task_id: u64,
    engine: accelerator_scheduler.Engine,
    resource_class: accelerator_scheduler.ResourceClass,
    requested_at_tick: u64,
    deadline_tick: u64 = 0,
    shared_memory_bytes: usize = 0,
};

pub const AcceleratorClaimRecord = struct {
    id: u64,
    task_id: u64,
    engine: accelerator_scheduler.Engine,
    resource_class: accelerator_scheduler.ResourceClass,
    requested_at_tick: u64,
    deadline_tick: u64,
    shared_memory_bytes: usize,
};

const Slot = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    resource_class: accelerator_scheduler.ResourceClass = .foreground_interactive,
    queued_ready: bool = false,
    next_ready_index: usize = no_index,
    dispatch_count: u64 = 0,
    last_dispatch_tick: u64 = 0,
    last_wake_tick: u64 = 0,
    wake_event_count: u64 = 0,
    cpu_ticks_consumed: u64 = 0,
    cpu_budget_remaining_ticks: u64 = 0,
    deadline_tick: u64 = 0,
    missed_deadline_count: u64 = 0,
};

const AcceleratorClaimSlot = struct {
    in_use: bool = false,
    record: AcceleratorClaimRecord = zeroAcceleratorClaim(),
    next_claim_index: usize = no_index,
};

const SchedulerSlotArena = indexed_arena.IndexedArenaWithKey(u64, Slot, task_runtime.MAX_TASKS, task_runtime.MAX_TASKS * 2, schedulerSlotTaskId);
const AcceleratorClaimArena = indexed_arena.IndexedArenaWithKey(u64, AcceleratorClaimSlot, MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS * 2, acceleratorClaimSlotId);

pub const Scheduler = struct {
    executor: *userspace_executor.Executor,
    initialized: bool = false,
    catalog_ptr: ?*userspace_loader.Catalog = null,
    runtime_ptr: ?*task_runtime.Runtime = null,
    capability_table_ptr: ?*const capability.CapabilityTable = null,
    slots: SchedulerSlotArena = SchedulerSlotArena.init(),
    ready_heads: [RESOURCE_CLASS_COUNT]usize = [_]usize{no_index} ** RESOURCE_CLASS_COUNT,
    ready_tails: [RESOURCE_CLASS_COUNT]usize = [_]usize{no_index} ** RESOURCE_CLASS_COUNT,
    ready_counts: [RESOURCE_CLASS_COUNT]usize = [_]usize{0} ** RESOURCE_CLASS_COUNT,
    ready_task_count: usize = 0,
    accelerator_claims: AcceleratorClaimArena = AcceleratorClaimArena.init(),
    accelerator_claim_heads: [ENGINE_COUNT]usize = [_]usize{no_index} ** ENGINE_COUNT,
    accelerator_claim_tails: [ENGINE_COUNT]usize = [_]usize{no_index} ** ENGINE_COUNT,
    accelerator_claim_counts: [ENGINE_COUNT]usize = [_]usize{0} ** ENGINE_COUNT,
    next_accelerator_claim_id: u64 = 1,
    resource_state: accelerator_scheduler.SystemState = .{},
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
        self.slots = SchedulerSlotArena.init();
        self.ready_heads = [_]usize{no_index} ** RESOURCE_CLASS_COUNT;
        self.ready_tails = [_]usize{no_index} ** RESOURCE_CLASS_COUNT;
        self.ready_counts = [_]usize{0} ** RESOURCE_CLASS_COUNT;
        self.ready_task_count = 0;
        self.accelerator_claims = AcceleratorClaimArena.init();
        self.accelerator_claim_heads = [_]usize{no_index} ** ENGINE_COUNT;
        self.accelerator_claim_tails = [_]usize{no_index} ** ENGINE_COUNT;
        self.accelerator_claim_counts = [_]usize{0} ** ENGINE_COUNT;
        self.next_accelerator_claim_id = 1;
        self.resource_state = .{};
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
        self.last_dispatch_tick = 0;
        self.executor.init();
        if (builtin.target.os.tag == .freestanding and !self.ready_marker_printed) {
            common.printBootMarker(boot_markers.userspace_scheduler_ready);
            self.ready_marker_printed = true;
        }
    }

    pub fn configureResourceState(self: *Scheduler, state: accelerator_scheduler.SystemState) void {
        self.resource_state = state;
    }

    pub fn registerTask(self: *Scheduler, task_id: u64) bool {
        if (!self.initialized) return false;
        const runtime = self.runtime_ptr orelse return false;
        const task = runtime.find(task_id) orelse return false;
        const slot_index = self.slots.reserveIndex(task_id) orelse return false;
        const slot = &self.slots.slots[slot_index];
        slot.task_id = task_id;
        slot.resource_class = task.resourceClass();
        slot.cpu_budget_remaining_ticks = task.budget.cpu_time_ticks;
        slot.deadline_tick = deadlineFromNow(slot.resource_class, 0);
        slot.last_wake_tick = 0;
        slot.wake_event_count = 1;
        return self.enqueueReadyIndex(slot_index, slot.resource_class);
    }

    pub fn unregisterTask(self: *Scheduler, task_id: u64) bool {
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        self.unlinkReadyIndex(slot_index);
        self.removeAcceleratorClaimsForTask(task_id);
        return self.slots.removeIndex(slot_index);
    }

    pub fn parkTaskUntilEvent(self: *Scheduler, task_id: u64) bool {
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        self.unlinkReadyIndex(slot_index);
        return true;
    }

    pub fn wakeTask(
        self: *Scheduler,
        task_id: u64,
        reason: WakeReason,
        now_ticks: u64,
        deadline_tick: u64,
    ) bool {
        _ = reason;
        if (!self.initialized) return false;
        const runtime = self.runtime_ptr orelse return false;
        const task = runtime.find(task_id) orelse return false;
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        const slot = &self.slots.slots[slot_index];
        if (slot.queued_ready and slot.resource_class != task.resourceClass()) {
            self.unlinkReadyIndex(slot_index);
        }
        slot.resource_class = task.resourceClass();
        slot.last_wake_tick = now_ticks;
        slot.wake_event_count += 1;
        slot.deadline_tick = if (deadline_tick != 0) deadline_tick else deadlineFromNow(slot.resource_class, now_ticks);
        if (slot.cpu_budget_remaining_ticks == 0 and task.budget.cpu_time_ticks != 0) {
            slot.cpu_budget_remaining_ticks = task.budget.cpu_time_ticks;
        }
        return self.enqueueReadyIndex(slot_index, slot.resource_class);
    }

    pub fn refillTaskBudget(self: *Scheduler, task_id: u64, cpu_ticks: u64, now_ticks: u64) bool {
        const slot = self.slots.get(task_id) orelse return false;
        slot.cpu_budget_remaining_ticks = std.math.add(u64, slot.cpu_budget_remaining_ticks, cpu_ticks) catch std.math.maxInt(u64);
        return self.wakeTask(task_id, .budget_refill, now_ticks, 0);
    }

    pub fn readyQueueDepth(self: *const Scheduler, class: accelerator_scheduler.ResourceClass) usize {
        return self.ready_counts[resourceClassIndex(class)];
    }

    pub fn enqueueAcceleratorClaim(self: *Scheduler, request: AcceleratorClaimRequest) ?u64 {
        if (!self.initialized or request.engine == .cpu) return null;
        if (self.slots.getConst(request.task_id) == null) return null;

        const claim_id = self.nextAcceleratorClaimId();
        const claim_index = self.accelerator_claims.reserveIndex(claim_id) orelse return null;
        const slot = &self.accelerator_claims.slots[claim_index];
        slot.record = .{
            .id = claim_id,
            .task_id = request.task_id,
            .engine = request.engine,
            .resource_class = request.resource_class,
            .requested_at_tick = request.requested_at_tick,
            .deadline_tick = request.deadline_tick,
            .shared_memory_bytes = request.shared_memory_bytes,
        };
        self.appendAcceleratorClaimIndex(request.engine, claim_index);
        return claim_id;
    }

    pub fn grantNextAcceleratorClaim(
        self: *Scheduler,
        engine: accelerator_scheduler.Engine,
        now_ticks: u64,
    ) ?AcceleratorClaimRecord {
        const claim_index = self.popAcceleratorClaimIndex(engine) orelse return null;
        const record = self.accelerator_claims.slots[claim_index].record;
        _ = self.accelerator_claims.removeIndex(claim_index);
        _ = self.wakeTask(record.task_id, .accelerator_available, now_ticks, record.deadline_tick);
        return record;
    }

    pub fn acceleratorClaimQueueDepth(self: *const Scheduler, engine: accelerator_scheduler.Engine) usize {
        return self.accelerator_claim_counts[engineIndex(engine)];
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

        while (self.ready_task_count != 0) {
            const class = self.selectReadyResourceClass(now_ticks) orelse break;
            const index = self.popReadyIndex(class) orelse break;
            const slot = &self.slots.slots[index];
            if (!slot.in_use) continue;

            const task_id = slot.task_id;
            const task = runtime.find(task_id) orelse {
                _ = self.unregisterSlotIndex(index);
                continue;
            };
            if (task.state != .active or !task.runsAsUserspaceProcess() or !task.hasLoadedExecutable()) {
                continue;
            }
            if (!hasDispatchBudget(slot, task)) continue;

            self.accountDeadline(slot, now_ticks);
            const yielded = self.executeTask(task_id, now_ticks);
            self.last_dispatch_tick = now_ticks;
            slot.dispatch_count += 1;
            slot.last_dispatch_tick = now_ticks;
            slot.cpu_ticks_consumed += DISPATCH_CPU_TICK_COST;
            slot.cpu_budget_remaining_ticks = saturatingSubTicks(slot.cpu_budget_remaining_ticks, DISPATCH_CPU_TICK_COST);
            if (builtin.target.os.tag == .freestanding and yielded and !self.active_marker_printed) {
                common.printBootMarker(boot_markers.userspace_scheduler_active);
                self.active_marker_printed = true;
            }
            if (runtime.find(task_id)) |updated_task| {
                if (updated_task.state == .active and
                    updated_task.runsAsUserspaceProcess() and
                    updated_task.hasLoadedExecutable() and
                    hasDispatchBudget(slot, updated_task))
                {
                    slot.resource_class = updated_task.resourceClass();
                    slot.deadline_tick = deadlineFromNow(slot.resource_class, now_ticks);
                    _ = self.enqueueReadyIndex(index, slot.resource_class);
                }
            }
            return yielded;
        }

        self.last_dispatch_tick = now_ticks;
        return false;
    }

    fn enqueueReadyIndex(
        self: *Scheduler,
        slot_index: usize,
        class: accelerator_scheduler.ResourceClass,
    ) bool {
        if (slot_index >= self.slots.slots.len) return false;
        const slot = &self.slots.slots[slot_index];
        if (!slot.in_use) return false;
        if (slot.queued_ready) return true;

        const queue_index = resourceClassIndex(class);
        slot.resource_class = class;
        slot.next_ready_index = no_index;
        if (self.ready_tails[queue_index] == no_index) {
            self.ready_heads[queue_index] = slot_index;
        } else {
            self.slots.slots[self.ready_tails[queue_index]].next_ready_index = slot_index;
        }
        self.ready_tails[queue_index] = slot_index;
        self.ready_counts[queue_index] += 1;
        self.ready_task_count += 1;
        slot.queued_ready = true;
        return true;
    }

    fn popReadyIndex(self: *Scheduler, class: accelerator_scheduler.ResourceClass) ?usize {
        const queue_index = resourceClassIndex(class);
        const slot_index = self.ready_heads[queue_index];
        if (slot_index == no_index) return null;
        if (slot_index >= self.slots.slots.len) return null;

        const slot = &self.slots.slots[slot_index];
        self.ready_heads[queue_index] = slot.next_ready_index;
        if (self.ready_heads[queue_index] == no_index) self.ready_tails[queue_index] = no_index;
        slot.next_ready_index = no_index;
        if (slot.queued_ready) {
            slot.queued_ready = false;
            self.ready_counts[queue_index] -= 1;
            self.ready_task_count -= 1;
        }
        return slot_index;
    }

    fn unlinkReadyIndex(self: *Scheduler, slot_index: usize) void {
        if (slot_index >= self.slots.slots.len) return;
        const target = &self.slots.slots[slot_index];
        if (!target.in_use or !target.queued_ready) return;

        const queue_index = resourceClassIndex(target.resource_class);
        var previous: usize = no_index;
        var current = self.ready_heads[queue_index];
        while (current != no_index) : (current = self.slots.slots[current].next_ready_index) {
            if (current == slot_index) {
                const next = self.slots.slots[current].next_ready_index;
                if (previous == no_index) {
                    self.ready_heads[queue_index] = next;
                } else {
                    self.slots.slots[previous].next_ready_index = next;
                }
                if (self.ready_tails[queue_index] == current) self.ready_tails[queue_index] = previous;
                target.next_ready_index = no_index;
                target.queued_ready = false;
                self.ready_counts[queue_index] -= 1;
                self.ready_task_count -= 1;
                return;
            }
            previous = current;
        }
        target.queued_ready = false;
        target.next_ready_index = no_index;
    }

    fn selectReadyResourceClass(self: *const Scheduler, now_ticks: u64) ?accelerator_scheduler.ResourceClass {
        var deadline_class: ?accelerator_scheduler.ResourceClass = null;
        var earliest_deadline: u64 = std.math.maxInt(u64);
        for (resource_priority_order) |class| {
            if (!self.resourceClassDispatchable(class)) continue;
            const queue_index = resourceClassIndex(class);
            const head = self.ready_heads[queue_index];
            if (head == no_index) continue;
            const deadline = self.slots.slots[head].deadline_tick;
            if (deadline != 0 and deadline <= now_ticks and deadline < earliest_deadline) {
                earliest_deadline = deadline;
                deadline_class = class;
            }
        }
        if (deadline_class) |class| return class;
        for (resource_priority_order) |class| {
            if (!self.resourceClassDispatchable(class)) continue;
            if (self.ready_heads[resourceClassIndex(class)] != no_index) return class;
        }
        return null;
    }

    fn resourceClassDispatchable(self: *const Scheduler, class: accelerator_scheduler.ResourceClass) bool {
        return switch (class) {
            .emergency_system_critical => true,
            .batch_compute => self.resource_state.thermal_pressure != .critical and !self.resource_state.battery_saver,
            .background_light => self.resource_state.thermal_pressure != .critical,
            .foreground_interactive, .media_export => true,
        };
    }

    fn accountDeadline(self: *Scheduler, slot: *Slot, now_ticks: u64) void {
        _ = self;
        if (slot.deadline_tick != 0 and now_ticks > slot.deadline_tick) {
            slot.missed_deadline_count += 1;
        }
    }

    fn unregisterSlotIndex(self: *Scheduler, slot_index: usize) bool {
        if (slot_index >= self.slots.slots.len) return false;
        const task_id = self.slots.slots[slot_index].task_id;
        self.unlinkReadyIndex(slot_index);
        self.removeAcceleratorClaimsForTask(task_id);
        return self.slots.removeIndex(slot_index);
    }

    fn appendAcceleratorClaimIndex(self: *Scheduler, engine: accelerator_scheduler.Engine, claim_index: usize) void {
        const queue_index = engineIndex(engine);
        const claim = &self.accelerator_claims.slots[claim_index];
        claim.next_claim_index = no_index;
        if (self.accelerator_claim_tails[queue_index] == no_index) {
            self.accelerator_claim_heads[queue_index] = claim_index;
        } else {
            self.accelerator_claims.slots[self.accelerator_claim_tails[queue_index]].next_claim_index = claim_index;
        }
        self.accelerator_claim_tails[queue_index] = claim_index;
        self.accelerator_claim_counts[queue_index] += 1;
    }

    fn popAcceleratorClaimIndex(self: *Scheduler, engine: accelerator_scheduler.Engine) ?usize {
        const queue_index = engineIndex(engine);
        const claim_index = self.accelerator_claim_heads[queue_index];
        if (claim_index == no_index) return null;
        if (claim_index >= self.accelerator_claims.slots.len) return null;
        const claim = &self.accelerator_claims.slots[claim_index];
        self.accelerator_claim_heads[queue_index] = claim.next_claim_index;
        if (self.accelerator_claim_heads[queue_index] == no_index) self.accelerator_claim_tails[queue_index] = no_index;
        claim.next_claim_index = no_index;
        self.accelerator_claim_counts[queue_index] -= 1;
        return claim_index;
    }

    fn removeAcceleratorClaimsForTask(self: *Scheduler, task_id: u64) void {
        for (engine_priority_order) |engine| {
            const queue_index = engineIndex(engine);
            var previous: usize = no_index;
            var current = self.accelerator_claim_heads[queue_index];
            while (current != no_index) {
                const next = self.accelerator_claims.slots[current].next_claim_index;
                if (self.accelerator_claims.slots[current].record.task_id == task_id) {
                    if (previous == no_index) {
                        self.accelerator_claim_heads[queue_index] = next;
                    } else {
                        self.accelerator_claims.slots[previous].next_claim_index = next;
                    }
                    if (self.accelerator_claim_tails[queue_index] == current) self.accelerator_claim_tails[queue_index] = previous;
                    self.accelerator_claims.slots[current].next_claim_index = no_index;
                    self.accelerator_claim_counts[queue_index] -= 1;
                    _ = self.accelerator_claims.removeIndex(current);
                } else {
                    previous = current;
                }
                current = next;
            }
        }
    }

    fn nextAcceleratorClaimId(self: *Scheduler) u64 {
        const claim_id = self.next_accelerator_claim_id;
        self.next_accelerator_claim_id +%= 1;
        if (self.next_accelerator_claim_id == 0) self.next_accelerator_claim_id = 1;
        return claim_id;
    }
};

fn schedulerSlotTaskId(slot: *const Slot) u64 {
    return slot.task_id;
}

fn acceleratorClaimSlotId(slot: *const AcceleratorClaimSlot) u64 {
    return slot.record.id;
}

fn hasDispatchBudget(slot: *const Slot, task: *const task_runtime.TaskRecord) bool {
    _ = task;
    return slot.cpu_budget_remaining_ticks >= DISPATCH_CPU_TICK_COST;
}

fn saturatingSubTicks(value: u64, amount: u64) u64 {
    if (amount >= value) return 0;
    return value - amount;
}

const resource_priority_order = [_]accelerator_scheduler.ResourceClass{
    .emergency_system_critical,
    .foreground_interactive,
    .media_export,
    .background_light,
    .batch_compute,
};

const engine_priority_order = [_]accelerator_scheduler.Engine{
    .gpu,
    .npu,
    .media,
};

fn resourceClassIndex(class: accelerator_scheduler.ResourceClass) usize {
    return switch (class) {
        .foreground_interactive => 0,
        .background_light => 1,
        .media_export => 2,
        .batch_compute => 3,
        .emergency_system_critical => 4,
    };
}

fn engineIndex(engine: accelerator_scheduler.Engine) usize {
    return switch (engine) {
        .cpu => 0,
        .gpu => 1,
        .npu => 2,
        .media => 3,
    };
}

fn deadlineFromNow(class: accelerator_scheduler.ResourceClass, now_ticks: u64) u64 {
    const delta: u64 = switch (class) {
        .emergency_system_critical => EMERGENCY_DEADLINE_DELTA_TICKS,
        .foreground_interactive => FOREGROUND_DEADLINE_DELTA_TICKS,
        .media_export => MEDIA_EXPORT_DEADLINE_DELTA_TICKS,
        .background_light => BACKGROUND_DEADLINE_DELTA_TICKS,
        .batch_compute => BATCH_DEADLINE_DELTA_TICKS,
    };
    return std.math.add(u64, now_ticks, delta) catch std.math.maxInt(u64);
}

fn zeroAcceleratorClaim() AcceleratorClaimRecord {
    return .{
        .id = 0,
        .task_id = 0,
        .engine = .cpu,
        .resource_class = .background_light,
        .requested_at_tick = 0,
        .deadline_tick = 0,
        .shared_memory_bytes = 0,
    };
}

test "userspace scheduler registers tasks through indexed arena slots" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
    const second_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });

    try std.testing.expect(scheduler.registerTask(first_task.id));
    try std.testing.expect(!scheduler.registerTask(first_task.id));
    try std.testing.expectEqual(@as(usize, 1), scheduler.slots.countInUse());

    const first_index = scheduler.slots.slotIndexOf(first_task.id).?;
    try std.testing.expect(scheduler.unregisterTask(first_task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.slots.countInUse());

    try std.testing.expect(scheduler.registerTask(second_task.id));
    try std.testing.expectEqual(first_index, scheduler.slots.slotIndexOf(second_task.id).?);
}

test "userspace scheduler dispatches resource ready queues by priority" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const background_image = task_runtime.syntheticUserspaceImage("background", "app.example.background");
    const foreground_image = task_runtime.syntheticUserspaceImage("foreground", "app.example.foreground");
    const background = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
            .resource_class = .background_light,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 3,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.background",
        },
        .userspace_image = &background_image,
    });
    const foreground = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 4 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
            .resource_class = .foreground_interactive,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 4,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.foreground",
        },
        .userspace_image = &foreground_image,
    });

    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.background_light));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));

    try std.testing.expect(scheduler.wakeTask(foreground.id, .timer, 10, 5));
    try std.testing.expect(!scheduler.runNext(10));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(foreground.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(foreground.id).?.missed_deadline_count);
    try std.testing.expectEqual(@as(u64, 0), scheduler.slots.getConst(background.id).?.dispatch_count);
}

test "userspace scheduler uses event wakeups and explicit budget refills" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = task_runtime.syntheticUserspaceImage("wake-budgeted", "app.example.wake-budgeted");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 5 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 5,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.wake-budgeted",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(!scheduler.runNext(1));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);
    try std.testing.expect(!scheduler.runNext(2));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);

    try std.testing.expect(scheduler.refillTaskBudget(task.id, DISPATCH_CPU_TICK_COST, 3));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expect(!scheduler.runNext(4));
    try std.testing.expectEqual(@as(u64, 2), scheduler.slots.getConst(task.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 2), scheduler.slots.getConst(task.id).?.wake_event_count);
}

test "userspace scheduler separates accelerator claim queues from cpu ready queues" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 6 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .media_export,
        },
        .local_only = true,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.media_export));

    const gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 7,
        .deadline_tick = TEST_ACCELERATOR_DEADLINE_TICKS,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    _ = gpu_claim;
    const media_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .media,
        .resource_class = .media_export,
        .requested_at_tick = 8,
        .deadline_tick = TEST_ACCELERATOR_DEADLINE_TICKS,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;

    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));
    const granted = scheduler.grantNextAcceleratorClaim(.media, 9).?;
    try std.testing.expectEqual(media_claim, granted.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.media_export));
}

test "userspace scheduler thermal pressure gates batch queues without scanning task slots" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = task_runtime.syntheticUserspaceImage("batch", "app.example.batch");
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 7 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
            .resource_class = .batch_compute,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 7,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.batch",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    scheduler.configureResourceState(.{ .thermal_pressure = .critical });
    try std.testing.expect(!scheduler.runNext(10));
    try std.testing.expectEqual(@as(u64, 0), scheduler.slots.getConst(task.id).?.dispatch_count);

    scheduler.configureResourceState(.{ .thermal_pressure = .nominal });
    try std.testing.expect(!scheduler.runNext(11));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);
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
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
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
    const slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), slot.dispatch_count);
    try std.testing.expectEqual(DISPATCH_CPU_TICK_COST, slot.cpu_ticks_consumed);

    try std.testing.expect(!scheduler.runNext(2));
    try std.testing.expectEqual(@as(u64, 1), scheduler.slots.getConst(task.id).?.dispatch_count);
}
