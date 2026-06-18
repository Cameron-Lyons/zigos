const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const accelerator_scheduler = @import("accelerator_scheduler.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const capability = @import("../kernel_api/capability.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_loader = @import("userspace_loader.zig");
const generated_image_fixtures = if (builtin.is_test) @import("generated_image_fixtures.zig") else struct {};

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
const MEMORY_BANDWIDTH_UNIT_BYTES: usize = 1024;
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

pub const TaskDispatchStats = struct {
    task_id: u64,
    resource_class: accelerator_scheduler.ResourceClass,
    queued_ready: bool,
    dispatch_count: u64,
    delayed_dispatch_count: u64,
    denied_dispatch_count: u64,
    missed_deadline_count: u64,
    last_dispatch_tick: u64,
    last_wake_tick: u64,
    wake_event_count: u64,
    cpu_ticks_consumed: u64,
    memory_bandwidth_consumed_units: usize,
    last_dispatch_engine: accelerator_scheduler.Engine,
    last_dispatch_reason: accelerator_scheduler.DecisionReason,
    last_dispatch_degraded: bool,
    last_dispatch_zero_copy: bool,
};

const Slot = struct {
    in_use: bool = false,
    task_id: u64 = 0,
    resource_class: accelerator_scheduler.ResourceClass = .foreground_interactive,
    queued_ready: bool = false,
    prev_ready_index: usize = no_index,
    next_ready_index: usize = no_index,
    dispatch_count: u64 = 0,
    last_dispatch_tick: u64 = 0,
    last_wake_tick: u64 = 0,
    wake_event_count: u64 = 0,
    cpu_ticks_consumed: u64 = 0,
    cpu_budget_remaining_ticks: u64 = 0,
    memory_bandwidth_consumed_units: usize = 0,
    deadline_tick: u64 = 0,
    missed_deadline_count: u64 = 0,
    dispatch_request: accelerator_scheduler.Request = .{ .class = .foreground_interactive },
    dispatch_request_configured: bool = false,
    require_accelerator: bool = false,
    pending_accelerator_claim_id: u64 = 0,
    pending_accelerator_engine: accelerator_scheduler.Engine = .cpu,
    last_dispatch_engine: accelerator_scheduler.Engine = .cpu,
    last_dispatch_reason: accelerator_scheduler.DecisionReason = .normal,
    last_dispatch_degraded: bool = false,
    last_dispatch_zero_copy: bool = false,
    last_policy_delay_tick: u64 = 0,
    delayed_dispatch_count: u64 = 0,
    denied_dispatch_count: u64 = 0,
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
    engine_dispatch_counts: [ENGINE_COUNT]u64 = [_]u64{0} ** ENGINE_COUNT,
    engine_denial_counts: [ENGINE_COUNT]u64 = [_]u64{0} ** ENGINE_COUNT,
    next_accelerator_claim_id: u64 = 1,
    resource_state: accelerator_scheduler.SystemState = .{},
    resource_telemetry_source: accelerator_scheduler.TelemetrySource = .synthetic,
    resource_telemetry_observed_tick: u64 = 0,
    resource_hardware_evidence_complete: bool = false,
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
        self.engine_dispatch_counts = [_]u64{0} ** ENGINE_COUNT;
        self.engine_denial_counts = [_]u64{0} ** ENGINE_COUNT;
        self.next_accelerator_claim_id = 1;
        self.resource_state = .{};
        self.resource_telemetry_source = .synthetic;
        self.resource_telemetry_observed_tick = 0;
        self.resource_hardware_evidence_complete = false;
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
        self.resource_telemetry_source = .synthetic;
        self.resource_telemetry_observed_tick = 0;
        self.resource_hardware_evidence_complete = false;
    }

    pub fn configureResourceTelemetry(self: *Scheduler, sample: accelerator_scheduler.TelemetrySample) void {
        if (!accelerator_scheduler.telemetrySampleIsFresh(
            self.resource_telemetry_source,
            self.resource_telemetry_observed_tick,
            sample,
        )) return;
        self.resource_state = sample.toSystemState();
        self.resource_telemetry_source = sample.source;
        self.resource_telemetry_observed_tick = sample.observed_tick;
        self.resource_hardware_evidence_complete = sample.hardwareReaderEvidenceComplete();
    }

    pub fn configureResourceTelemetryFromProvider(
        self: *Scheduler,
        provider: accelerator_scheduler.TelemetryProvider,
    ) void {
        self.configureResourceTelemetry(provider.read());
    }

    pub fn observedResourceTelemetry(self: *const Scheduler) bool {
        return self.resource_telemetry_source != .synthetic;
    }

    pub fn registerTask(self: *Scheduler, task_id: u64) bool {
        if (!self.initialized) return false;
        const runtime = self.runtime_ptr orelse return false;
        const task = runtime.find(task_id) orelse return false;
        const slot_index = self.slots.reserveIndex(task_id) orelse return false;
        const slot = &self.slots.slots[slot_index];
        slot.task_id = task_id;
        slot.resource_class = task.resourceClass();
        slot.dispatch_request = deriveDispatchRequest(task);
        slot.dispatch_request_configured = false;
        slot.require_accelerator = false;
        slot.cpu_budget_remaining_ticks = task.budget.cpu_time_ticks;
        slot.deadline_tick = deadlineFromNow(slot.resource_class, 0);
        slot.last_wake_tick = 0;
        slot.wake_event_count = 1;
        return self.enqueueReadyIndex(slot_index, slot.resource_class);
    }

    pub fn configureTaskDispatchRequest(
        self: *Scheduler,
        task_id: u64,
        request: accelerator_scheduler.Request,
        require_accelerator: bool,
    ) bool {
        const runtime = self.runtime_ptr orelse return false;
        const task = runtime.find(task_id) orelse return false;
        const slot = self.slots.get(task_id) orelse return false;
        slot.dispatch_request = request;
        slot.dispatch_request.class = task.resourceClass();
        slot.dispatch_request_configured = true;
        slot.require_accelerator = require_accelerator;
        return true;
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

    pub fn taskDispatchStats(self: *const Scheduler, task_id: u64) ?TaskDispatchStats {
        const slot = self.slots.getConst(task_id) orelse return null;
        return .{
            .task_id = slot.task_id,
            .resource_class = slot.resource_class,
            .queued_ready = slot.queued_ready,
            .dispatch_count = slot.dispatch_count,
            .delayed_dispatch_count = slot.delayed_dispatch_count,
            .denied_dispatch_count = slot.denied_dispatch_count,
            .missed_deadline_count = slot.missed_deadline_count,
            .last_dispatch_tick = slot.last_dispatch_tick,
            .last_wake_tick = slot.last_wake_tick,
            .wake_event_count = slot.wake_event_count,
            .cpu_ticks_consumed = slot.cpu_ticks_consumed,
            .memory_bandwidth_consumed_units = slot.memory_bandwidth_consumed_units,
            .last_dispatch_engine = slot.last_dispatch_engine,
            .last_dispatch_reason = slot.last_dispatch_reason,
            .last_dispatch_degraded = slot.last_dispatch_degraded,
            .last_dispatch_zero_copy = slot.last_dispatch_zero_copy,
        };
    }

    pub fn enqueueAcceleratorClaim(self: *Scheduler, request: AcceleratorClaimRequest) ?u64 {
        if (!self.initialized or request.engine == .cpu) return null;
        const task_slot = self.slots.get(request.task_id) orelse return null;
        if (self.findAcceleratorClaimForTaskEngine(request.task_id, request.engine)) |claim_id| {
            return claim_id;
        }

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
        if (task_slot.pending_accelerator_claim_id == 0) {
            task_slot.pending_accelerator_claim_id = claim_id;
            task_slot.pending_accelerator_engine = request.engine;
        }
        return claim_id;
    }

    pub fn grantNextAcceleratorClaim(
        self: *Scheduler,
        engine: accelerator_scheduler.Engine,
        now_ticks: u64,
    ) ?AcceleratorClaimRecord {
        if (!self.physicalEngineAvailable(engine)) return null;
        const claim_index = self.popAcceleratorClaimIndex(engine) orelse return null;
        const record = self.accelerator_claims.slots[claim_index].record;
        _ = self.accelerator_claims.removeIndex(claim_index);
        if (self.slots.get(record.task_id)) |slot| {
            if (slot.pending_accelerator_claim_id == record.id) {
                slot.pending_accelerator_claim_id = 0;
                slot.pending_accelerator_engine = .cpu;
            }
        }
        _ = self.wakeTask(record.task_id, .accelerator_available, now_ticks, record.deadline_tick);
        return record;
    }

    pub fn acceleratorClaimQueueDepth(self: *const Scheduler, engine: accelerator_scheduler.Engine) usize {
        return self.accelerator_claim_counts[engineIndex(engine)];
    }

    pub fn engineDispatchCount(self: *const Scheduler, engine: accelerator_scheduler.Engine) u64 {
        return self.engine_dispatch_counts[engineIndex(engine)];
    }

    pub fn engineDenialCount(self: *const Scheduler, engine: accelerator_scheduler.Engine) u64 {
        return self.engine_denial_counts[engineIndex(engine)];
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

        self.wakeAvailableAcceleratorClaims(now_ticks);
        const runtime = self.runtime_ptr orelse return false;

        while (self.ready_task_count != 0) {
            const class = self.selectReadyResourceClass(now_ticks) orelse {
                if (self.accountBlockedReadyClasses(now_ticks)) {
                    self.last_dispatch_tick = now_ticks;
                }
                break;
            };
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
            if (!hasDispatchBudget(slot, task)) {
                self.accountDispatchDenied(slot, .cpu_budget, .cpu);
                continue;
            }

            const decision = self.planTaskDispatch(slot, task);
            slot.last_dispatch_engine = decision.engine;
            slot.last_dispatch_reason = decision.reason;
            slot.last_dispatch_degraded = decision.degraded;
            slot.last_dispatch_zero_copy = decision.zero_copy_allowed;
            if (decision.delayed) {
                self.accountDispatchDelayedAt(slot, decision, now_ticks);
                _ = self.enqueueReadyIndex(index, slot.resource_class);
                self.last_dispatch_tick = now_ticks;
                return false;
            }
            if (self.dispatchRequiresUnavailableAccelerator(slot, decision)) {
                self.accountDispatchDenied(slot, decision.reason, requestedAcceleratorEngine(self.dispatchRequestFor(slot, task)));
                self.queuePendingAcceleratorWake(slot, now_ticks);
                self.last_dispatch_tick = now_ticks;
                return false;
            }

            self.accountDeadline(slot, now_ticks);
            const yielded = self.executeTask(task_id, now_ticks);
            self.last_dispatch_tick = now_ticks;
            slot.dispatch_count += 1;
            slot.last_dispatch_tick = now_ticks;
            slot.cpu_ticks_consumed += DISPATCH_CPU_TICK_COST;
            slot.cpu_budget_remaining_ticks = saturatingSubTicks(slot.cpu_budget_remaining_ticks, DISPATCH_CPU_TICK_COST);
            slot.memory_bandwidth_consumed_units = std.math.add(
                usize,
                slot.memory_bandwidth_consumed_units,
                memoryBandwidthUnitsFor(task),
            ) catch std.math.maxInt(usize);
            self.accountDispatchResources(task, decision);
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
                    if (!slot.dispatch_request_configured) slot.dispatch_request = deriveDispatchRequest(updated_task);
                    slot.deadline_tick = deadlineAfterDispatch(slot.resource_class, now_ticks);
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
        slot.prev_ready_index = self.ready_tails[queue_index];
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
        const next = slot.next_ready_index;
        self.ready_heads[queue_index] = next;
        if (self.ready_heads[queue_index] == no_index) self.ready_tails[queue_index] = no_index;
        if (next != no_index) self.slots.slots[next].prev_ready_index = no_index;
        slot.prev_ready_index = no_index;
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
        const previous = target.prev_ready_index;
        const next = target.next_ready_index;

        if (previous == no_index) {
            self.ready_heads[queue_index] = next;
        } else {
            self.slots.slots[previous].next_ready_index = next;
        }
        if (next == no_index) {
            self.ready_tails[queue_index] = previous;
        } else {
            self.slots.slots[next].prev_ready_index = previous;
        }

        target.queued_ready = false;
        target.prev_ready_index = no_index;
        target.next_ready_index = no_index;
        self.ready_counts[queue_index] -= 1;
        self.ready_task_count -= 1;
    }

    fn selectReadyResourceClass(self: *const Scheduler, now_ticks: u64) ?accelerator_scheduler.ResourceClass {
        var deadline_class: ?accelerator_scheduler.ResourceClass = null;
        var earliest_deadline: u64 = std.math.maxInt(u64);
        var selected_dispatch_count: u64 = std.math.maxInt(u64);
        var selected_last_dispatch_tick: u64 = std.math.maxInt(u64);
        for (resource_priority_order) |class| {
            if (!self.resourceClassDispatchable(class)) continue;
            const queue_index = resourceClassIndex(class);
            const head = self.ready_heads[queue_index];
            if (head == no_index) continue;
            const slot = &self.slots.slots[head];
            const deadline = slot.deadline_tick;
            if (deadline != 0 and
                deadline <= now_ticks and
                expiredReadyCandidateBeats(slot, deadline, earliest_deadline, selected_dispatch_count, selected_last_dispatch_tick))
            {
                earliest_deadline = deadline;
                selected_dispatch_count = slot.dispatch_count;
                selected_last_dispatch_tick = slot.last_dispatch_tick;
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

    fn accountBlockedReadyClasses(self: *Scheduler, now_ticks: u64) bool {
        var accounted = false;
        for (resource_priority_order) |class| {
            if (self.resourceClassDispatchable(class)) continue;
            const queue_index = resourceClassIndex(class);
            const slot_index = self.ready_heads[queue_index];
            if (slot_index == no_index) continue;
            if (slot_index >= self.slots.slots.len) continue;

            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use or slot.last_policy_delay_tick == now_ticks) continue;

            self.accountDispatchDelayedAt(slot, self.blockedResourceDecision(class), now_ticks);
            accounted = true;
        }
        return accounted;
    }

    fn blockedResourceDecision(
        self: *const Scheduler,
        class: accelerator_scheduler.ResourceClass,
    ) accelerator_scheduler.Decision {
        const decision = accelerator_scheduler.planWithState(
            self.resource_state,
            self.engineAvailability(),
            .{ .class = class },
        );
        if (decision.delayed) return decision;
        return .{
            .class = class,
            .engine = .cpu,
            .delayed = true,
            .degraded = true,
            .zero_copy_allowed = false,
            .reason = self.blockedResourceReason(),
        };
    }

    fn blockedResourceReason(self: *const Scheduler) accelerator_scheduler.DecisionReason {
        if (self.resource_state.thermal_pressure == .critical) return .thermal_throttle;
        if (self.resource_state.battery_saver) return .battery_preserve;
        return .normal;
    }

    fn planTaskDispatch(
        self: *const Scheduler,
        slot: *const Slot,
        task: *const task_runtime.TaskRecord,
    ) accelerator_scheduler.Decision {
        return accelerator_scheduler.planWithState(
            self.resource_state,
            self.engineAvailability(),
            self.dispatchRequestFor(slot, task),
        );
    }

    fn dispatchRequestFor(
        self: *const Scheduler,
        slot: *const Slot,
        task: *const task_runtime.TaskRecord,
    ) accelerator_scheduler.Request {
        _ = self;
        var request = if (slot.dispatch_request_configured)
            slot.dispatch_request
        else
            deriveDispatchRequest(task);
        request.class = slot.resource_class;
        if (request.expected_cpu_ticks == 0) request.expected_cpu_ticks = DISPATCH_CPU_TICK_COST;
        if (request.memory_bandwidth_units == 0) request.memory_bandwidth_units = memoryBandwidthUnitsFor(task);
        if (request.shared_memory_bytes == 0) request.shared_memory_bytes = task.budget.shared_memory_bytes;
        return request;
    }

    fn dispatchRequiresUnavailableAccelerator(
        self: *const Scheduler,
        slot: *const Slot,
        decision: accelerator_scheduler.Decision,
    ) bool {
        _ = self;
        return slot.require_accelerator and decision.engine == .cpu;
    }

    fn accountDispatchDelayed(self: *Scheduler, slot: *Slot, decision: accelerator_scheduler.Decision) void {
        _ = self;
        slot.delayed_dispatch_count += 1;
        slot.last_dispatch_engine = decision.engine;
        slot.last_dispatch_reason = decision.reason;
        slot.last_dispatch_degraded = decision.degraded;
        slot.last_dispatch_zero_copy = decision.zero_copy_allowed;
    }

    fn accountDispatchDelayedAt(
        self: *Scheduler,
        slot: *Slot,
        decision: accelerator_scheduler.Decision,
        now_ticks: u64,
    ) void {
        if (slot.last_policy_delay_tick == now_ticks) return;
        self.accountDispatchDelayed(slot, decision);
        slot.last_policy_delay_tick = now_ticks;
    }

    fn accountDispatchDenied(
        self: *Scheduler,
        slot: *Slot,
        reason: accelerator_scheduler.DecisionReason,
        engine: accelerator_scheduler.Engine,
    ) void {
        slot.denied_dispatch_count += 1;
        slot.last_dispatch_reason = reason;
        self.engine_denial_counts[engineIndex(engine)] += 1;
    }

    fn accountDispatchResources(
        self: *Scheduler,
        task: *const task_runtime.TaskRecord,
        decision: accelerator_scheduler.Decision,
    ) void {
        self.engine_dispatch_counts[engineIndex(decision.engine)] += 1;
        self.resource_state.cpu_budget_ticks = saturatingSubTicks(self.resource_state.cpu_budget_ticks, DISPATCH_CPU_TICK_COST);
        self.resource_state.memory_bandwidth_units = saturatingSubUsize(
            self.resource_state.memory_bandwidth_units,
            memoryBandwidthUnitsFor(task),
        );
    }

    fn queuePendingAcceleratorWake(self: *Scheduler, slot: *Slot, now_ticks: u64) void {
        if (slot.pending_accelerator_claim_id != 0) return;
        const request = self.dispatchRequestFor(slot, self.runtime_ptr.?.find(slot.task_id).?);
        const engine = requestedAcceleratorEngine(request);
        if (engine == .cpu) return;
        _ = self.enqueueAcceleratorClaim(.{
            .task_id = slot.task_id,
            .engine = engine,
            .resource_class = slot.resource_class,
            .requested_at_tick = now_ticks,
            .deadline_tick = slot.deadline_tick,
            .shared_memory_bytes = request.shared_memory_bytes,
        });
        self.unlinkReadyIndex(self.slots.slotIndexOf(slot.task_id) orelse return);
    }

    fn wakeAvailableAcceleratorClaims(self: *Scheduler, now_ticks: u64) void {
        for (engine_priority_order) |engine| {
            if (!self.physicalEngineAvailable(engine)) continue;
            while (self.accelerator_claim_counts[engineIndex(engine)] != 0) {
                _ = self.grantNextAcceleratorClaim(engine, now_ticks) orelse break;
            }
        }
    }

    fn engineAvailability(self: *const Scheduler) accelerator_scheduler.EngineAvailability {
        return .{
            .gpu = self.engineCurrentlyAvailable(.gpu),
            .npu = self.engineCurrentlyAvailable(.npu),
            .media = self.engineCurrentlyAvailable(.media),
        };
    }

    fn engineCurrentlyAvailable(self: *const Scheduler, engine: accelerator_scheduler.Engine) bool {
        return switch (engine) {
            .cpu => true,
            .gpu => self.physicalEngineAvailable(.gpu) and self.accelerator_claim_counts[engineIndex(.gpu)] == 0,
            .npu => self.physicalEngineAvailable(.npu) and self.accelerator_claim_counts[engineIndex(.npu)] == 0,
            .media => self.physicalEngineAvailable(.media) and self.accelerator_claim_counts[engineIndex(.media)] == 0,
        };
    }

    fn physicalEngineAvailable(self: *const Scheduler, engine: accelerator_scheduler.Engine) bool {
        const telemetry_ready = self.hardwareQueueTelemetryReady();
        return switch (engine) {
            .cpu => true,
            .gpu => telemetry_ready and self.resource_state.gpu_available,
            .npu => telemetry_ready and self.resource_state.npu_available,
            .media => telemetry_ready and self.resource_state.media_available,
        };
    }

    fn hardwareQueueTelemetryReady(self: *const Scheduler) bool {
        if (!self.observedResourceTelemetry()) return false;
        return self.resource_telemetry_source != .hardware or self.resource_hardware_evidence_complete;
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
                    if (self.slots.get(task_id)) |slot| {
                        if (slot.pending_accelerator_claim_id == self.accelerator_claims.slots[current].record.id) {
                            slot.pending_accelerator_claim_id = 0;
                            slot.pending_accelerator_engine = .cpu;
                        }
                    }
                    _ = self.accelerator_claims.removeIndex(current);
                } else {
                    previous = current;
                }
                current = next;
            }
        }
    }

    fn findAcceleratorClaimForTaskEngine(
        self: *const Scheduler,
        task_id: u64,
        engine: accelerator_scheduler.Engine,
    ) ?u64 {
        const queue_index = engineIndex(engine);
        var current = self.accelerator_claim_heads[queue_index];
        while (current != no_index) {
            if (current >= self.accelerator_claims.slots.len) return null;
            const record = self.accelerator_claims.slots[current].record;
            if (record.task_id == task_id and record.engine == engine) return record.id;
            current = self.accelerator_claims.slots[current].next_claim_index;
        }
        return null;
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

fn saturatingSubUsize(value: usize, amount: usize) usize {
    if (amount >= value) return 0;
    return value - amount;
}

fn deriveDispatchRequest(task: *const task_runtime.TaskRecord) accelerator_scheduler.Request {
    const class = task.resourceClass();
    var request = accelerator_scheduler.Request{
        .class = class,
        .shared_memory_bytes = task.budget.shared_memory_bytes,
        .expected_cpu_ticks = DISPATCH_CPU_TICK_COST,
        .memory_bandwidth_units = memoryBandwidthUnitsFor(task),
    };
    switch (class) {
        .emergency_system_critical => {},
        .foreground_interactive => request.wants_gpu = task.ui_surface_id != null,
        .background_light => {
            request.estimated_energy_milliwatt_hours = estimatedDispatchEnergyMilliwattHours(task);
            request.defer_for_low_carbon_power = true;
        },
        .media_export => {
            request.wants_gpu = true;
            request.wants_media_engine = true;
        },
        .batch_compute => {
            request.wants_npu = true;
            request.estimated_energy_milliwatt_hours = estimatedDispatchEnergyMilliwattHours(task);
            request.defer_for_low_carbon_power = true;
        },
    }
    return request;
}

fn estimatedDispatchEnergyMilliwattHours(task: *const task_runtime.TaskRecord) u32 {
    const budget_units = @min(memoryBandwidthUnitsFor(task), std.math.maxInt(u32) - 1);
    return @as(u32, 1) + @as(u32, @intCast(budget_units));
}

fn memoryBandwidthUnitsFor(task: *const task_runtime.TaskRecord) usize {
    const bytes = task.budget.memory_bytes +| task.budget.shared_memory_bytes;
    if (bytes == std.math.maxInt(usize)) return bytes;
    return @max(@as(usize, 1), (bytes +| (MEMORY_BANDWIDTH_UNIT_BYTES - 1)) / MEMORY_BANDWIDTH_UNIT_BYTES);
}

fn requestedAcceleratorEngine(request: accelerator_scheduler.Request) accelerator_scheduler.Engine {
    if (request.wants_media_engine) return .media;
    if (request.wants_npu) return .npu;
    if (request.wants_gpu) return .gpu;
    return .cpu;
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

fn deadlineAfterDispatch(class: accelerator_scheduler.ResourceClass, now_ticks: u64) u64 {
    const next_quantum_tick = std.math.add(u64, now_ticks, DISPATCH_CPU_TICK_COST) catch std.math.maxInt(u64);
    return deadlineFromNow(class, next_quantum_tick);
}

fn expiredReadyCandidateBeats(
    slot: *const Slot,
    deadline: u64,
    selected_deadline: u64,
    selected_dispatch_count: u64,
    selected_last_dispatch_tick: u64,
) bool {
    if (deadline < selected_deadline) return true;
    if (deadline > selected_deadline) return false;
    if (slot.dispatch_count < selected_dispatch_count) return true;
    if (slot.dispatch_count > selected_dispatch_count) return false;
    return slot.last_dispatch_tick < selected_last_dispatch_tick;
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

fn completeTestHardwareEvidence() accelerator_scheduler.HardwareTelemetryEvidence {
    return .{
        .target_id = "test-hardware-telemetry",
        .reader_generation = 1,
        .acpi_observed = true,
        .thermal_observed = true,
        .battery_observed = true,
        .accelerator_observed = true,
        .grid_carbon_observed = true,
    };
}

fn schedulerTestUserspaceImage(service_task: bool) !task_runtime.ExecutableImageSpec {
    if (!builtin.is_test) @compileError("schedulerTestUserspaceImage is test-only");
    return if (service_task)
        try generated_image_fixtures.serviceImage()
    else
        try generated_image_fixtures.appImage();
}

fn createRunnableSchedulerTask(
    runtime: *task_runtime.Runtime,
    serial: u64,
    class: accelerator_scheduler.ResourceClass,
    label: []const u8,
    bundle_id: []const u8,
    ui_surface_id: ?u64,
) !*task_runtime.TaskRecord {
    return createRunnableSchedulerTaskWithBudget(
        runtime,
        serial,
        class,
        label,
        bundle_id,
        ui_surface_id,
        DISPATCH_CPU_TICK_COST,
    );
}

fn createRunnableSchedulerTaskWithBudget(
    runtime: *task_runtime.Runtime,
    serial: u64,
    class: accelerator_scheduler.ResourceClass,
    label: []const u8,
    bundle_id: []const u8,
    ui_surface_id: ?u64,
    cpu_time_ticks: u64,
) !*task_runtime.TaskRecord {
    _ = label;
    const service_task = class == .emergency_system_critical;
    var image = try schedulerTestUserspaceImage(service_task);
    return runtime.createTask(.{
        .owner = .{
            .kind = if (service_task) .service else .app,
            .serial = serial,
        },
        .component_class = if (service_task) .service_component else .app_component,
        .budget = .{
            .cpu_time_ticks = cpu_time_ticks,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = class,
            .background_allowed = class == .background_light or class == .batch_compute,
        },
        .ui_surface_id = ui_surface_id,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = serial,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = bundle_id,
        },
        .userspace_image = &image,
    });
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

test "userspace scheduler unlinks ready queue slots through prev links" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const first_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 11 },
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
        .owner = .{ .kind = .app, .serial = 12 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_TASK_SHARED_MEMORY_BYTES,
        },
        .local_only = true,
    });
    const third_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 13 },
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
    try std.testing.expect(scheduler.registerTask(second_task.id));
    try std.testing.expect(scheduler.registerTask(third_task.id));

    const first_index = scheduler.slots.slotIndexOf(first_task.id).?;
    const second_index = scheduler.slots.slotIndexOf(second_task.id).?;
    const third_index = scheduler.slots.slotIndexOf(third_task.id).?;
    const queue_index = resourceClassIndex(.foreground_interactive);
    try std.testing.expectEqual(first_index, scheduler.ready_heads[queue_index]);
    try std.testing.expectEqual(third_index, scheduler.ready_tails[queue_index]);
    try std.testing.expectEqual(first_index, scheduler.slots.slots[second_index].prev_ready_index);
    try std.testing.expectEqual(third_index, scheduler.slots.slots[second_index].next_ready_index);

    try std.testing.expect(scheduler.parkTaskUntilEvent(second_task.id));
    try std.testing.expectEqual(@as(usize, 2), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(third_index, scheduler.slots.slots[first_index].next_ready_index);
    try std.testing.expectEqual(first_index, scheduler.slots.slots[third_index].prev_ready_index);
    try std.testing.expectEqual(no_index, scheduler.slots.slots[second_index].prev_ready_index);
    try std.testing.expectEqual(no_index, scheduler.slots.slots[second_index].next_ready_index);

    try std.testing.expect(scheduler.unregisterTask(first_task.id));
    try std.testing.expectEqual(third_index, scheduler.ready_heads[queue_index]);
    try std.testing.expectEqual(third_index, scheduler.ready_tails[queue_index]);
    try std.testing.expectEqual(no_index, scheduler.slots.slots[third_index].prev_ready_index);
}

test "userspace scheduler dispatches resource ready queues by priority" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const background_image = try schedulerTestUserspaceImage(false);
    const foreground_image = try schedulerTestUserspaceImage(false);
    const background = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 3 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
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
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
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

    const image = try schedulerTestUserspaceImage(false);
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
    const duplicate_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 8,
        .deadline_tick = TEST_ACCELERATOR_DEADLINE_TICKS,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expectEqual(gpu_claim, duplicate_gpu_claim);
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
    try std.testing.expect(scheduler.grantNextAcceleratorClaim(.media, 8) == null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .emulator,
        .observed_tick = 9,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    const granted = scheduler.grantNextAcceleratorClaim(.media, 9).?;
    try std.testing.expectEqual(media_claim, granted.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.media_export));
}

test "userspace scheduler requires observed platform telemetry before waking hardware queues" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceState(.{
        .gpu_available = false,
        .media_available = false,
    });

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 20 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .media_export,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 20,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.media-required",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }, true));

    try std.testing.expect(!scheduler.runNext(1));
    const denied_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), denied_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), denied_slot.denied_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.accelerator_unavailable, denied_slot.last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDenialCount(.media));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.media_export));

    scheduler.configureResourceState(.{ .media_available = true });
    try std.testing.expect(!scheduler.runNext(2));
    const synthetic_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), synthetic_slot.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDenialCount(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 2,
        .media_available = true,
    });
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.resource_hardware_evidence_complete);
    try std.testing.expect(!scheduler.runNext(2));
    const partial_hardware_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), partial_hardware_slot.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(2, 20, 3, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(512),
        .gpu_driver_online = false,
        .npu_driver_online = false,
        .media_driver_online = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.runNext(3));
    const dispatched_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, dispatched_slot.last_dispatch_engine);
    try std.testing.expect(dispatched_slot.last_dispatch_zero_copy);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDispatchCount(.media));
}

test "userspace scheduler ignores stale observed telemetry samples" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 10,
        .gpu_available = false,
        .npu_available = false,
        .media_available = false,
        .grid_carbon_intensity_grams_per_kwh = 500,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 9,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .grid_carbon_intensity_grams_per_kwh = 100,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    try std.testing.expectEqual(@as(u64, 10), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(!scheduler.resource_state.gpu_available);
    try std.testing.expect(!scheduler.resource_state.npu_available);
    try std.testing.expectEqual(@as(u16, 500), scheduler.resource_state.grid_carbon_intensity_grams_per_kwh);

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 11,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .grid_carbon_intensity_grams_per_kwh = 100,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    try std.testing.expectEqual(@as(u64, 11), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    try std.testing.expectEqual(@as(u16, 100), scheduler.resource_state.grid_carbon_intensity_grams_per_kwh);
}

test "userspace scheduler delays on memory bandwidth before npu dispatch" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceState(.{
        .memory_bandwidth_units = 1,
        .npu_available = true,
    });

    const image = try schedulerTestUserspaceImage(false);
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 21 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = units.kibibytes(128),
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .batch_compute,
            .background_allowed = true,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 21,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.npu-batch",
        },
        .userspace_image = &image,
    });

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.configureTaskDispatchRequest(task.id, .{
        .class = .batch_compute,
        .wants_npu = true,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
        .memory_bandwidth_units = 256,
    }, false));

    try std.testing.expect(!scheduler.runNext(1));
    const delayed_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), delayed_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), delayed_slot.delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.memory_bandwidth, delayed_slot.last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));

    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(3, 21, 2, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .gpu_driver_online = false,
        .npu_driver_online = true,
        .media_driver_online = false,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.runNext(2));
    const dispatched_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, dispatched_slot.last_dispatch_engine);
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDispatchCount(.npu));
}

test "userspace scheduler derives low-carbon deferral for batch tasks" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceState(.{
        .npu_available = true,
        .grid_carbon_intensity_grams_per_kwh = 620,
    });

    const task = try createRunnableSchedulerTask(
        &runtime,
        221,
        .batch_compute,
        "carbon-batch",
        "app.example.carbon-batch",
        null,
    );
    try std.testing.expect(scheduler.registerTask(task.id));
    const initial_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expect(initial_slot.dispatch_request.defer_for_low_carbon_power);
    try std.testing.expect(initial_slot.dispatch_request.estimated_energy_milliwatt_hours != 0);

    try std.testing.expect(!scheduler.runNext(1));
    const delayed_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), delayed_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), delayed_slot.delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.carbon_aware_delay, delayed_slot.last_dispatch_reason);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));

    try std.testing.expect(!scheduler.runNext(1));
    const same_tick_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), same_tick_slot.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), same_tick_slot.delayed_dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 2,
        .grid_carbon_intensity_grams_per_kwh = 180,
        .npu_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    try std.testing.expect(!scheduler.runNext(2));
    const dispatched_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 1), dispatched_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, dispatched_slot.last_dispatch_engine);
    try std.testing.expectEqual(@as(u64, 1), scheduler.engineDispatchCount(.npu));
}

test "userspace scheduler applies thermal and battery decisions to live dispatch" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    const foreground_image = try schedulerTestUserspaceImage(false);
    const foreground = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 22 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .foreground_interactive,
        },
        .ui_surface_id = 4,
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 22,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.thermal-ui",
        },
        .userspace_image = &foreground_image,
    });
    try std.testing.expect(scheduler.registerTask(foreground.id));
    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(22, 220, 101, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(512),
        .thermal_milli_celsius = 91_000,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expectEqual(accelerator_scheduler.TelemetrySource.hardware, scheduler.resource_telemetry_source);
    try std.testing.expectEqual(@as(u64, 101), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(!scheduler.runNext(1));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, foreground_slot.last_dispatch_engine);
    try std.testing.expect(foreground_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, foreground_slot.last_dispatch_reason);

    const media_image = try schedulerTestUserspaceImage(false);
    const media_task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 23 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = DISPATCH_CPU_TICK_COST * 2,
            .memory_bytes = TEST_TASK_MEMORY_BYTES,
            .endpoint_slots = TEST_TASK_ENDPOINT_SLOTS,
            .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
            .resource_class = .media_export,
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 23,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.example.battery-media",
        },
        .userspace_image = &media_image,
    });
    try std.testing.expect(scheduler.registerTask(media_task.id));
    try provider.observeLive(220, 102, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(512),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 15,
        .battery_charging = false,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 102), scheduler.resource_telemetry_observed_tick);
    try std.testing.expect(!scheduler.runNext(2));
    const media_slot = scheduler.slots.getConst(media_task.id).?;
    try std.testing.expectEqual(@as(u64, 1), media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, media_slot.last_dispatch_engine);
    try std.testing.expect(media_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, media_slot.last_dispatch_reason);
}

test "userspace scheduler applies booted live telemetry across every resource class" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const critical = try createRunnableSchedulerTask(&runtime, 30, .emergency_system_critical, "critical", "svc.example.critical", null);
    const foreground = try createRunnableSchedulerTask(&runtime, 31, .foreground_interactive, "foreground", "app.example.foreground-live", 31);
    const media = try createRunnableSchedulerTask(&runtime, 32, .media_export, "media", "app.example.media-live", null);
    const background = try createRunnableSchedulerTask(&runtime, 33, .background_light, "background", "app.example.background-live", null);
    const batch = try createRunnableSchedulerTask(&runtime, 34, .batch_compute, "batch", "app.example.batch-live", null);

    const task_ids = [_]u64{ critical.id, foreground.id, media.id, background.id, batch.id };
    for (task_ids) |task_id| {
        try std.testing.expect(scheduler.registerTask(task_id));
    }
    try std.testing.expect(scheduler.configureTaskDispatchRequest(background.id, .{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }, false));

    var provider = try accelerator_scheduler.BootedPlatformTelemetryProvider.initForBootedService(30, 300, 10, .{
        .total_cpu_budget_ticks = 20_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .thermal_milli_celsius = 91_000,
        .battery_percent = 80,
        .battery_charging = true,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    try std.testing.expect(!scheduler.runNext(10));
    const critical_slot = scheduler.slots.getConst(critical.id).?;
    try std.testing.expectEqual(@as(u64, 1), critical_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.normal, critical_slot.last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(11));
    const foreground_slot = scheduler.slots.getConst(foreground.id).?;
    try std.testing.expectEqual(@as(u64, 1), foreground_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, foreground_slot.last_dispatch_engine);
    try std.testing.expect(foreground_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, foreground_slot.last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(12));
    const media_slot = scheduler.slots.getConst(media.id).?;
    try std.testing.expectEqual(@as(u64, 1), media_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, media_slot.last_dispatch_engine);
    try std.testing.expect(media_slot.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, media_slot.last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(13));
    const thermally_blocked_background = scheduler.slots.getConst(background.id).?;
    const thermally_blocked_batch = scheduler.slots.getConst(batch.id).?;
    try std.testing.expectEqual(@as(u64, 0), thermally_blocked_background.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), thermally_blocked_background.delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, thermally_blocked_background.last_dispatch_reason);
    try std.testing.expectEqual(@as(u64, 0), thermally_blocked_batch.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), thermally_blocked_batch.delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, thermally_blocked_batch.last_dispatch_reason);

    try provider.observeLive(300, 14, .{
        .total_cpu_budget_ticks = 20_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 12,
        .battery_charging = false,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .privacy_sensitive_task_count = 1,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    try std.testing.expect(!scheduler.runNext(14));
    const privacy_limited_background = scheduler.slots.getConst(background.id).?;
    try std.testing.expectEqual(@as(u64, 1), privacy_limited_background.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, privacy_limited_background.last_dispatch_engine);
    try std.testing.expect(privacy_limited_background.last_dispatch_degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.privacy_mode, privacy_limited_background.last_dispatch_reason);

    try std.testing.expect(!scheduler.runNext(15));
    const battery_blocked_batch = scheduler.slots.getConst(batch.id).?;
    try std.testing.expectEqual(@as(u64, 0), battery_blocked_batch.dispatch_count);
    try std.testing.expectEqual(@as(u64, 2), battery_blocked_batch.delayed_dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, battery_blocked_batch.last_dispatch_reason);

    try provider.observeLive(300, 16, .{
        .total_cpu_budget_ticks = 20_000,
        .memory_capacity_bytes = units.mebibytes(1),
        .thermal_milli_celsius = 45_000,
        .battery_percent = 80,
        .battery_charging = true,
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    scheduler.configureResourceTelemetryFromProvider(provider.telemetryProvider());

    try std.testing.expect(!scheduler.runNext(16));
    const batch_slot = scheduler.slots.getConst(batch.id).?;
    try std.testing.expectEqual(@as(u64, 1), batch_slot.dispatch_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, batch_slot.last_dispatch_engine);
}

test "userspace scheduler sustained load gate bounds background and batch starvation" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 256,
        .memory_bandwidth_units = 1024,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const foreground = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        240,
        .foreground_interactive,
        "sustained-foreground",
        "app.example.sustained-foreground",
        240,
        DISPATCH_CPU_TICK_COST * 160,
    );
    const background = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        241,
        .background_light,
        "sustained-background",
        "app.example.sustained-background",
        null,
        DISPATCH_CPU_TICK_COST * 8,
    );
    const batch = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        242,
        .batch_compute,
        "sustained-batch",
        "app.example.sustained-batch",
        null,
        DISPATCH_CPU_TICK_COST * 8,
    );

    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(batch.id));

    var first_background_dispatch_tick: u64 = 0;
    var first_batch_dispatch_tick: u64 = 0;
    var now_ticks: u64 = 1_000;
    while (now_ticks <= BATCH_DEADLINE_DELTA_TICKS + 2_000) : (now_ticks += 1_000) {
        _ = scheduler.runNext(now_ticks);
        const background_stats = scheduler.taskDispatchStats(background.id).?;
        const batch_stats = scheduler.taskDispatchStats(batch.id).?;
        if (first_background_dispatch_tick == 0 and background_stats.dispatch_count != 0) {
            first_background_dispatch_tick = background_stats.last_dispatch_tick;
        }
        if (first_batch_dispatch_tick == 0 and batch_stats.dispatch_count != 0) {
            first_batch_dispatch_tick = batch_stats.last_dispatch_tick;
        }
    }

    const foreground_stats = scheduler.taskDispatchStats(foreground.id).?;
    const background_stats = scheduler.taskDispatchStats(background.id).?;
    const batch_stats = scheduler.taskDispatchStats(batch.id).?;
    try std.testing.expect(foreground_stats.dispatch_count > background_stats.dispatch_count);
    try std.testing.expect(background_stats.dispatch_count > 0);
    try std.testing.expect(batch_stats.dispatch_count > 0);
    try std.testing.expect(first_background_dispatch_tick <= BACKGROUND_DEADLINE_DELTA_TICKS);
    try std.testing.expect(first_batch_dispatch_tick <= BATCH_DEADLINE_DELTA_TICKS + 1_000);
    try std.testing.expectEqual(@as(u64, 0), background_stats.missed_deadline_count);
    try std.testing.expectEqual(@as(u64, 0), batch_stats.missed_deadline_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, batch_stats.last_dispatch_engine);
}

test "userspace scheduler breaks expired lower-class ties by service debt" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);
    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 1,
        .npu_available = true,
        .cpu_budget_ticks = DISPATCH_CPU_TICK_COST * 16,
        .memory_bandwidth_units = 1024,
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const background = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        250,
        .background_light,
        "tie-background",
        "app.example.tie-background",
        null,
        DISPATCH_CPU_TICK_COST * 2,
    );
    const batch = try createRunnableSchedulerTaskWithBudget(
        &runtime,
        251,
        .batch_compute,
        "tie-batch",
        "app.example.tie-batch",
        null,
        DISPATCH_CPU_TICK_COST * 2,
    );

    try std.testing.expect(scheduler.registerTask(background.id));
    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.wakeTask(background.id, .timer, 10, 20));
    try std.testing.expect(scheduler.wakeTask(batch.id, .timer, 10, 100));

    try std.testing.expect(!scheduler.runNext(20));
    try std.testing.expectEqual(@as(u64, 1), scheduler.taskDispatchStats(background.id).?.dispatch_count);
    try std.testing.expectEqual(@as(u64, 0), scheduler.taskDispatchStats(batch.id).?.dispatch_count);

    try std.testing.expect(scheduler.wakeTask(background.id, .timer, 21, 30));
    try std.testing.expect(scheduler.wakeTask(batch.id, .timer, 21, 30));
    try std.testing.expect(!scheduler.runNext(30));

    const background_stats = scheduler.taskDispatchStats(background.id).?;
    const batch_stats = scheduler.taskDispatchStats(batch.id).?;
    try std.testing.expectEqual(@as(u64, 1), background_stats.dispatch_count);
    try std.testing.expectEqual(@as(u64, 1), batch_stats.dispatch_count);
    try std.testing.expectEqual(@as(u64, 0), batch_stats.missed_deadline_count);
    try std.testing.expectEqual(accelerator_scheduler.Engine.npu, batch_stats.last_dispatch_engine);
}

test "userspace scheduler thermal pressure gates batch queues without scanning task slots" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const image = try schedulerTestUserspaceImage(false);
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

    const image = try schedulerTestUserspaceImage(false);
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
