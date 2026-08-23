const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const accelerator_scheduler = @import("accelerator_scheduler.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const capability = @import("../kernel_api/capability.zig");
const native_util = @import("../core/util.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_flags = @import("userspace_flags.zig");
const generated_image_fixtures = if (builtin.is_test) @import("generated_image_fixtures.zig") else struct {};
const root = @import("root");

const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const DISPATCH_CPU_TICK_COST: u64 = 1_000;
pub const RESOURCE_CLASS_COUNT: usize = std.meta.fields(accelerator_scheduler.ResourceClass).len;
pub const ENGINE_COUNT: usize = std.meta.fields(accelerator_scheduler.Engine).len;
pub const MAX_ACCELERATOR_CLAIMS: usize = task_runtime.MAX_TASKS;
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
const arena_no_index = indexed_arena.no_index;
pub const QueueSlotIndex = u8;
pub const QUEUE_NO_INDEX: QueueSlotIndex = @intCast(task_runtime.MAX_TASKS);
pub const COMPACT_QUEUE_METADATA = true;
pub const STEADY_UI_ELIGIBILITY_CATALOG_LOOKUPS: u8 = 0;
pub const SCHEDULED_TASK_INDEX_LOOKUPS_PER_DISPATCH: u8 = 0;

comptime {
    if (task_runtime.MAX_TASKS > std.math.maxInt(QueueSlotIndex) or
        MAX_ACCELERATOR_CLAIMS > std.math.maxInt(QueueSlotIndex))
    {
        @compileError("userspace scheduler queues no longer fit compact slot indexes");
    }
}

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
    event_wait_count: u64,
    ui_state_update_count: u64,
    last_ui_state_revision: u64,
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
    task_handle: task_runtime.TaskHandle = .{},
    mapping_handle: userspace_executor.MappingHandle = .{},
    resource_class: accelerator_scheduler.ResourceClass = .foreground_interactive,
    queued_ready: bool = false,
    prev_ready_index: QueueSlotIndex = QUEUE_NO_INDEX,
    next_ready_index: QueueSlotIndex = QUEUE_NO_INDEX,
    dispatch_count: u64 = 0,
    event_wait_count: u64 = 0,
    ui_state_update_count: u64 = 0,
    last_ui_state_revision: u64 = 0,
    owns_ui_surface: bool = false,
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

    comptime {
        if (@sizeOf(@This()) > SCHEDULER_SLOT_SIZE_CEILING_BYTES) {
            @compileError("userspace scheduler slot exceeds its compact size ceiling");
        }
    }
};

const AcceleratorClaimSlot = struct {
    in_use: bool = false,
    record: AcceleratorClaimRecord = zeroAcceleratorClaim(),
    prev_claim_index: QueueSlotIndex = QUEUE_NO_INDEX,
    next_claim_index: QueueSlotIndex = QUEUE_NO_INDEX,
    prev_deadline_index: QueueSlotIndex = QUEUE_NO_INDEX,
    next_deadline_index: QueueSlotIndex = QUEUE_NO_INDEX,

    comptime {
        if (@sizeOf(@This()) > ACCELERATOR_CLAIM_SLOT_SIZE_CEILING_BYTES) {
            @compileError("userspace accelerator claim slot exceeds its compact size ceiling");
        }
    }
};

const SchedulerSlotArena = indexed_arena.IndexedArenaWithKey(u64, Slot, task_runtime.MAX_TASKS, task_runtime.MAX_TASKS * 2, schedulerSlotTaskId);
const AcceleratorClaimArena = indexed_arena.IndexedArenaWithKey(u64, AcceleratorClaimSlot, MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS * 2, acceleratorClaimSlotId);
const AcceleratorClaimTaskIndex = indexed_arena.MultimapIndex(MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS, MAX_ACCELERATOR_CLAIMS * 2);
const heap_backed_accelerator_claims = builtin.target.os.tag == .freestanding;
pub const SCHEDULER_SLOT_SIZE_CEILING_BYTES: usize = 208;
pub const ACCELERATOR_CLAIM_SLOT_SIZE_CEILING_BYTES: usize = 56;
pub const ACCELERATOR_CLAIM_BACKING_SIZE_CEILING_BYTES: usize = 15_912;
pub const SCHEDULER_SIZE_CEILING_BYTES: usize = if (heap_backed_accelerator_claims) 30_568 else 46_472;

pub const AcceleratorClaimBacking = struct {
    claims: AcceleratorClaimArena = AcceleratorClaimArena.init(),
    task_index: AcceleratorClaimTaskIndex = AcceleratorClaimTaskIndex.init(),

    fn init() AcceleratorClaimBacking {
        return .{};
    }

    fn initializeAllocated(self: *AcceleratorClaimBacking) void {
        @memset(std.mem.asBytes(self), 0);
        self.claims.free_head = indexed_arena.reusableNoIndex(MAX_ACCELERATOR_CLAIMS);
        const CompactIndex = @FieldType(AcceleratorClaimTaskIndex, "free_bucket_head");
        const compact_no_index: CompactIndex = @intCast(MAX_ACCELERATOR_CLAIMS);
        for (&self.task_index.links) |*link| link.bucket = compact_no_index;
        self.task_index.free_bucket_head = compact_no_index;
    }

    comptime {
        if (@sizeOf(@This()) > ACCELERATOR_CLAIM_BACKING_SIZE_CEILING_BYTES) {
            @compileError("userspace accelerator claim backing exceeds its compact size ceiling");
        }
    }
};

const AcceleratorClaimBackingStorage = if (heap_backed_accelerator_claims) ?*AcceleratorClaimBacking else AcceleratorClaimBacking;

pub const Scheduler = struct {
    executor: *userspace_executor.Executor,
    executor_binding_claimed: bool = false,
    initialized: bool = false,
    catalog_ptr: ?*userspace_loader.Catalog = null,
    runtime_ptr: ?*task_runtime.Runtime = null,
    capability_table_ptr: ?*const capability.CapabilityTable = null,
    slots: SchedulerSlotArena = SchedulerSlotArena.init(),
    ready_heads: [RESOURCE_CLASS_COUNT]QueueSlotIndex = [_]QueueSlotIndex{QUEUE_NO_INDEX} ** RESOURCE_CLASS_COUNT,
    ready_tails: [RESOURCE_CLASS_COUNT]QueueSlotIndex = [_]QueueSlotIndex{QUEUE_NO_INDEX} ** RESOURCE_CLASS_COUNT,
    ready_counts: [RESOURCE_CLASS_COUNT]QueueSlotIndex = [_]QueueSlotIndex{0} ** RESOURCE_CLASS_COUNT,
    ready_task_count: QueueSlotIndex = 0,
    accelerator_claim_backing: AcceleratorClaimBackingStorage = if (heap_backed_accelerator_claims) null else AcceleratorClaimBacking.init(),
    accelerator_claim_heads: [ENGINE_COUNT]QueueSlotIndex = [_]QueueSlotIndex{QUEUE_NO_INDEX} ** ENGINE_COUNT,
    accelerator_claim_tails: [ENGINE_COUNT]QueueSlotIndex = [_]QueueSlotIndex{QUEUE_NO_INDEX} ** ENGINE_COUNT,
    accelerator_deadline_heads: [ENGINE_COUNT]QueueSlotIndex = [_]QueueSlotIndex{QUEUE_NO_INDEX} ** ENGINE_COUNT,
    accelerator_deadline_tails: [ENGINE_COUNT]QueueSlotIndex = [_]QueueSlotIndex{QUEUE_NO_INDEX} ** ENGINE_COUNT,
    accelerator_claim_counts: [ENGINE_COUNT]QueueSlotIndex = [_]QueueSlotIndex{0} ** ENGINE_COUNT,
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
    event_wait_marker_printed: bool = false,
    ui_state_marker_printed: bool = false,

    comptime {
        if (@sizeOf(@This()) > SCHEDULER_SIZE_CEILING_BYTES) {
            @compileError("userspace scheduler exceeds its compact resident size ceiling");
        }
    }

    pub fn init(executor: *userspace_executor.Executor) Scheduler {
        return .{ .executor = executor };
    }

    pub fn initializeAllocated(self: *Scheduler, executor: *userspace_executor.Executor) void {
        @memset(std.mem.asBytes(self), 0);
        self.executor = executor;
        self.slots.free_head = indexed_arena.reusableNoIndex(task_runtime.MAX_TASKS);
        for (&self.ready_heads) |*head| head.* = QUEUE_NO_INDEX;
        for (&self.ready_tails) |*tail| tail.* = QUEUE_NO_INDEX;
        for (&self.accelerator_claim_heads) |*head| head.* = QUEUE_NO_INDEX;
        for (&self.accelerator_claim_tails) |*tail| tail.* = QUEUE_NO_INDEX;
        for (&self.accelerator_deadline_heads) |*head| head.* = QUEUE_NO_INDEX;
        for (&self.accelerator_deadline_tails) |*tail| tail.* = QUEUE_NO_INDEX;
        self.next_accelerator_claim_id = 1;
        self.resource_state = .{};
        self.resource_telemetry_source = .synthetic;
    }

    fn acceleratorClaimBacking(self: *Scheduler) ?*AcceleratorClaimBacking {
        if (comptime heap_backed_accelerator_claims) return self.accelerator_claim_backing;
        return &self.accelerator_claim_backing;
    }

    fn acceleratorClaimBackingConst(self: *const Scheduler) ?*const AcceleratorClaimBacking {
        if (comptime heap_backed_accelerator_claims) return self.accelerator_claim_backing;
        return &self.accelerator_claim_backing;
    }

    fn ensureAcceleratorClaimBacking(self: *Scheduler) ?*AcceleratorClaimBacking {
        if (self.acceleratorClaimBacking()) |backing| return backing;
        if (comptime heap_backed_accelerator_claims) {
            const allocation = kernel_memory.kmalloc(@sizeOf(AcceleratorClaimBacking)) orelse return null;
            const backing: *AcceleratorClaimBacking = @ptrCast(@alignCast(allocation));
            backing.initializeAllocated();
            self.accelerator_claim_backing = backing;
            return backing;
        }
        return &self.accelerator_claim_backing;
    }

    fn releaseAcceleratorClaimBacking(self: *Scheduler) void {
        if (comptime heap_backed_accelerator_claims) {
            if (self.accelerator_claim_backing) |backing| {
                @memset(std.mem.asBytes(backing), 0);
                kernel_memory.kfree(@ptrCast(backing));
                self.accelerator_claim_backing = null;
            }
        }
    }

    pub fn deinit(self: *Scheduler) void {
        const runtime = self.runtime_ptr;
        if (builtin.target.os.tag == .freestanding) {
            if (runtime) |bound_runtime| {
                if (!bound_runtime.unbindAddressSpaceRetirementSink(self.executor.retirementSink())) {
                    native_util.impossibleByInvariant("userspace runtime retirement ownership changed while bound");
                }
            }
        }
        if (self.executor_binding_claimed) {
            self.executor.deinit();
            const bound_runtime = runtime orelse
                native_util.impossibleByInvariant("userspace executor ownership has no runtime");
            if (!self.executor.releaseRuntimeBinding(self, bound_runtime)) {
                native_util.impossibleByInvariant("userspace executor ownership changed while bound");
            }
        }
        self.executor_binding_claimed = false;
        self.initialized = false;
        self.catalog_ptr = null;
        self.runtime_ptr = null;
        self.capability_table_ptr = null;
        self.releaseAcceleratorClaimBacking();
    }

    pub fn reset(self: *Scheduler) void {
        const executor = self.executor;
        self.deinit();
        if (comptime builtin.target.os.tag == .freestanding) {
            self.initializeAllocated(executor);
        } else {
            self.* = Scheduler.init(executor);
        }
    }

    pub fn bind(
        self: *Scheduler,
        catalog: *userspace_loader.Catalog,
        runtime: *task_runtime.Runtime,
        capability_table: *const capability.CapabilityTable,
    ) void {
        if (self.initialized or self.runtime_ptr != null) self.reset();
        if (!self.executor.claimRuntimeBinding(self, runtime)) {
            native_util.impossibleByInvariant("userspace executor already has an owner");
        }
        self.executor_binding_claimed = true;
        if (builtin.target.os.tag == .freestanding) {
            if (!runtime.bindAddressSpaceRetirementSink(self.executor.retirementSink())) {
                _ = self.executor.releaseRuntimeBinding(self, runtime);
                self.executor_binding_claimed = false;
                native_util.impossibleByInvariant("userspace runtime already has an address-space owner");
            }
        }
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
        const task_handle = runtime.taskHandle(task_id) orelse return false;
        const task = runtime.findByHandle(task_handle, task_id) orelse return false;
        const catalog = self.catalog_ptr orelse return false;
        const owns_ui_surface = taskUiPresentationEligible(catalog, task);
        const slot_index = self.slots.reserveIndex(task_id) orelse return false;
        const slot = &self.slots.slots[slot_index];
        slot.task_id = task_id;
        slot.task_handle = task_handle;
        slot.resource_class = task.resourceClass();
        slot.dispatch_request = deriveDispatchRequest(task);
        slot.dispatch_request_configured = false;
        slot.require_accelerator = false;
        slot.owns_ui_surface = owns_ui_surface;
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
        const task_handle = runtime.taskHandle(task_id) orelse return false;
        const task = runtime.findByHandle(task_handle, task_id) orelse return false;
        const slot_index = self.slots.slotIndexOf(task_id) orelse return false;
        const slot = &self.slots.slots[slot_index];
        if (slot.queued_ready and slot.resource_class != task.resourceClass()) {
            self.unlinkReadyIndex(slot_index);
        }
        if (!slot.task_handle.eql(task_handle)) slot.mapping_handle = .{};
        slot.task_handle = task_handle;
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
        return @intCast(self.ready_counts[resourceClassIndex(class)]);
    }

    pub fn hasReadyTasks(self: *const Scheduler) bool {
        return self.ready_task_count != 0;
    }

    pub fn taskDispatchStats(self: *const Scheduler, task_id: u64) ?TaskDispatchStats {
        const slot = self.slots.getConst(task_id) orelse return null;
        return .{
            .task_id = slot.task_id,
            .resource_class = slot.resource_class,
            .queued_ready = slot.queued_ready,
            .dispatch_count = slot.dispatch_count,
            .event_wait_count = slot.event_wait_count,
            .ui_state_update_count = slot.ui_state_update_count,
            .last_ui_state_revision = slot.last_ui_state_revision,
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

        const backing = self.ensureAcceleratorClaimBacking() orelse return null;
        const claim_id = self.nextAcceleratorClaimId() orelse return null;
        const claim_index = backing.claims.reserveIndex(claim_id) orelse return null;
        const slot = &backing.claims.slots[claim_index];
        slot.record = .{
            .id = claim_id,
            .task_id = request.task_id,
            .engine = request.engine,
            .resource_class = request.resource_class,
            .requested_at_tick = request.requested_at_tick,
            .deadline_tick = request.deadline_tick,
            .shared_memory_bytes = request.shared_memory_bytes,
        };
        if (!backing.task_index.append(acceleratorClaimTaskKey(request.task_id), claim_index)) {
            _ = backing.claims.removeIndex(claim_index);
            return null;
        }
        self.insertAcceleratorClaimIndex(request.engine, claim_index);
        self.next_accelerator_claim_id +%= 1;
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
        const claim_index = self.popBestAcceleratorClaimIndex(engine, now_ticks) orelse return null;
        const backing = self.acceleratorClaimBacking() orelse
            native_util.impossibleByInvariant("queued accelerator claim retains its backing");
        const record = backing.claims.slots[claim_index].record;
        _ = backing.claims.removeIndex(claim_index);
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
        return @intCast(self.accelerator_claim_counts[engineIndex(engine)]);
    }

    pub fn engineDispatchCount(self: *const Scheduler, engine: accelerator_scheduler.Engine) u64 {
        return self.engine_dispatch_counts[engineIndex(engine)];
    }

    pub fn engineDenialCount(self: *const Scheduler, engine: accelerator_scheduler.Engine) u64 {
        return self.engine_denial_counts[engineIndex(engine)];
    }

    pub fn executeTask(self: *Scheduler, task_id: u64, now_ticks: u64) userspace_executor.ExecutionOutcome {
        if (!self.initialized) return .unavailable;
        const runtime = self.runtime_ptr orelse return .unavailable;
        const task = runtime.findConst(task_id) orelse return .unavailable;
        var uncached_mapping_handle = userspace_executor.MappingHandle{};
        const mapping_handle = if (self.slots.get(task_id)) |slot|
            &slot.mapping_handle
        else
            &uncached_mapping_handle;
        return self.executePreparedTask(task, mapping_handle, now_ticks);
    }

    fn executePreparedTask(
        self: *Scheduler,
        task: *const task_runtime.TaskRecord,
        mapping_handle: *userspace_executor.MappingHandle,
        now_ticks: u64,
    ) userspace_executor.ExecutionOutcome {
        if (!self.initialized) return .unavailable;
        const catalog = self.catalog_ptr orelse return .unavailable;
        const runtime = self.runtime_ptr orelse return .unavailable;
        const capability_table = self.capability_table_ptr orelse return .unavailable;
        return self.executor.executeTask(catalog, runtime, capability_table, task, mapping_handle, now_ticks);
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
            const task = runtime.findByHandle(slot.task_handle, task_id) orelse {
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
                self.queuePendingAcceleratorWake(slot, task, now_ticks);
                self.last_dispatch_tick = now_ticks;
                return false;
            }

            const dispatch_memory_bandwidth_units = memoryBandwidthUnitsFor(task);
            self.accountDeadline(slot, now_ticks);
            const outcome = self.executePreparedTask(task, &slot.mapping_handle, now_ticks);
            const yielded = outcome.handedOff();
            self.last_dispatch_tick = now_ticks;
            slot.dispatch_count += 1;
            if (outcome == .wait_for_event) {
                slot.event_wait_count += 1;
                if (builtin.target.os.tag == .freestanding and !self.event_wait_marker_printed) {
                    common.printBootMarker(boot_markers.userspace_scheduler_event_wait_ready);
                    self.event_wait_marker_printed = true;
                }
            }
            const ui_revision = self.executor.lastYieldUiRevision();
            if (outcome.handedOff() and
                slot.owns_ui_surface and
                ui_revision > slot.last_ui_state_revision)
            {
                slot.last_ui_state_revision = ui_revision;
                slot.ui_state_update_count += 1;
                if (builtin.target.os.tag == .freestanding and !self.ui_state_marker_printed) {
                    common.printBootMarker(boot_markers.userspace_ui_state_ready);
                    self.ui_state_marker_printed = true;
                }
            }
            slot.last_dispatch_tick = now_ticks;
            slot.cpu_ticks_consumed += DISPATCH_CPU_TICK_COST;
            slot.cpu_budget_remaining_ticks -|= DISPATCH_CPU_TICK_COST;
            slot.memory_bandwidth_consumed_units = std.math.add(
                usize,
                slot.memory_bandwidth_consumed_units,
                dispatch_memory_bandwidth_units,
            ) catch std.math.maxInt(usize);
            self.accountDispatchResources(dispatch_memory_bandwidth_units, decision);
            if (builtin.target.os.tag == .freestanding and yielded and !self.active_marker_printed) {
                common.printBootMarker(boot_markers.userspace_scheduler_active);
                self.active_marker_printed = true;
            }
            if (runtime.findByHandle(slot.task_handle, task_id)) |updated_task| {
                if (!taskEligibleForPostDispatchRequeue(task_id, updated_task, slot)) return yielded;
                slot.resource_class = updated_task.resourceClass();
                if (!slot.dispatch_request_configured) slot.dispatch_request = deriveDispatchRequest(updated_task);
                slot.deadline_tick = deadlineAfterDispatch(slot.resource_class, now_ticks);
                if (executionRemainsReady(outcome)) {
                    _ = self.enqueueReadyIndex(index, slot.resource_class);
                }
            } else {
                _ = self.unregisterSlotIndex(index);
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
        slot.next_ready_index = QUEUE_NO_INDEX;
        if (self.ready_tails[queue_index] == QUEUE_NO_INDEX) {
            self.ready_heads[queue_index] = compactQueueIndex(slot_index);
        } else {
            self.slots.slots[self.ready_tails[queue_index]].next_ready_index = compactQueueIndex(slot_index);
        }
        self.ready_tails[queue_index] = compactQueueIndex(slot_index);
        self.ready_counts[queue_index] += 1;
        self.ready_task_count += 1;
        slot.queued_ready = true;
        return true;
    }

    fn popReadyIndex(self: *Scheduler, class: accelerator_scheduler.ResourceClass) ?usize {
        const queue_index = resourceClassIndex(class);
        const slot_index = self.ready_heads[queue_index];
        if (slot_index == QUEUE_NO_INDEX) return null;
        if (slot_index >= self.slots.slots.len) return null;

        const slot = &self.slots.slots[slot_index];
        const next = slot.next_ready_index;
        self.ready_heads[queue_index] = next;
        if (self.ready_heads[queue_index] == QUEUE_NO_INDEX) self.ready_tails[queue_index] = QUEUE_NO_INDEX;
        if (next != QUEUE_NO_INDEX) self.slots.slots[next].prev_ready_index = QUEUE_NO_INDEX;
        slot.prev_ready_index = QUEUE_NO_INDEX;
        slot.next_ready_index = QUEUE_NO_INDEX;
        if (slot.queued_ready) {
            slot.queued_ready = false;
            self.ready_counts[queue_index] -= 1;
            self.ready_task_count -= 1;
        }
        return @intCast(slot_index);
    }

    fn unlinkReadyIndex(self: *Scheduler, slot_index: usize) void {
        if (slot_index >= self.slots.slots.len) return;
        const target = &self.slots.slots[slot_index];
        if (!target.in_use or !target.queued_ready) return;

        const queue_index = resourceClassIndex(target.resource_class);
        const previous = target.prev_ready_index;
        const next = target.next_ready_index;

        if (previous == QUEUE_NO_INDEX) {
            self.ready_heads[queue_index] = next;
        } else {
            self.slots.slots[previous].next_ready_index = next;
        }
        if (next == QUEUE_NO_INDEX) {
            self.ready_tails[queue_index] = previous;
        } else {
            self.slots.slots[next].prev_ready_index = previous;
        }

        target.queued_ready = false;
        target.prev_ready_index = QUEUE_NO_INDEX;
        target.next_ready_index = QUEUE_NO_INDEX;
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
            if (head == QUEUE_NO_INDEX) continue;
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
            if (self.ready_heads[resourceClassIndex(class)] != QUEUE_NO_INDEX) return class;
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
            if (slot_index == QUEUE_NO_INDEX) continue;
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
        memory_bandwidth_units: usize,
        decision: accelerator_scheduler.Decision,
    ) void {
        self.engine_dispatch_counts[engineIndex(decision.engine)] += 1;
        self.resource_state.cpu_budget_ticks -|= DISPATCH_CPU_TICK_COST;
        self.resource_state.memory_bandwidth_units -|= memory_bandwidth_units;
    }

    fn queuePendingAcceleratorWake(
        self: *Scheduler,
        slot: *Slot,
        task: *const task_runtime.TaskRecord,
        now_ticks: u64,
    ) void {
        if (slot.pending_accelerator_claim_id != 0) return;
        const request = self.dispatchRequestFor(slot, task);
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
        return self.resource_telemetry_source == .hardware and self.resource_hardware_evidence_complete;
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

    fn insertAcceleratorClaimIndex(self: *Scheduler, engine: accelerator_scheduler.Engine, claim_index: usize) void {
        const backing = self.acceleratorClaimBacking() orelse
            native_util.impossibleByInvariant("accelerator claim insertion requires allocated backing");
        const queue_index = engineIndex(engine);
        const claim = &backing.claims.slots[claim_index];
        claim.prev_claim_index = QUEUE_NO_INDEX;
        claim.next_claim_index = QUEUE_NO_INDEX;
        claim.prev_deadline_index = QUEUE_NO_INDEX;
        claim.next_deadline_index = QUEUE_NO_INDEX;

        var current = self.accelerator_claim_heads[queue_index];
        while (current != QUEUE_NO_INDEX) : (current = backing.claims.slots[current].next_claim_index) {
            if (self.acceleratorClaimPriorityBeats(claim_index, @intCast(current))) {
                self.linkAcceleratorClaimBefore(queue_index, claim_index, @intCast(current));
                self.insertAcceleratorDeadlineIndex(queue_index, claim_index);
                self.accelerator_claim_counts[queue_index] += 1;
                return;
            }
        }

        if (self.accelerator_claim_tails[queue_index] == QUEUE_NO_INDEX) {
            self.accelerator_claim_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            claim.prev_claim_index = self.accelerator_claim_tails[queue_index];
            backing.claims.slots[self.accelerator_claim_tails[queue_index]].next_claim_index = compactQueueIndex(claim_index);
        }
        self.accelerator_claim_tails[queue_index] = compactQueueIndex(claim_index);
        self.insertAcceleratorDeadlineIndex(queue_index, claim_index);
        self.accelerator_claim_counts[queue_index] += 1;
    }

    fn linkAcceleratorClaimBefore(
        self: *Scheduler,
        queue_index: usize,
        claim_index: usize,
        before_index: usize,
    ) void {
        const backing = self.acceleratorClaimBacking() orelse
            native_util.impossibleByInvariant("linked accelerator claims retain their backing");
        const previous = backing.claims.slots[before_index].prev_claim_index;
        backing.claims.slots[claim_index].prev_claim_index = previous;
        backing.claims.slots[claim_index].next_claim_index = compactQueueIndex(before_index);
        backing.claims.slots[before_index].prev_claim_index = compactQueueIndex(claim_index);
        if (previous == QUEUE_NO_INDEX) {
            self.accelerator_claim_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            backing.claims.slots[previous].next_claim_index = compactQueueIndex(claim_index);
        }
    }

    fn insertAcceleratorDeadlineIndex(self: *Scheduler, queue_index: usize, claim_index: usize) void {
        const backing = self.acceleratorClaimBacking() orelse
            native_util.impossibleByInvariant("accelerator deadline insertion requires allocated backing");
        const claim = &backing.claims.slots[claim_index];
        if (claim.record.deadline_tick == 0) return;

        var current = self.accelerator_deadline_heads[queue_index];
        while (current != QUEUE_NO_INDEX) : (current = backing.claims.slots[current].next_deadline_index) {
            if (self.acceleratorClaimDeadlineBeats(claim_index, @intCast(current))) {
                self.linkAcceleratorDeadlineBefore(queue_index, claim_index, @intCast(current));
                return;
            }
        }

        if (self.accelerator_deadline_tails[queue_index] == QUEUE_NO_INDEX) {
            self.accelerator_deadline_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            claim.prev_deadline_index = self.accelerator_deadline_tails[queue_index];
            backing.claims.slots[self.accelerator_deadline_tails[queue_index]].next_deadline_index = compactQueueIndex(claim_index);
        }
        self.accelerator_deadline_tails[queue_index] = compactQueueIndex(claim_index);
    }

    fn linkAcceleratorDeadlineBefore(
        self: *Scheduler,
        queue_index: usize,
        claim_index: usize,
        before_index: usize,
    ) void {
        const backing = self.acceleratorClaimBacking() orelse
            native_util.impossibleByInvariant("linked accelerator deadlines retain their backing");
        const previous = backing.claims.slots[before_index].prev_deadline_index;
        backing.claims.slots[claim_index].prev_deadline_index = previous;
        backing.claims.slots[claim_index].next_deadline_index = compactQueueIndex(before_index);
        backing.claims.slots[before_index].prev_deadline_index = compactQueueIndex(claim_index);
        if (previous == QUEUE_NO_INDEX) {
            self.accelerator_deadline_heads[queue_index] = compactQueueIndex(claim_index);
        } else {
            backing.claims.slots[previous].next_deadline_index = compactQueueIndex(claim_index);
        }
    }

    fn popBestAcceleratorClaimIndex(
        self: *Scheduler,
        engine: accelerator_scheduler.Engine,
        now_ticks: u64,
    ) ?usize {
        const backing = self.acceleratorClaimBacking() orelse return null;
        const queue_index = engineIndex(engine);
        const deadline_head = self.accelerator_deadline_heads[queue_index];
        const best = if (deadline_head != QUEUE_NO_INDEX and
            claimDeadlineExpired(backing.claims.slots[deadline_head].record, now_ticks))
            deadline_head
        else
            self.accelerator_claim_heads[queue_index];
        if (best == QUEUE_NO_INDEX or best >= backing.claims.slots.len) return null;

        self.unlinkAcceleratorClaimIndex(engine, @intCast(best));
        self.accelerator_claim_counts[queue_index] -= 1;
        return @intCast(best);
    }

    fn unlinkAcceleratorClaimIndex(
        self: *Scheduler,
        engine: accelerator_scheduler.Engine,
        claim_index: usize,
    ) void {
        const backing = self.acceleratorClaimBacking() orelse
            native_util.impossibleByInvariant("linked accelerator claim retains its backing");
        const queue_index = engineIndex(engine);
        const previous = backing.claims.slots[claim_index].prev_claim_index;
        const next = backing.claims.slots[claim_index].next_claim_index;
        if (previous == QUEUE_NO_INDEX) {
            self.accelerator_claim_heads[queue_index] = next;
        } else {
            backing.claims.slots[previous].next_claim_index = next;
        }
        if (next == QUEUE_NO_INDEX) {
            self.accelerator_claim_tails[queue_index] = previous;
        } else {
            backing.claims.slots[next].prev_claim_index = previous;
        }

        const previous_deadline = backing.claims.slots[claim_index].prev_deadline_index;
        const next_deadline = backing.claims.slots[claim_index].next_deadline_index;
        if (backing.claims.slots[claim_index].record.deadline_tick != 0) {
            if (previous_deadline == QUEUE_NO_INDEX) {
                self.accelerator_deadline_heads[queue_index] = next_deadline;
            } else {
                backing.claims.slots[previous_deadline].next_deadline_index = next_deadline;
            }
            if (next_deadline == QUEUE_NO_INDEX) {
                self.accelerator_deadline_tails[queue_index] = previous_deadline;
            } else {
                backing.claims.slots[next_deadline].prev_deadline_index = previous_deadline;
            }
        }

        _ = backing.task_index.remove(
            acceleratorClaimTaskKey(backing.claims.slots[claim_index].record.task_id),
            claim_index,
        );
        backing.claims.slots[claim_index].prev_claim_index = QUEUE_NO_INDEX;
        backing.claims.slots[claim_index].next_claim_index = QUEUE_NO_INDEX;
        backing.claims.slots[claim_index].prev_deadline_index = QUEUE_NO_INDEX;
        backing.claims.slots[claim_index].next_deadline_index = QUEUE_NO_INDEX;
    }

    fn acceleratorClaimPriorityBeats(
        self: *const Scheduler,
        candidate_index: usize,
        selected_index: usize,
    ) bool {
        const backing = self.acceleratorClaimBackingConst() orelse
            native_util.impossibleByInvariant("ranked accelerator claims retain their backing");
        const candidate = backing.claims.slots[candidate_index].record;
        const selected = backing.claims.slots[selected_index].record;

        const candidate_priority = resourceClassPriorityRank(candidate.resource_class);
        const selected_priority = resourceClassPriorityRank(selected.resource_class);
        if (candidate_priority < selected_priority) return true;
        if (candidate_priority > selected_priority) return false;

        if (candidate.deadline_tick != 0 and selected.deadline_tick != 0) {
            if (candidate.deadline_tick < selected.deadline_tick) return true;
            if (candidate.deadline_tick > selected.deadline_tick) return false;
        } else if (candidate.deadline_tick != selected.deadline_tick) {
            return candidate.deadline_tick != 0;
        }

        const candidate_dispatches = self.taskDispatchCount(candidate.task_id);
        const selected_dispatches = self.taskDispatchCount(selected.task_id);
        if (candidate_dispatches < selected_dispatches) return true;
        if (candidate_dispatches > selected_dispatches) return false;

        const candidate_last_dispatch = self.taskLastDispatchTick(candidate.task_id);
        const selected_last_dispatch = self.taskLastDispatchTick(selected.task_id);
        if (candidate_last_dispatch < selected_last_dispatch) return true;
        if (candidate_last_dispatch > selected_last_dispatch) return false;

        return candidate.requested_at_tick < selected.requested_at_tick;
    }

    fn acceleratorClaimDeadlineBeats(
        self: *const Scheduler,
        candidate_index: usize,
        selected_index: usize,
    ) bool {
        const backing = self.acceleratorClaimBackingConst() orelse
            native_util.impossibleByInvariant("ranked accelerator deadlines retain their backing");
        const candidate = backing.claims.slots[candidate_index].record;
        const selected = backing.claims.slots[selected_index].record;
        if (candidate.deadline_tick < selected.deadline_tick) return true;
        if (candidate.deadline_tick > selected.deadline_tick) return false;
        return self.acceleratorClaimPriorityBeats(candidate_index, selected_index);
    }

    fn taskDispatchCount(self: *const Scheduler, task_id: u64) u64 {
        return if (self.slots.getConst(task_id)) |slot| slot.dispatch_count else std.math.maxInt(u64);
    }

    fn taskLastDispatchTick(self: *const Scheduler, task_id: u64) u64 {
        return if (self.slots.getConst(task_id)) |slot| slot.last_dispatch_tick else std.math.maxInt(u64);
    }

    fn removeAcceleratorClaimsForTask(self: *Scheduler, task_id: u64) void {
        const backing = self.acceleratorClaimBacking() orelse return;
        const task_key = acceleratorClaimTaskKey(task_id);
        var current = backing.task_index.head(task_key);
        while (current != arena_no_index) {
            if (current >= backing.claims.slots.len) {
                native_util.impossibleByInvariant("accelerator claim task index points outside claim slots");
            }
            const next = backing.task_index.next(current);
            const claim_slot = &backing.claims.slots[current];
            if (!claim_slot.in_use) native_util.impossibleByInvariant("accelerator claim task index points at a free slot");
            if (claim_slot.record.task_id != task_id) {
                native_util.impossibleByInvariant("accelerator claim task index points at the wrong task");
            }
            const record = claim_slot.record;
            self.unlinkAcceleratorClaimIndex(record.engine, current);
            self.accelerator_claim_counts[engineIndex(record.engine)] -= 1;
            if (self.slots.get(task_id)) |slot| {
                if (slot.pending_accelerator_claim_id == record.id) {
                    slot.pending_accelerator_claim_id = 0;
                    slot.pending_accelerator_engine = .cpu;
                }
            }
            _ = backing.claims.removeIndex(current);
            current = next;
        }
    }

    fn findAcceleratorClaimForTaskEngine(
        self: *const Scheduler,
        task_id: u64,
        engine: accelerator_scheduler.Engine,
    ) ?u64 {
        const backing = self.acceleratorClaimBackingConst() orelse return null;
        const task_key = acceleratorClaimTaskKey(task_id);
        var current = backing.task_index.head(task_key);
        while (current != arena_no_index) : (current = backing.task_index.next(current)) {
            if (current >= backing.claims.slots.len) {
                native_util.impossibleByInvariant("accelerator claim task index points outside claim slots");
            }
            const slot = &backing.claims.slots[current];
            if (!slot.in_use) native_util.impossibleByInvariant("accelerator claim task index points at a free slot");
            const record = slot.record;
            if (record.task_id != task_id) native_util.impossibleByInvariant("accelerator claim task index points at the wrong task");
            if (record.task_id == task_id and record.engine == engine) return record.id;
        }
        return null;
    }

    fn nextAcceleratorClaimId(self: *Scheduler) ?u64 {
        if (self.next_accelerator_claim_id == 0) return null;
        const backing = self.acceleratorClaimBacking() orelse return self.next_accelerator_claim_id;
        if (backing.claims.countInUse() >= MAX_ACCELERATOR_CLAIMS) return null;
        if (backing.claims.get(self.next_accelerator_claim_id) != null) return null;
        return self.next_accelerator_claim_id;
    }
};

fn schedulerSlotTaskId(slot: *const Slot) u64 {
    return slot.task_id;
}

fn compactQueueIndex(index: usize) QueueSlotIndex {
    return @intCast(index);
}

fn acceleratorClaimSlotId(slot: *const AcceleratorClaimSlot) u64 {
    return slot.record.id;
}

test "scheduler caches immutable UI presentation eligibility" {
    try std.testing.expect(contractOwnsUiSurface(userspace_flags.FLAG_OWNS_UI_SURFACE));
    try std.testing.expect(contractOwnsUiSurface(userspace_flags.FLAG_OWNS_UI_SURFACE | userspace_flags.FLAG_BACKGROUND_ELIGIBLE));
    try std.testing.expect(!contractOwnsUiSurface(0));
    try std.testing.expect(!contractOwnsUiSurface(userspace_flags.FLAG_BACKGROUND_ELIGIBLE));
    try std.testing.expectEqual(@as(u8, 0), STEADY_UI_ELIGIBILITY_CATALOG_LOOKUPS);
}

fn acceleratorClaimTaskKey(task_id: u64) u64 {
    return task_id;
}

fn hasDispatchBudget(slot: *const Slot, task: *const task_runtime.TaskRecord) bool {
    _ = task;
    return slot.cpu_budget_remaining_ticks >= DISPATCH_CPU_TICK_COST;
}

fn taskEligibleForPostDispatchRequeue(
    expected_task_id: u64,
    task: *const task_runtime.TaskRecord,
    slot: *const Slot,
) bool {
    return task.id == expected_task_id and
        task.state == .active and
        task.runsAsUserspaceProcess() and
        task.hasLoadedExecutable() and
        hasDispatchBudget(slot, task);
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

fn resourceClassPriorityRank(class: accelerator_scheduler.ResourceClass) usize {
    for (resource_priority_order, 0..) |priority_class, priority| {
        if (priority_class == class) return priority;
    }
    return resource_priority_order.len;
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

fn executionRemainsReady(outcome: userspace_executor.ExecutionOutcome) bool {
    return outcome != .wait_for_event;
}

fn taskUiPresentationEligible(
    catalog: *userspace_loader.Catalog,
    task: *const task_runtime.TaskRecord,
) bool {
    const image = catalog.findById(task.launch.image_id) orelse return false;
    return contractOwnsUiSurface(image.contract_flags);
}

fn contractOwnsUiSurface(contract_flags: u32) bool {
    return (contract_flags & userspace_flags.FLAG_OWNS_UI_SURFACE) != 0;
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

fn claimDeadlineExpired(record: AcceleratorClaimRecord, now_ticks: u64) bool {
    return record.deadline_tick != 0 and record.deadline_tick <= now_ticks;
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

test "allocated scheduler initialization preserves empty queue invariants" {
    var executor = userspace_executor.Executor{};
    var scheduler: Scheduler = undefined;
    scheduler.initializeAllocated(&executor);

    try std.testing.expectEqual(@as(usize, 0), scheduler.slots.countInUse());
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expectEqual(@as(u64, 1), scheduler.next_accelerator_claim_id);
    try std.testing.expectEqual(std.math.maxInt(u64), scheduler.resource_state.cpu_budget_ticks);
    try std.testing.expectEqual(std.math.maxInt(usize), scheduler.resource_state.memory_bandwidth_units);
    try std.testing.expect(scheduler.resource_state.gpu_available);
    const slot_index = scheduler.slots.reserveIndex(7).?;
    try std.testing.expectEqual(@as(usize, 0), slot_index);
    try std.testing.expect(scheduler.slots.removeIndex(slot_index));
}

test "post-dispatch requeue validates retained task identity and state" {
    var runtime = task_runtime.Runtime.init();
    const task = try createRunnableSchedulerTask(
        &runtime,
        71,
        .foreground_interactive,
        "retained-task",
        "app.retained-task",
        null,
    );
    var slot = Slot{
        .in_use = true,
        .task_id = task.id,
        .cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST,
    };

    try std.testing.expect(taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id + 1, task, &slot));

    try std.testing.expect(try runtime.suspendTask(task.id, 1));
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    try std.testing.expect(try runtime.resumeTask(task.id, 2));
    try std.testing.expect(taskEligibleForPostDispatchRequeue(task.id, task, &slot));

    slot.cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST - 1;
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    slot.cpu_budget_remaining_ticks = DISPATCH_CPU_TICK_COST;

    try std.testing.expect(try runtime.terminateTask(task.id, 3));
    try std.testing.expect(!taskEligibleForPostDispatchRequeue(task.id, task, &slot));
    try std.testing.expectEqual(@as(u8, 0), SCHEDULED_TASK_INDEX_LOOKUPS_PER_DISPATCH);
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
    try std.testing.expect(scheduler.hasReadyTasks());
    try std.testing.expect(!scheduler.registerTask(first_task.id));
    try std.testing.expectEqual(@as(usize, 1), scheduler.slots.countInUse());

    const first_index = scheduler.slots.slotIndexOf(first_task.id).?;
    const first_handle = scheduler.slots.slots[first_index].task_handle;
    try std.testing.expectEqual(first_task.id, runtime.findByHandle(first_handle, first_task.id).?.id);
    try std.testing.expect(!scheduler.slots.slots[first_index].owns_ui_surface);
    scheduler.slots.slots[first_index].owns_ui_surface = true;
    try std.testing.expect(scheduler.unregisterTask(first_task.id));
    try std.testing.expect(!scheduler.hasReadyTasks());
    try std.testing.expectEqual(@as(usize, 0), scheduler.slots.countInUse());

    try std.testing.expect(scheduler.registerTask(second_task.id));
    try std.testing.expect(scheduler.hasReadyTasks());
    try std.testing.expectEqual(first_index, scheduler.slots.slotIndexOf(second_task.id).?);
    const second_handle = scheduler.slots.slots[first_index].task_handle;
    try std.testing.expect(!second_handle.eql(first_handle));
    try std.testing.expectEqual(second_task.id, runtime.findByHandle(second_handle, second_task.id).?.id);
    try std.testing.expect(!scheduler.slots.slots[first_index].owns_ui_surface);
}

test "userspace scheduler refreshes task handles after runtime restore" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(
        &runtime,
        72,
        .foreground_interactive,
        "restored-task",
        "app.restored-task",
        null,
    );
    const task_id = task.id;
    try std.testing.expect(scheduler.registerTask(task_id));
    const slot = scheduler.slots.get(task_id).?;
    const original_handle = slot.task_handle;
    slot.mapping_handle = userspace_executor.MappingHandle.fromParts(3, 9);

    var snapshot = task_runtime.Runtime.initSnapshot();
    runtime.writeSnapshot(&snapshot);
    try runtime.restoreFromSnapshot(&snapshot);
    const restored_handle = runtime.taskHandle(task_id).?;
    try std.testing.expect(!restored_handle.eql(original_handle));

    try std.testing.expect(scheduler.wakeTask(task_id, .external_event, 1, 0));
    try std.testing.expect(slot.task_handle.eql(restored_handle));
    try std.testing.expect(slot.mapping_handle.isZero());
}

test "userspace scheduler rejects stale handles after task id reuse" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(
        &runtime,
        73,
        .foreground_interactive,
        "original-task",
        "app.original-task",
        null,
    );
    const task_id = task.id;
    try std.testing.expect(scheduler.registerTask(task_id));
    const original_handle = scheduler.slots.get(task_id).?.task_handle;

    runtime.reset();
    const replacement = try createRunnableSchedulerTask(
        &runtime,
        74,
        .foreground_interactive,
        "replacement-task",
        "app.replacement-task",
        null,
    );
    try std.testing.expectEqual(task_id, replacement.id);
    try std.testing.expect(!runtime.taskHandle(task_id).?.eql(original_handle));

    try std.testing.expect(!scheduler.runNext(1));
    try std.testing.expect(scheduler.slots.get(task_id) == null);
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
    try std.testing.expectEqual(compactQueueIndex(first_index), scheduler.ready_heads[queue_index]);
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.ready_tails[queue_index]);
    try std.testing.expectEqual(compactQueueIndex(first_index), scheduler.slots.slots[second_index].prev_ready_index);
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.slots.slots[second_index].next_ready_index);

    try std.testing.expect(scheduler.parkTaskUntilEvent(second_task.id));
    try std.testing.expectEqual(@as(usize, 2), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.slots.slots[first_index].next_ready_index);
    try std.testing.expectEqual(compactQueueIndex(first_index), scheduler.slots.slots[third_index].prev_ready_index);
    try std.testing.expectEqual(QUEUE_NO_INDEX, scheduler.slots.slots[second_index].prev_ready_index);
    try std.testing.expectEqual(QUEUE_NO_INDEX, scheduler.slots.slots[second_index].next_ready_index);

    try std.testing.expect(scheduler.unregisterTask(first_task.id));
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.ready_heads[queue_index]);
    try std.testing.expectEqual(compactQueueIndex(third_index), scheduler.ready_tails[queue_index]);
    try std.testing.expectEqual(QUEUE_NO_INDEX, scheduler.slots.slots[third_index].prev_ready_index);
}

test "userspace scheduler compact queue indexes cover every task slot" {
    try std.testing.expectEqual(@as(usize, task_runtime.MAX_TASKS), @as(usize, QUEUE_NO_INDEX));
    try std.testing.expectEqual(
        @as(QueueSlotIndex, @intCast(task_runtime.MAX_TASKS - 1)),
        compactQueueIndex(task_runtime.MAX_TASKS - 1),
    );
}

test "userspace scheduler parks only explicit event-wait yields" {
    try std.testing.expect(executionRemainsReady(.unavailable));
    try std.testing.expect(executionRemainsReady(.yielded));
    try std.testing.expect(!executionRemainsReady(.wait_for_event));
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
    try std.testing.expect(scheduler.grantNextAcceleratorClaim(.media, 9) == null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

    scheduler.configureResourceTelemetry(.{
        .source = .hardware,
        .observed_tick = 10,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .hardware_evidence = completeTestHardwareEvidence(),
    });
    const granted = scheduler.grantNextAcceleratorClaim(.media, 10).?;
    try std.testing.expectEqual(media_claim, granted.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.media_export));
}

test "userspace scheduler indexes accelerator claims by task across grants and unregister" {
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
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const task = try createRunnableSchedulerTask(
        &runtime,
        250,
        .media_export,
        "indexed-claim-task",
        "app.example.indexed-claim-task",
        250,
    );

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));

    const first_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 1,
        .deadline_tick = 40,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const duplicate_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 2,
        .deadline_tick = 30,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expectEqual(first_gpu_claim, duplicate_gpu_claim);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));

    const granted_gpu = scheduler.grantNextAcceleratorClaim(.gpu, 3).?;
    try std.testing.expectEqual(first_gpu_claim, granted_gpu.id);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));

    try std.testing.expect(scheduler.parkTaskUntilEvent(task.id));
    const second_gpu_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 4,
        .deadline_tick = 45,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expect(first_gpu_claim != second_gpu_claim);
    _ = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .media,
        .resource_class = .media_export,
        .requested_at_tick = 5,
        .deadline_tick = 46,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    try std.testing.expectEqual(@as(usize, 2), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));

    try std.testing.expect(scheduler.unregisterTask(task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimBackingConst().?.task_index.count(acceleratorClaimTaskKey(task.id)));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
}

test "userspace scheduler stops accelerator claim ids at exhaustion" {
    var executor = userspace_executor.Executor{};
    var scheduler = Scheduler.init(&executor);
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    scheduler.bind(&catalog, &runtime, &capabilities);

    const task = try createRunnableSchedulerTask(
        &runtime,
        251,
        .media_export,
        "final-claim-task",
        "app.example.final-claim-task",
        251,
    );
    try std.testing.expect(scheduler.registerTask(task.id));
    scheduler.next_accelerator_claim_id = std.math.maxInt(u64);

    const final_claim_id = scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .gpu,
        .resource_class = .media_export,
        .requested_at_tick = 1,
    }).?;
    try std.testing.expectEqual(std.math.maxInt(u64), final_claim_id);
    try std.testing.expectEqual(@as(u64, 0), scheduler.next_accelerator_claim_id);
    try std.testing.expect(scheduler.unregisterTask(task.id));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));

    try std.testing.expect(scheduler.registerTask(task.id));
    try std.testing.expect(scheduler.enqueueAcceleratorClaim(.{
        .task_id = task.id,
        .engine = .media,
        .resource_class = .media_export,
        .requested_at_tick = 2,
    }) == null);
    try std.testing.expectEqual(@as(u64, 0), scheduler.next_accelerator_claim_id);
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.media));
}

test "userspace scheduler grants expired high-priority accelerator claims before older batch claims" {
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
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const batch = try createRunnableSchedulerTask(
        &runtime,
        260,
        .batch_compute,
        "queued-batch-gpu",
        "app.example.queued-batch-gpu",
        null,
    );
    const foreground = try createRunnableSchedulerTask(
        &runtime,
        261,
        .foreground_interactive,
        "urgent-foreground-gpu",
        "app.example.urgent-foreground-gpu",
        261,
    );

    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(batch.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(foreground.id));

    const batch_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = batch.id,
        .engine = .gpu,
        .resource_class = .batch_compute,
        .requested_at_tick = 1,
        .deadline_tick = 200,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const foreground_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = foreground.id,
        .engine = .gpu,
        .resource_class = .foreground_interactive,
        .requested_at_tick = 2,
        .deadline_tick = 20,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;

    try std.testing.expectEqual(@as(usize, 2), scheduler.acceleratorClaimQueueDepth(.gpu));
    const granted_foreground = scheduler.grantNextAcceleratorClaim(.gpu, 20).?;
    try std.testing.expectEqual(foreground_claim, granted_foreground.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.batch_compute));
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.gpu));

    const granted_batch = scheduler.grantNextAcceleratorClaim(.gpu, 21).?;
    try std.testing.expectEqual(batch_claim, granted_batch.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
}

test "userspace scheduler grants expired accelerator deadlines before unexpired foreground claims" {
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
        .hardware_evidence = completeTestHardwareEvidence(),
    });

    const batch = try createRunnableSchedulerTask(
        &runtime,
        262,
        .batch_compute,
        "expired-batch-gpu",
        "app.example.expired-batch-gpu",
        null,
    );
    const foreground = try createRunnableSchedulerTask(
        &runtime,
        263,
        .foreground_interactive,
        "unexpired-foreground-gpu",
        "app.example.unexpired-foreground-gpu",
        263,
    );

    try std.testing.expect(scheduler.registerTask(batch.id));
    try std.testing.expect(scheduler.registerTask(foreground.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(batch.id));
    try std.testing.expect(scheduler.parkTaskUntilEvent(foreground.id));

    const foreground_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = foreground.id,
        .engine = .gpu,
        .resource_class = .foreground_interactive,
        .requested_at_tick = 1,
        .deadline_tick = 200,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;
    const batch_claim = scheduler.enqueueAcceleratorClaim(.{
        .task_id = batch.id,
        .engine = .gpu,
        .resource_class = .batch_compute,
        .requested_at_tick = 2,
        .deadline_tick = 20,
        .shared_memory_bytes = TEST_ACCELERATOR_SHARED_MEMORY_BYTES,
    }).?;

    try std.testing.expectEqual(@as(usize, 2), scheduler.acceleratorClaimQueueDepth(.gpu));
    const granted_batch = scheduler.grantNextAcceleratorClaim(.gpu, 20).?;
    try std.testing.expectEqual(batch_claim, granted_batch.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.batch_compute));
    try std.testing.expectEqual(@as(usize, 0), scheduler.readyQueueDepth(.foreground_interactive));

    const granted_foreground = scheduler.grantNextAcceleratorClaim(.gpu, 21).?;
    try std.testing.expectEqual(foreground_claim, granted_foreground.id);
    try std.testing.expectEqual(@as(usize, 1), scheduler.readyQueueDepth(.foreground_interactive));
    try std.testing.expectEqual(@as(usize, 0), scheduler.acceleratorClaimQueueDepth(.gpu));
}

test "userspace scheduler requires complete hardware telemetry before waking hardware queues" {
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
        .source = .emulator,
        .observed_tick = 1,
        .media_available = true,
    });
    try std.testing.expect(scheduler.observedResourceTelemetry());
    try std.testing.expect(!scheduler.runNext(2));
    const emulator_slot = scheduler.slots.getConst(task.id).?;
    try std.testing.expectEqual(@as(u64, 0), emulator_slot.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), scheduler.acceleratorClaimQueueDepth(.media));

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
