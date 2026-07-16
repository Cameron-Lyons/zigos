const std = @import("std");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const units = @import("../core/units.zig");

pub const Engine = enum(u8) {
    cpu,
    gpu,
    npu,
    media,
};

pub const ResourceClass = enum(u8) {
    foreground_interactive,
    background_light,
    media_export,
    batch_compute,
    emergency_system_critical,
};

pub const ThermalPressure = enum(u8) {
    nominal,
    elevated,
    critical,
};

pub const DecisionReason = enum(u8) {
    normal,
    thermal_throttle,
    battery_preserve,
    privacy_mode,
    accelerator_unavailable,
    cpu_budget,
    memory_bandwidth,
    carbon_aware_delay,
};

pub const SystemState = struct {
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
    cpu_budget_ticks: u64 = std.math.maxInt(u64),
    memory_bandwidth_units: usize = std.math.maxInt(usize),
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
};

pub const TelemetrySource = enum(u8) {
    synthetic,
    emulator,
    boot_provider,
    hardware,
};

pub const TelemetryProviderRole = enum(u8) {
    production,
    test_only,
};

pub const TelemetryProviderDescriptor = struct {
    name: []const u8,
    role: TelemetryProviderRole,
};

pub const TelemetryProvider = struct {
    context: *anyopaque,
    descriptor: TelemetryProviderDescriptor,
    read_fn: *const fn (*anyopaque) TelemetrySample,

    pub fn init(
        comptime Provider: type,
        provider: *Provider,
        descriptor: TelemetryProviderDescriptor,
    ) TelemetryProvider {
        return .{
            .context = @ptrCast(provider),
            .descriptor = descriptor,
            .read_fn = struct {
                fn read(context: *anyopaque) TelemetrySample {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.read();
                }
            }.read,
        };
    }

    pub fn read(self: TelemetryProvider) TelemetrySample {
        return self.read_fn(self.context);
    }

    pub fn testOnly(self: TelemetryProvider) bool {
        return self.descriptor.role == .test_only;
    }
};

pub const PlatformTelemetrySignals = struct {
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
    cpu_budget_ticks: u64 = std.math.maxInt(u64),
    memory_bandwidth_units: usize = std.math.maxInt(usize),
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
};

pub const HardwareTelemetryEvidence = struct {
    target_id: []const u8 = "",
    reader_generation: u32 = 0,
    acpi_observed: bool = false,
    thermal_observed: bool = false,
    battery_observed: bool = false,
    accelerator_observed: bool = false,
    grid_carbon_observed: bool = false,

    pub fn complete(self: HardwareTelemetryEvidence) bool {
        return self.target_id.len != 0 and
            self.reader_generation != 0 and
            self.acpi_observed and
            self.thermal_observed and
            self.battery_observed and
            self.accelerator_observed and
            self.grid_carbon_observed;
    }
};

pub const LivePlatformCounters = struct {
    total_cpu_budget_ticks: u64 = std.math.maxInt(u64),
    consumed_cpu_ticks: u64 = 0,
    memory_capacity_bytes: usize = std.math.maxInt(usize),
    reserved_memory_bytes: usize = 0,
    reserved_shared_memory_bytes: usize = 0,
    gpu_driver_online: bool = true,
    npu_driver_online: bool = true,
    media_driver_online: bool = true,
    thermal_milli_celsius: u32 = 45_000,
    battery_percent: u8 = 100,
    battery_charging: bool = true,
    privacy_sensitive_task_count: usize = 0,
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
    hardware_evidence: HardwareTelemetryEvidence = .{},
};

pub const TelemetrySample = struct {
    source: TelemetrySource = .synthetic,
    observed_tick: u64 = 0,
    thermal_pressure: ThermalPressure = .nominal,
    battery_saver: bool = false,
    privacy_mode: bool = false,
    gpu_available: bool = true,
    npu_available: bool = true,
    media_available: bool = true,
    cpu_budget_ticks: u64 = std.math.maxInt(u64),
    memory_bandwidth_units: usize = std.math.maxInt(usize),
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
    hardware_evidence: HardwareTelemetryEvidence = .{},

    pub fn toSystemState(self: TelemetrySample) SystemState {
        return .{
            .thermal_pressure = self.thermal_pressure,
            .battery_saver = self.battery_saver,
            .privacy_mode = self.privacy_mode,
            .gpu_available = self.gpu_available,
            .npu_available = self.npu_available,
            .media_available = self.media_available,
            .cpu_budget_ticks = self.cpu_budget_ticks,
            .memory_bandwidth_units = self.memory_bandwidth_units,
            .grid_carbon_intensity_grams_per_kwh = self.grid_carbon_intensity_grams_per_kwh,
        };
    }

    pub fn observed(self: TelemetrySample) bool {
        return self.source != .synthetic;
    }

    pub fn hardwareReaderEvidenceComplete(self: TelemetrySample) bool {
        return self.source != .hardware or self.hardware_evidence.complete();
    }
};

pub const EmulatedTelemetryDevice = struct {
    current: TelemetrySample = .{ .source = .emulator },
    read_count: u32 = 0,

    pub const telemetry_descriptor = TelemetryProviderDescriptor{
        .name = "emulated-telemetry-device",
        .role = .test_only,
    };

    pub fn init(sample: TelemetrySample) EmulatedTelemetryDevice {
        var current = sample;
        current.source = .emulator;
        return .{ .current = current };
    }

    pub fn update(self: *EmulatedTelemetryDevice, sample: TelemetrySample) void {
        var current = sample;
        current.source = .emulator;
        self.current = current;
    }

    pub fn telemetryProvider(self: *EmulatedTelemetryDevice) TelemetryProvider {
        return TelemetryProvider.init(EmulatedTelemetryDevice, self, telemetry_descriptor);
    }

    pub fn read(self: *EmulatedTelemetryDevice) TelemetrySample {
        self.read_count += 1;
        return self.current;
    }
};

pub const BootedPlatformTelemetryProvider = struct {
    boot_id: u64,
    task_id: u64 = 0,
    current: TelemetrySample = .{ .source = .boot_provider },
    read_count: u32 = 0,
    live_observation_count: u32 = 0,
    rejected_observation_count: u32 = 0,

    pub const telemetry_descriptor = TelemetryProviderDescriptor{
        .name = "booted-platform-telemetry-provider",
        .role = .production,
    };

    pub fn init(boot_id: u64, observed_tick: u64, signals: PlatformTelemetrySignals) BootedPlatformTelemetryProvider {
        return .{
            .boot_id = boot_id,
            .current = sampleFromPlatformSignals(.boot_provider, observed_tick, signals),
        };
    }

    pub fn initForBootedService(
        boot_id: u64,
        task_id: u64,
        observed_tick: u64,
        counters: LivePlatformCounters,
    ) TelemetryError!BootedPlatformTelemetryProvider {
        if (boot_id == 0) return error.TelemetryProviderUnauthorized;
        if (task_id == 0) return error.TelemetryProviderUnauthorized;
        return .{
            .boot_id = boot_id,
            .task_id = task_id,
            .current = sampleFromLivePlatformCounters(observed_tick, counters),
            .live_observation_count = 1,
        };
    }

    pub fn observe(self: *BootedPlatformTelemetryProvider, observed_tick: u64, signals: PlatformTelemetrySignals) TelemetryError!void {
        if (self.task_id != 0) {
            self.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (observed_tick < self.current.observed_tick) {
            self.rejected_observation_count += 1;
            return error.TelemetryObservationStale;
        }
        self.current = sampleFromPlatformSignals(.boot_provider, observed_tick, signals);
    }

    pub fn observeLive(
        self: *BootedPlatformTelemetryProvider,
        caller_task_id: u64,
        observed_tick: u64,
        counters: LivePlatformCounters,
    ) TelemetryError!void {
        if (self.task_id == 0 or caller_task_id == 0) {
            self.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (self.task_id != 0 and caller_task_id != self.task_id) {
            self.rejected_observation_count += 1;
            return error.TelemetryProviderUnauthorized;
        }
        if (observed_tick < self.current.observed_tick) {
            self.rejected_observation_count += 1;
            return error.TelemetryObservationStale;
        }
        self.current = sampleFromLivePlatformCounters(observed_tick, counters);
        self.live_observation_count += 1;
    }

    pub fn telemetryProvider(self: *BootedPlatformTelemetryProvider) TelemetryProvider {
        return TelemetryProvider.init(BootedPlatformTelemetryProvider, self, telemetry_descriptor);
    }

    pub fn read(self: *BootedPlatformTelemetryProvider) TelemetrySample {
        self.read_count += 1;
        return self.current;
    }
};

pub const TelemetryError = error{
    TelemetryObservationStale,
    TelemetryProviderUnauthorized,
};

pub const Request = struct {
    class: ResourceClass,
    wants_gpu: bool = false,
    wants_npu: bool = false,
    wants_media_engine: bool = false,
    privacy_sensitive: bool = false,
    shared_memory_bytes: usize = 0,
    expected_cpu_ticks: u64 = 0,
    memory_bandwidth_units: usize = 0,
    estimated_energy_milliwatt_hours: u32 = 0,
    defer_for_low_carbon_power: bool = false,
};

pub const Decision = struct {
    class: ResourceClass,
    engine: Engine,
    delayed: bool,
    degraded: bool,
    zero_copy_allowed: bool,
    reason: DecisionReason,
};

pub const MAX_ENGINE_CLAIMS: usize = 16;
const ENGINE_COUNT: usize = std.meta.fields(Engine).len;
const CLAIM_INDEX_CAPACITY: usize = MAX_ENGINE_CLAIMS * 2;
const HIGH_CARBON_GRID_GRAMS_PER_KWH: u16 = 450;

pub const EngineAvailability = struct {
    gpu: bool = true,
    npu: bool = true,
    media: bool = true,

    pub fn forEngine(self: EngineAvailability, engine: Engine) bool {
        return switch (engine) {
            .cpu => true,
            .gpu => self.gpu,
            .npu => self.npu,
            .media => self.media,
        };
    }
};

pub const ClaimRequest = struct {
    task_id: u64,
    request: Request,
    require_accelerator: bool = false,
    shared_memory_object_id: ?ids.SharedMemoryId = null,
};

pub const ClaimRecord = struct {
    id: u64,
    task_id: u64,
    class: ResourceClass,
    engine: Engine,
    delayed: bool,
    degraded: bool,
    zero_copy: bool,
    reason: DecisionReason,
    shared_memory_object_id: ?ids.SharedMemoryId,
    active: bool,
    queue_generation: u32,
    queue_completion_sequence: u64,
};

pub const BrokeredEngineQueue = struct {
    broker_task_id: u64 = 0,
    owner_task_id: u64 = 0,
    generation: u32 = 0,
    completion_sequence: u64 = 0,
    completion_interrupts_observed: u32 = 0,
    accepts_work: bool = false,

    pub fn readyFor(self: BrokeredEngineQueue, task_id: u64) bool {
        return self.accepts_work and
            self.broker_task_id != 0 and
            self.owner_task_id == task_id and
            self.generation != 0 and
            self.completion_interrupts_observed != 0;
    }
};

pub const BrokeredEngineQueueEvent = struct {
    engine: Engine,
    broker_task_id: u64,
    owner_task_id: u64,
    generation: u32,
    completion_sequence: u64,
    completion_interrupts_observed: u32,
    accepts_work: bool,

    pub fn verified(self: BrokeredEngineQueueEvent) bool {
        return self.engine != .cpu and
            self.broker_task_id != 0 and
            self.owner_task_id != 0 and
            self.generation != 0 and
            self.completion_interrupts_observed != 0 and
            self.accepts_work;
    }

    pub fn toQueue(self: BrokeredEngineQueueEvent) BrokeredEngineQueue {
        return .{
            .broker_task_id = self.broker_task_id,
            .owner_task_id = self.owner_task_id,
            .generation = self.generation,
            .completion_sequence = self.completion_sequence,
            .completion_interrupts_observed = self.completion_interrupts_observed,
            .accepts_work = self.accepts_work,
        };
    }
};

pub const Error = shared_memory.Error || error{
    AcceleratorRequired,
    ClaimIdExhausted,
    ClaimNotFound,
    ClaimTableFull,
    EngineBusy,
    EngineQueueNotOwned,
    EngineQueueGenerationMismatch,
    InvalidEngineQueueEvent,
    QueueCompletionMissing,
    QueueCompletionStale,
    SharedMemoryTableRequired,
    ZeroCopyUnavailable,
};

const ClaimSlot = struct {
    in_use: bool = false,
    claim: ClaimRecord = zeroClaim(),
};

const ClaimArena = indexed_arena.IndexedArenaWithKey(u64, ClaimSlot, MAX_ENGINE_CLAIMS, CLAIM_INDEX_CAPACITY, claimSlotId);
const ClaimTaskIndex = indexed_arena.MultimapIndex(MAX_ENGINE_CLAIMS, MAX_ENGINE_CLAIMS, CLAIM_INDEX_CAPACITY);

pub const Controller = struct {
    state: SystemState = .{},
    last_telemetry_source: TelemetrySource = .synthetic,
    last_telemetry_observed_tick: u64 = 0,
    last_hardware_evidence_complete: bool = false,
    production_hardware_telemetry_required: bool = false,
    next_claim_id: u64 = 1,
    claims: ClaimArena = ClaimArena.init(),
    claim_task_index: ClaimTaskIndex = ClaimTaskIndex.init(),
    active_engine_claims: [ENGINE_COUNT]u64 = [_]u64{0} ** ENGINE_COUNT,
    active_claim_count: u16 = 0,
    brokered_engine_queues_required: bool = false,
    brokered_engine_queues: [ENGINE_COUNT]BrokeredEngineQueue = [_]BrokeredEngineQueue{.{}} ** ENGINE_COUNT,

    pub fn init() Controller {
        return .{};
    }

    pub fn configure(self: *Controller, state: SystemState) void {
        self.state = state;
        self.last_telemetry_source = .synthetic;
        self.last_telemetry_observed_tick = 0;
        self.last_hardware_evidence_complete = false;
    }

    pub fn configureFromTelemetry(self: *Controller, sample: TelemetrySample) void {
        if (!telemetrySampleIsFresh(self.last_telemetry_source, self.last_telemetry_observed_tick, sample)) return;
        self.state = sample.toSystemState();
        self.last_telemetry_source = sample.source;
        self.last_telemetry_observed_tick = sample.observed_tick;
        self.last_hardware_evidence_complete = sample.hardwareReaderEvidenceComplete();
    }

    pub fn configureFromProvider(self: *Controller, provider: TelemetryProvider) void {
        self.configureFromTelemetry(provider.read());
    }

    pub fn observedTelemetry(self: *const Controller) bool {
        return self.last_telemetry_source != .synthetic;
    }

    pub fn requireProductionHardwareTelemetryForAccelerators(self: *Controller) void {
        self.production_hardware_telemetry_required = true;
    }

    pub fn requireBrokeredEngineQueues(self: *Controller) void {
        self.brokered_engine_queues_required = true;
    }

    pub fn configureBrokeredEngineQueue(
        self: *Controller,
        engine: Engine,
        queue: BrokeredEngineQueue,
    ) bool {
        if (engine == .cpu) return false;
        if (!queue.readyFor(queue.owner_task_id)) return false;
        self.brokered_engine_queues_required = true;
        self.brokered_engine_queues[engineIndex(engine)] = queue;
        return true;
    }

    pub fn brokeredQueueFor(self: *const Controller, engine: Engine) BrokeredEngineQueue {
        return if (engine == .cpu) .{} else self.brokered_engine_queues[engineIndex(engine)];
    }

    pub fn observeBrokeredEngineQueueEvent(
        self: *Controller,
        event: BrokeredEngineQueueEvent,
    ) Error!void {
        if (!event.verified()) return error.InvalidEngineQueueEvent;
        const active_claim_id = self.activeEngineClaimId(event.engine);
        if (active_claim_id != 0) {
            const active_claim = self.findActiveClaim(active_claim_id) orelse return error.ClaimNotFound;
            if (active_claim.task_id != event.owner_task_id) return error.EngineQueueNotOwned;
            if (active_claim.queue_generation != event.generation) return error.EngineQueueGenerationMismatch;
            if (event.completion_sequence <= active_claim.queue_completion_sequence) return error.QueueCompletionStale;
        }

        const queue = &self.brokered_engine_queues[engineIndex(event.engine)];
        if (event.generation == queue.generation and
            event.completion_sequence < queue.completion_sequence)
        {
            return error.QueueCompletionStale;
        }
        if (event.generation == queue.generation and
            event.completion_interrupts_observed < queue.completion_interrupts_observed)
        {
            return error.QueueCompletionStale;
        }

        self.brokered_engine_queues_required = true;
        queue.* = event.toQueue();
    }

    pub fn completeBrokeredEngineQueue(
        self: *Controller,
        engine: Engine,
        owner_task_id: u64,
        generation: u32,
        completion_sequence: u64,
    ) Error!void {
        if (engine == .cpu) return error.EngineQueueNotOwned;
        const queue = &self.brokered_engine_queues[engineIndex(engine)];
        if (!queue.readyFor(owner_task_id)) return error.EngineQueueNotOwned;
        if (queue.generation != generation) return error.EngineQueueGenerationMismatch;
        if (completion_sequence <= queue.completion_sequence) return error.QueueCompletionStale;
        queue.completion_sequence = completion_sequence;
        queue.completion_interrupts_observed +|= 1;
    }

    pub fn claim(self: *Controller, request: ClaimRequest) Error!ClaimRecord {
        return self.claimWithSharedMemory(request, null);
    }

    pub fn claimWithSharedMemory(
        self: *Controller,
        request: ClaimRequest,
        shared: ?*shared_memory.Table,
    ) Error!ClaimRecord {
        const preferred_engine = preferredEngineFor(request.request);
        if (request.require_accelerator and preferred_engine != .cpu and self.activeEngineClaimId(preferred_engine) != 0) {
            return error.EngineBusy;
        }
        if (!request.require_accelerator and preferred_engine != .cpu and self.activeEngineClaimId(preferred_engine) != 0) {
            if (request.shared_memory_object_id != null) return error.ZeroCopyUnavailable;
            const claim_id = try self.nextReservableClaimId();
            var fallback = zeroClaim();
            fallback.id = claim_id;
            fallback.task_id = request.task_id;
            fallback.class = request.request.class;
            fallback.engine = .cpu;
            fallback.degraded = true;
            fallback.reason = .accelerator_unavailable;
            fallback.active = true;
            const record_claim = try self.upsertClaim(fallback);
            self.advanceNextClaimIdFrom(claim_id);
            self.markClaimActive(record_claim);
            return record_claim;
        }
        var decision = self.plan(request.request);
        if (decision.engine != .cpu and !self.engineQueueReadyFor(decision.engine, request.task_id)) {
            if (request.require_accelerator) return error.AcceleratorRequired;
            decision.engine = .cpu;
            decision.degraded = true;
            decision.zero_copy_allowed = false;
            decision.reason = .accelerator_unavailable;
        }
        if (request.require_accelerator and decision.engine == .cpu) return error.AcceleratorRequired;

        if (decision.engine != .cpu and self.activeEngineClaimId(decision.engine) != 0) {
            if (request.require_accelerator) return error.EngineBusy;
            decision.engine = .cpu;
            decision.degraded = true;
            decision.zero_copy_allowed = false;
            decision.reason = .accelerator_unavailable;
        }

        const claim_id = try self.nextReservableClaimId();
        var attached_object_id: ?ids.SharedMemoryId = null;
        errdefer if (attached_object_id) |object_id| {
            if (shared) |shared_table| {
                _ = shared_table.detachAccelerator(object_id, computeTargetFor(decision.engine)) catch false;
            }
        };
        if (request.shared_memory_object_id) |object_id| {
            if (decision.engine == .cpu or !decision.zero_copy_allowed) return error.ZeroCopyUnavailable;
            const shared_table = shared orelse return error.SharedMemoryTableRequired;
            try shared_table.attachAccelerator(object_id, computeTargetFor(decision.engine));
            attached_object_id = object_id;
        }

        var record = zeroClaim();
        record.id = claim_id;
        record.task_id = request.task_id;
        record.class = decision.class;
        record.engine = decision.engine;
        record.delayed = decision.delayed;
        record.degraded = decision.degraded;
        record.zero_copy = decision.zero_copy_allowed and request.shared_memory_object_id != null;
        record.reason = decision.reason;
        record.shared_memory_object_id = request.shared_memory_object_id;
        record.active = true;
        if (record.engine != .cpu and self.brokered_engine_queues_required) {
            const queue = self.brokeredQueueFor(record.engine);
            record.queue_generation = queue.generation;
            record.queue_completion_sequence = queue.completion_sequence;
        }
        const record_claim = try self.upsertClaim(record);
        attached_object_id = null;
        self.advanceNextClaimIdFrom(claim_id);
        self.markClaimActive(record_claim);
        return record_claim;
    }

    pub fn releaseClaim(
        self: *Controller,
        claim_id: u64,
        shared: ?*shared_memory.Table,
    ) Error!bool {
        const slot_index = self.claims.slotIndexOf(claim_id) orelse return error.ClaimNotFound;
        const slot = &self.claims.slots[slot_index];
        if (!slot.claim.active) return false;

        const record = slot.claim;
        try self.requireCompletionBeforeRelease(record);
        if (record.shared_memory_object_id) |object_id| {
            const shared_table = shared orelse return error.SharedMemoryTableRequired;
            _ = try shared_table.detachAccelerator(object_id, computeTargetFor(record.engine));
        }
        self.markClaimInactive(record);
        _ = self.claim_task_index.remove(claimTaskKey(record.task_id), slot_index);
        _ = self.claims.removeIndex(slot_index);
        return true;
    }

    pub fn revokeTaskClaims(self: *Controller, task_id: u64, shared: ?*shared_memory.Table) Error!u16 {
        var released: u16 = 0;
        const task_key = claimTaskKey(task_id);
        var slot_index = self.claim_task_index.head(task_key);
        while (slot_index != indexed_arena.no_index) {
            if (slot_index >= MAX_ENGINE_CLAIMS) native_util.impossibleByInvariant("claim task index points outside claim slots");
            const next_slot_index = self.claim_task_index.next(slot_index);
            const slot = &self.claims.slots[slot_index];
            if (slot.in_use and slot.claim.active and slot.claim.task_id == task_id) {
                const record = slot.claim;
                if (record.shared_memory_object_id) |object_id| {
                    const shared_table = shared orelse return error.SharedMemoryTableRequired;
                    _ = try shared_table.detachAccelerator(object_id, computeTargetFor(record.engine));
                }
                self.markClaimInactive(record);
                _ = self.claim_task_index.remove(task_key, slot_index);
                _ = self.claims.removeIndex(slot_index);
                released += 1;
            }
            slot_index = next_slot_index;
        }
        return released;
    }

    pub fn findActiveClaim(self: *const Controller, claim_id: u64) ?ClaimRecord {
        const slot = self.claims.getConst(claim_id) orelse return null;
        if (!slot.claim.active) return null;
        return slot.claim;
    }

    pub fn activeClaimCount(self: *const Controller) u16 {
        return self.active_claim_count;
    }

    pub fn plan(self: *const Controller, request: Request) Decision {
        return planWithState(self.state, self.availableEngines(), request);
    }

    fn upsertClaim(self: *Controller, record: ClaimRecord) Error!ClaimRecord {
        if (self.claims.slotIndexOf(record.id)) |slot_index| {
            const slot = &self.claims.slots[slot_index];
            if (slot.claim.task_id != record.task_id) {
                _ = self.claim_task_index.remove(claimTaskKey(slot.claim.task_id), slot_index);
                if (!self.claim_task_index.append(claimTaskKey(record.task_id), slot_index)) {
                    native_util.impossibleByInvariant("claim task index capacity covers claim slots");
                }
            }
            slot.claim = record;
            return slot.claim;
        }

        const slot_index = self.claims.reserveIndex(record.id) orelse return error.ClaimTableFull;
        if (!self.claim_task_index.append(claimTaskKey(record.task_id), slot_index)) {
            _ = self.claims.removeIndex(slot_index);
            return error.ClaimTableFull;
        }
        const slot = &self.claims.slots[slot_index];
        slot.claim = record;
        return slot.claim;
    }

    fn nextReservableClaimId(self: *Controller) Error!u64 {
        if (self.claims.countInUse() >= MAX_ENGINE_CLAIMS) return error.ClaimTableFull;
        if (self.next_claim_id == 0) return error.ClaimIdExhausted;
        if (self.claims.get(self.next_claim_id) != null) return error.ClaimIdExhausted;
        return self.next_claim_id;
    }

    fn advanceNextClaimIdFrom(self: *Controller, claim_id: u64) void {
        self.next_claim_id = claim_id +% 1;
    }

    fn availableEngines(self: *const Controller) EngineAvailability {
        const hardware_ready = self.hardwareQueueTelemetryReady();
        return .{
            .gpu = hardware_ready and self.state.gpu_available and self.activeEngineClaimId(.gpu) == 0 and self.engineQueueReadyFor(.gpu, null),
            .npu = hardware_ready and self.state.npu_available and self.activeEngineClaimId(.npu) == 0 and self.engineQueueReadyFor(.npu, null),
            .media = hardware_ready and self.state.media_available and self.activeEngineClaimId(.media) == 0 and self.engineQueueReadyFor(.media, null),
        };
    }

    fn engineQueueReadyFor(self: *const Controller, engine: Engine, task_id: ?u64) bool {
        if (engine == .cpu or !self.brokered_engine_queues_required) return true;
        const queue = self.brokeredQueueFor(engine);
        if (task_id) |owner_task_id| return queue.readyFor(owner_task_id);
        return queue.accepts_work and queue.broker_task_id != 0 and queue.owner_task_id != 0 and queue.generation != 0;
    }

    fn requireCompletionBeforeRelease(self: *const Controller, record: ClaimRecord) Error!void {
        if (!self.brokered_engine_queues_required or record.engine == .cpu) return;
        const queue = self.brokeredQueueFor(record.engine);
        if (queue.owner_task_id != record.task_id) return error.EngineQueueNotOwned;
        if (queue.generation != record.queue_generation) return error.EngineQueueGenerationMismatch;
        if (queue.completion_sequence <= record.queue_completion_sequence) return error.QueueCompletionMissing;
    }

    fn hardwareQueueTelemetryReady(self: *const Controller) bool {
        if (self.production_hardware_telemetry_required) {
            return self.last_telemetry_source == .hardware and self.last_hardware_evidence_complete;
        }
        return self.last_telemetry_source != .hardware or self.last_hardware_evidence_complete;
    }

    fn activeEngineClaimId(self: *const Controller, engine: Engine) u64 {
        return self.active_engine_claims[engineIndex(engine)];
    }

    fn markClaimActive(self: *Controller, record: ClaimRecord) void {
        self.active_claim_count += 1;
        if (record.engine != .cpu) {
            self.active_engine_claims[engineIndex(record.engine)] = record.id;
        }
    }

    fn markClaimInactive(self: *Controller, record: ClaimRecord) void {
        if (self.active_claim_count != 0) self.active_claim_count -= 1;
        if (record.engine != .cpu and self.active_engine_claims[engineIndex(record.engine)] == record.id) {
            self.active_engine_claims[engineIndex(record.engine)] = 0;
        }
    }
};

pub fn planWithState(state: SystemState, availability: EngineAvailability, request: Request) Decision {
    var decision = Decision{
        .class = request.class,
        .engine = .cpu,
        .delayed = false,
        .degraded = false,
        .zero_copy_allowed = false,
        .reason = .normal,
    };

    if (request.class != .emergency_system_critical) {
        if (request.expected_cpu_ticks != 0 and request.expected_cpu_ticks > state.cpu_budget_ticks) {
            decision.delayed = true;
            decision.degraded = true;
            decision.reason = .cpu_budget;
            return decision;
        }
        if (request.memory_bandwidth_units != 0 and request.memory_bandwidth_units > state.memory_bandwidth_units) {
            decision.degraded = true;
            if (request.class == .batch_compute or request.class == .background_light) {
                decision.delayed = true;
            }
            decision.reason = .memory_bandwidth;
            return decision;
        }
        if (shouldDelayForLowCarbonPower(state, request)) {
            decision.delayed = true;
            decision.degraded = true;
            decision.reason = .carbon_aware_delay;
            return decision;
        }
    }

    switch (request.class) {
        .emergency_system_critical => return decision,
        .foreground_interactive => {
            if (request.wants_gpu and availability.forEngine(.gpu)) {
                decision.engine = .gpu;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
            }
            if (state.thermal_pressure == .critical) {
                decision.degraded = true;
                decision.reason = .thermal_throttle;
            }
            return decision;
        },
        .media_export => {
            if (request.wants_media_engine and availability.forEngine(.media) and state.thermal_pressure != .critical) {
                decision.engine = .media;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
            } else if (request.wants_gpu and availability.forEngine(.gpu)) {
                decision.engine = .gpu;
                decision.zero_copy_allowed = request.shared_memory_bytes != 0;
                decision.degraded = state.thermal_pressure != .nominal;
                if (decision.degraded) decision.reason = .thermal_throttle;
            } else {
                decision.engine = .cpu;
                decision.degraded = true;
                decision.reason = .accelerator_unavailable;
            }
            if (state.battery_saver and decision.engine != .cpu) {
                decision.degraded = true;
                decision.reason = .battery_preserve;
            }
            return decision;
        },
        .batch_compute => {
            if (state.thermal_pressure == .critical) {
                decision.delayed = true;
                decision.degraded = true;
                decision.reason = .thermal_throttle;
                return decision;
            }
            if (state.battery_saver) {
                decision.delayed = true;
                decision.degraded = true;
                decision.reason = .battery_preserve;
                return decision;
            }
        },
        .background_light => {},
    }

    if (request.wants_npu) {
        if (state.privacy_mode and request.privacy_sensitive) {
            decision.degraded = true;
            decision.reason = .privacy_mode;
            return decision;
        }
        if (availability.forEngine(.npu) and !state.battery_saver and state.thermal_pressure == .nominal) {
            decision.engine = .npu;
            decision.zero_copy_allowed = request.shared_memory_bytes != 0;
            return decision;
        }
        decision.degraded = true;
        decision.reason = .accelerator_unavailable;
    } else if (request.wants_gpu and availability.forEngine(.gpu)) {
        decision.engine = .gpu;
        decision.zero_copy_allowed = request.shared_memory_bytes != 0;
    }

    return decision;
}

fn claimSlotId(slot: *const ClaimSlot) u64 {
    return slot.claim.id;
}

fn claimTaskKey(task_id: u64) u64 {
    return indexed_arena.nonZeroKey(task_id);
}

fn computeTargetFor(engine: Engine) shared_memory.ComputeTarget {
    return switch (engine) {
        .cpu => .cpu,
        .gpu => .gpu,
        .npu => .npu,
        .media => .media,
    };
}

fn engineIndex(engine: Engine) usize {
    return switch (engine) {
        .cpu => 0,
        .gpu => 1,
        .npu => 2,
        .media => 3,
    };
}

fn preferredEngineFor(request: Request) Engine {
    if (request.wants_media_engine) return .media;
    if (request.wants_npu) return .npu;
    if (request.wants_gpu) return .gpu;
    return .cpu;
}

fn sampleFromPlatformSignals(source: TelemetrySource, observed_tick: u64, signals: PlatformTelemetrySignals) TelemetrySample {
    return .{
        .source = source,
        .observed_tick = observed_tick,
        .thermal_pressure = signals.thermal_pressure,
        .battery_saver = signals.battery_saver,
        .privacy_mode = signals.privacy_mode,
        .gpu_available = signals.gpu_available,
        .npu_available = signals.npu_available,
        .media_available = signals.media_available,
        .cpu_budget_ticks = signals.cpu_budget_ticks,
        .memory_bandwidth_units = signals.memory_bandwidth_units,
        .grid_carbon_intensity_grams_per_kwh = signals.grid_carbon_intensity_grams_per_kwh,
    };
}

pub fn telemetrySampleIsFresh(
    current_source: TelemetrySource,
    current_observed_tick: u64,
    sample: TelemetrySample,
) bool {
    if (sample.source == .synthetic or current_source == .synthetic) return true;
    return sample.observed_tick >= current_observed_tick;
}

fn sampleFromLivePlatformCounters(observed_tick: u64, counters: LivePlatformCounters) TelemetrySample {
    const reserved_bytes = std.math.add(usize, counters.reserved_memory_bytes, counters.reserved_shared_memory_bytes) catch std.math.maxInt(usize);
    const available_memory_bytes = saturatingSubUsize(counters.memory_capacity_bytes, reserved_bytes);
    return .{
        .source = .hardware,
        .observed_tick = observed_tick,
        .thermal_pressure = thermalPressureFromMilliCelsius(counters.thermal_milli_celsius),
        .battery_saver = !counters.battery_charging and counters.battery_percent <= 20,
        .privacy_mode = counters.privacy_sensitive_task_count != 0,
        .gpu_available = counters.gpu_driver_online,
        .npu_available = counters.npu_driver_online,
        .media_available = counters.media_driver_online,
        .cpu_budget_ticks = saturatingSubTicks(counters.total_cpu_budget_ticks, counters.consumed_cpu_ticks),
        .memory_bandwidth_units = available_memory_bytes / units.bytes_per_kib,
        .grid_carbon_intensity_grams_per_kwh = counters.grid_carbon_intensity_grams_per_kwh,
        .hardware_evidence = counters.hardware_evidence,
    };
}

fn shouldDelayForLowCarbonPower(state: SystemState, request: Request) bool {
    if (!request.defer_for_low_carbon_power) return false;
    if (request.class == .foreground_interactive) return false;
    if (request.estimated_energy_milliwatt_hours == 0) return false;
    if (state.grid_carbon_intensity_grams_per_kwh == 0) return false;
    return state.grid_carbon_intensity_grams_per_kwh >= HIGH_CARBON_GRID_GRAMS_PER_KWH;
}

fn thermalPressureFromMilliCelsius(value: u32) ThermalPressure {
    if (value >= 90_000) return .critical;
    if (value >= 75_000) return .elevated;
    return .nominal;
}

fn saturatingSubTicks(value: u64, amount: u64) u64 {
    if (amount >= value) return 0;
    return value - amount;
}

fn saturatingSubUsize(value: usize, amount: usize) usize {
    if (amount >= value) return 0;
    return value - amount;
}

fn zeroClaim() ClaimRecord {
    return .{
        .id = 0,
        .task_id = 0,
        .class = .background_light,
        .engine = .cpu,
        .delayed = false,
        .degraded = false,
        .zero_copy = false,
        .reason = .normal,
        .shared_memory_object_id = null,
        .active = false,
        .queue_generation = 0,
        .queue_completion_sequence = 0,
    };
}

test "accelerator scheduler preserves responsiveness while degrading opportunistic work" {
    var controller = Controller.init();
    controller.configure(.{
        .thermal_pressure = .critical,
        .battery_saver = false,
        .privacy_mode = false,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    const interactive = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = units.kibibytes(8),
    });
    try std.testing.expect(!interactive.delayed);
    try std.testing.expectEqual(Engine.gpu, interactive.engine);
    try std.testing.expect(interactive.degraded);

    const batch = controller.plan(.{
        .class = .batch_compute,
        .wants_gpu = true,
    });
    try std.testing.expect(batch.delayed);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, batch.reason);
}

test "accelerator scheduler uses media engines and privacy mode falls back from npu" {
    var controller = Controller.init();

    const media_export_plan = controller.plan(.{
        .class = .media_export,
        .wants_gpu = true,
        .wants_media_engine = true,
        .shared_memory_bytes = units.kibibytes(16),
    });
    try std.testing.expectEqual(Engine.media, media_export_plan.engine);
    try std.testing.expect(media_export_plan.zero_copy_allowed);

    controller.configure(.{
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    const inference = controller.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    try std.testing.expectEqual(Engine.cpu, inference.engine);
    try std.testing.expect(inference.degraded);
    try std.testing.expectEqual(DecisionReason.privacy_mode, inference.reason);
}

test "accelerator scheduler uses cpu and memory bandwidth accounting signals" {
    var controller = Controller.init();
    controller.configure(.{
        .cpu_budget_ticks = 1_000,
        .memory_bandwidth_units = 200,
    });

    const over_cpu_budget = controller.plan(.{
        .class = .background_light,
        .expected_cpu_ticks = 2_000,
    });
    try std.testing.expect(over_cpu_budget.delayed);
    try std.testing.expect(over_cpu_budget.degraded);
    try std.testing.expectEqual(DecisionReason.cpu_budget, over_cpu_budget.reason);

    const memory_limited = controller.plan(.{
        .class = .batch_compute,
        .memory_bandwidth_units = 512,
    });
    try std.testing.expect(memory_limited.delayed);
    try std.testing.expect(memory_limited.degraded);
    try std.testing.expectEqual(DecisionReason.memory_bandwidth, memory_limited.reason);

    const emergency = controller.plan(.{
        .class = .emergency_system_critical,
        .expected_cpu_ticks = 10_000,
        .memory_bandwidth_units = 10_000,
    });
    try std.testing.expect(!emergency.delayed);
    try std.testing.expect(!emergency.degraded);
}

test "accelerator scheduler delays deferrable work for lower carbon power windows" {
    var controller = Controller.init();
    controller.configure(.{
        .grid_carbon_intensity_grams_per_kwh = 620,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    const deferrable_batch = controller.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
        .estimated_energy_milliwatt_hours = 2_000,
        .defer_for_low_carbon_power = true,
    });
    try std.testing.expect(deferrable_batch.delayed);
    try std.testing.expect(deferrable_batch.degraded);
    try std.testing.expectEqual(DecisionReason.carbon_aware_delay, deferrable_batch.reason);
    try std.testing.expectEqual(Engine.cpu, deferrable_batch.engine);

    const foreground = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = units.kibibytes(4),
        .estimated_energy_milliwatt_hours = 2_000,
        .defer_for_low_carbon_power = true,
    });
    try std.testing.expect(!foreground.delayed);
    try std.testing.expectEqual(Engine.gpu, foreground.engine);

    controller.configure(.{
        .grid_carbon_intensity_grams_per_kwh = 200,
        .npu_available = true,
    });
    const low_carbon_batch = controller.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
        .estimated_energy_milliwatt_hours = 2_000,
        .defer_for_low_carbon_power = true,
    });
    try std.testing.expect(!low_carbon_batch.delayed);
    try std.testing.expectEqual(Engine.npu, low_carbon_batch.engine);
}

test "accelerator scheduler consumes emulator telemetry samples" {
    var controller = Controller.init();
    var telemetry = EmulatedTelemetryDevice.init(.{
        .source = .synthetic,
        .observed_tick = 42,
        .thermal_pressure = .critical,
        .battery_saver = true,
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .cpu_budget_ticks = 500,
        .memory_bandwidth_units = 128,
        .grid_carbon_intensity_grams_per_kwh = 610,
    });
    const telemetry_provider = telemetry.telemetryProvider();
    try std.testing.expect(telemetry_provider.testOnly());
    try std.testing.expectEqual(TelemetryProviderRole.test_only, telemetry_provider.descriptor.role);
    const sample = telemetry_provider.read();
    try std.testing.expect(sample.observed());
    controller.configureFromTelemetry(sample);
    try std.testing.expect(controller.observedTelemetry());
    try std.testing.expectEqual(TelemetrySource.emulator, controller.last_telemetry_source);
    try std.testing.expectEqual(@as(u64, 42), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(@as(u16, 610), controller.state.grid_carbon_intensity_grams_per_kwh);
    try std.testing.expectEqual(@as(u32, 1), telemetry.read_count);

    const interactive = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = shared_memory.PAGE_SIZE,
    });
    try std.testing.expect(!interactive.delayed);
    try std.testing.expectEqual(Engine.gpu, interactive.engine);
    try std.testing.expect(interactive.degraded);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, interactive.reason);

    const privacy_sensitive = controller.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    try std.testing.expectEqual(Engine.cpu, privacy_sensitive.engine);
    try std.testing.expect(privacy_sensitive.degraded);
    try std.testing.expectEqual(DecisionReason.privacy_mode, privacy_sensitive.reason);

    const memory_limited = controller.plan(.{
        .class = .batch_compute,
        .memory_bandwidth_units = 256,
    });
    try std.testing.expect(memory_limited.delayed);
    try std.testing.expectEqual(DecisionReason.memory_bandwidth, memory_limited.reason);

    telemetry.update(.{
        .observed_tick = 43,
        .thermal_pressure = .nominal,
        .battery_saver = true,
        .media_available = true,
    });
    controller.configureFromProvider(telemetry.telemetryProvider());
    const media_export = controller.plan(.{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = units.kibibytes(8),
    });
    try std.testing.expectEqual(Engine.media, media_export.engine);
    try std.testing.expect(media_export.degraded);
    try std.testing.expectEqual(DecisionReason.battery_preserve, media_export.reason);
    try std.testing.expectEqual(@as(u64, 43), controller.last_telemetry_observed_tick);
}

test "accelerator scheduler consumes booted platform provider samples" {
    var controller = Controller.init();
    var provider = BootedPlatformTelemetryProvider.init(7, 88, .{
        .thermal_pressure = .critical,
        .battery_saver = true,
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
        .cpu_budget_ticks = 1_000,
        .memory_bandwidth_units = 32,
    });

    const provider_interface = provider.telemetryProvider();
    try std.testing.expect(!provider_interface.testOnly());
    try std.testing.expectEqual(TelemetryProviderRole.production, provider_interface.descriptor.role);
    controller.configureFromProvider(provider_interface);
    try std.testing.expect(controller.observedTelemetry());
    try std.testing.expectEqual(TelemetrySource.boot_provider, controller.last_telemetry_source);
    try std.testing.expectEqual(@as(u64, 88), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(@as(u32, 1), provider.read_count);

    const foreground = controller.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = shared_memory.PAGE_SIZE,
    });
    try std.testing.expect(!foreground.delayed);
    try std.testing.expectEqual(Engine.gpu, foreground.engine);
    try std.testing.expect(foreground.degraded);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, foreground.reason);

    const batch = controller.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
    });
    try std.testing.expect(batch.delayed);
    try std.testing.expectEqual(DecisionReason.thermal_throttle, batch.reason);

    try provider.observe(89, .{
        .thermal_pressure = .nominal,
        .battery_saver = true,
        .media_available = true,
    });
    controller.configureFromProvider(provider.telemetryProvider());
    const media_export = controller.plan(.{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = units.kibibytes(8),
    });
    try std.testing.expectEqual(Engine.media, media_export.engine);
    try std.testing.expect(media_export.degraded);
    try std.testing.expectEqual(DecisionReason.battery_preserve, media_export.reason);
    try std.testing.expectEqual(@as(u64, 89), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(@as(u32, 2), provider.read_count);
}

test "accelerator scheduler rejects stale production telemetry observations" {
    var provider = try BootedPlatformTelemetryProvider.initForBootedService(8, 80, 10, .{
        .total_cpu_budget_ticks = 1_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .gpu_driver_online = true,
        .npu_driver_online = false,
        .media_driver_online = true,
    });

    try std.testing.expectError(error.TelemetryObservationStale, provider.observeLive(80, 9, .{
        .total_cpu_budget_ticks = 1_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .gpu_driver_online = false,
        .npu_driver_online = true,
        .media_driver_online = false,
    }));
    try std.testing.expectEqual(@as(u32, 1), provider.rejected_observation_count);
    try std.testing.expectEqual(@as(u64, 10), provider.current.observed_tick);
    try std.testing.expect(provider.current.gpu_available);
    try std.testing.expect(!provider.current.npu_available);

    try provider.observeLive(80, 11, .{
        .total_cpu_budget_ticks = 1_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .gpu_driver_online = false,
        .npu_driver_online = true,
        .media_driver_online = false,
    });
    try std.testing.expectEqual(@as(u64, 11), provider.current.observed_tick);
    try std.testing.expect(!provider.current.gpu_available);
    try std.testing.expect(provider.current.npu_available);
}

test "accelerator scheduler derives hardware telemetry from booted live counters" {
    try std.testing.expectError(error.TelemetryProviderUnauthorized, BootedPlatformTelemetryProvider.initForBootedService(0, 70, 99, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(128),
    }));
    var provider = try BootedPlatformTelemetryProvider.initForBootedService(8, 70, 100, .{
        .total_cpu_budget_ticks = 10_000,
        .consumed_cpu_ticks = 3_000,
        .memory_capacity_bytes = units.kibibytes(128),
        .reserved_memory_bytes = units.kibibytes(64),
        .reserved_shared_memory_bytes = units.kibibytes(16),
        .gpu_driver_online = true,
        .npu_driver_online = false,
        .media_driver_online = true,
        .thermal_milli_celsius = 82_000,
        .battery_percent = 15,
        .battery_charging = false,
        .privacy_sensitive_task_count = 1,
        .grid_carbon_intensity_grams_per_kwh = 590,
    });
    var controller = Controller.init();
    controller.configureFromProvider(provider.telemetryProvider());
    try std.testing.expect(controller.observedTelemetry());
    try std.testing.expectEqual(TelemetrySource.hardware, controller.last_telemetry_source);
    try std.testing.expectEqual(@as(u64, 100), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(ThermalPressure.elevated, controller.state.thermal_pressure);
    try std.testing.expect(controller.state.battery_saver);
    try std.testing.expect(controller.state.privacy_mode);
    try std.testing.expect(controller.state.gpu_available);
    try std.testing.expect(!controller.state.npu_available);
    try std.testing.expect(controller.state.media_available);
    try std.testing.expectEqual(@as(u64, 7_000), controller.state.cpu_budget_ticks);
    try std.testing.expectEqual(@as(usize, 48), controller.state.memory_bandwidth_units);
    try std.testing.expectEqual(@as(u16, 590), controller.state.grid_carbon_intensity_grams_per_kwh);
    try std.testing.expectEqual(@as(u32, 1), provider.live_observation_count);
    try std.testing.expectEqual(@as(u32, 1), provider.read_count);

    try std.testing.expectError(error.TelemetryProviderUnauthorized, provider.observe(101, .{
        .thermal_pressure = .critical,
        .battery_saver = true,
    }));
    try std.testing.expectEqual(@as(u32, 1), provider.rejected_observation_count);

    try std.testing.expectError(error.TelemetryProviderUnauthorized, provider.observeLive(71, 101, .{
        .total_cpu_budget_ticks = 10_000,
        .memory_capacity_bytes = units.kibibytes(128),
    }));
    try std.testing.expectEqual(@as(u32, 2), provider.rejected_observation_count);

    try provider.observeLive(70, 102, .{
        .total_cpu_budget_ticks = 10_000,
        .consumed_cpu_ticks = 2_000,
        .memory_capacity_bytes = units.kibibytes(256),
        .reserved_memory_bytes = units.kibibytes(64),
        .gpu_driver_online = true,
        .npu_driver_online = true,
        .media_driver_online = false,
        .thermal_milli_celsius = 91_000,
        .battery_percent = 80,
        .battery_charging = true,
    });
    controller.configureFromProvider(provider.telemetryProvider());
    try std.testing.expectEqual(@as(u64, 102), controller.last_telemetry_observed_tick);
    try std.testing.expectEqual(ThermalPressure.critical, controller.state.thermal_pressure);
    try std.testing.expect(!controller.state.battery_saver);
    try std.testing.expect(controller.state.npu_available);
    try std.testing.expect(!controller.state.media_available);
    try std.testing.expectEqual(@as(u64, 8_000), controller.state.cpu_budget_ticks);
    try std.testing.expectEqual(@as(usize, 192), controller.state.memory_bandwidth_units);
    try std.testing.expectEqual(@as(u32, 2), provider.live_observation_count);
    try std.testing.expectEqual(@as(u32, 2), provider.read_count);
}

test "accelerator scheduler production mode requires complete hardware telemetry before accelerator claims" {
    var controller = Controller.init();
    controller.requireProductionHardwareTelemetryForAccelerators();
    controller.configure(.{
        .media_available = true,
    });

    try std.testing.expectError(error.AcceleratorRequired, controller.claim(.{
        .task_id = 91,
        .request = .{
            .class = .media_export,
            .wants_media_engine = true,
        },
        .require_accelerator = true,
    }));

    var emulator = EmulatedTelemetryDevice.init(.{
        .observed_tick = 1,
        .media_available = true,
    });
    controller.configureFromProvider(emulator.telemetryProvider());
    try std.testing.expectEqual(TelemetrySource.emulator, controller.last_telemetry_source);
    try std.testing.expectError(error.AcceleratorRequired, controller.claim(.{
        .task_id = 91,
        .request = .{
            .class = .media_export,
            .wants_media_engine = true,
        },
        .require_accelerator = true,
    }));

    controller.configureFromTelemetry(.{
        .source = .hardware,
        .observed_tick = 2,
        .media_available = true,
    });
    try std.testing.expect(!controller.last_hardware_evidence_complete);
    try std.testing.expectError(error.AcceleratorRequired, controller.claim(.{
        .task_id = 91,
        .request = .{
            .class = .media_export,
            .wants_media_engine = true,
        },
        .require_accelerator = true,
    }));

    controller.configureFromTelemetry(.{
        .source = .hardware,
        .observed_tick = 3,
        .media_available = true,
        .hardware_evidence = .{
            .target_id = "nuc11tnki5",
            .reader_generation = 7,
            .acpi_observed = true,
            .thermal_observed = true,
            .battery_observed = true,
            .accelerator_observed = true,
            .grid_carbon_observed = true,
        },
    });
    const claim = try controller.claim(.{
        .task_id = 91,
        .request = .{
            .class = .media_export,
            .wants_media_engine = true,
        },
        .require_accelerator = true,
    });
    try std.testing.expectEqual(Engine.media, claim.engine);
}

test "accelerator scheduler tracks exclusive engine claims and zero-copy attachments" {
    var controller = Controller.init();
    var shared = shared_memory.Table.init();
    const object = try shared.createWithAccess(ids.task(9), units.kibibytes(32), .{
        .media = true,
        .gpu = true,
    });

    const claim = try controller.claimWithSharedMemory(.{
        .task_id = 9,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = units.kibibytes(32),
        },
        .require_accelerator = true,
        .shared_memory_object_id = object.id,
    }, &shared);
    try std.testing.expectEqual(Engine.media, claim.engine);
    try std.testing.expect(claim.zero_copy);
    try std.testing.expect(try shared.isAcceleratorAttached(object.id, .media));
    const media_mapping = try shared.acceleratorMappingDescriptor(object.id, .media);
    try std.testing.expect(media_mapping.zero_copy);
    try std.testing.expectEqual(object.page_base, media_mapping.page_base);
    try std.testing.expectEqual(@as(usize, 8), media_mapping.page_count);
    try shared.validateAcceleratorMappingDescriptor(media_mapping, .media);
    try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());

    try std.testing.expectError(error.EngineBusy, controller.claim(.{
        .task_id = 10,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = units.kibibytes(32),
        },
        .require_accelerator = true,
    }));

    const degraded = try controller.claim(.{
        .task_id = 11,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = units.kibibytes(32),
        },
    });
    try std.testing.expectEqual(Engine.cpu, degraded.engine);
    try std.testing.expect(degraded.degraded);

    try std.testing.expect(try controller.releaseClaim(claim.id, &shared));
    try std.testing.expect(!(try shared.isAcceleratorAttached(object.id, .media)));
    try std.testing.expectError(error.AcceleratorNotAttached, shared.acceleratorMappingDescriptor(object.id, .media));
    try std.testing.expectError(error.AcceleratorNotAttached, shared.validateAcceleratorMappingDescriptor(media_mapping, .media));
    try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());
    try std.testing.expect(try controller.releaseClaim(degraded.id, null));
    try std.testing.expectEqual(@as(u16, 0), controller.activeClaimCount());
}

test "accelerator scheduler gates brokered engine queues on ownership and completion" {
    var controller = Controller.init();
    controller.configure(.{
        .npu_available = true,
    });
    controller.requireBrokeredEngineQueues();

    try std.testing.expectError(error.AcceleratorRequired, controller.claim(.{
        .task_id = 44,
        .request = .{
            .class = .batch_compute,
            .wants_npu = true,
        },
        .require_accelerator = true,
    }));

    try std.testing.expect(!controller.configureBrokeredEngineQueue(.npu, .{
        .broker_task_id = 700,
        .owner_task_id = 44,
        .generation = 1,
        .completion_sequence = 9,
        .accepts_work = true,
    }));

    try std.testing.expect(controller.configureBrokeredEngineQueue(.npu, .{
        .broker_task_id = 700,
        .owner_task_id = 45,
        .generation = 1,
        .completion_sequence = 10,
        .completion_interrupts_observed = 1,
        .accepts_work = true,
    }));
    try std.testing.expectError(error.AcceleratorRequired, controller.claim(.{
        .task_id = 44,
        .request = .{
            .class = .batch_compute,
            .wants_npu = true,
        },
        .require_accelerator = true,
    }));

    try std.testing.expect(controller.configureBrokeredEngineQueue(.npu, .{
        .broker_task_id = 700,
        .owner_task_id = 44,
        .generation = 2,
        .completion_sequence = 20,
        .completion_interrupts_observed = 2,
        .accepts_work = true,
    }));
    const claim = try controller.claim(.{
        .task_id = 44,
        .request = .{
            .class = .batch_compute,
            .wants_npu = true,
        },
        .require_accelerator = true,
    });
    try std.testing.expectEqual(Engine.npu, claim.engine);
    try std.testing.expectEqual(@as(u32, 2), claim.queue_generation);
    try std.testing.expectEqual(@as(u64, 20), claim.queue_completion_sequence);
    try std.testing.expectError(error.QueueCompletionMissing, controller.releaseClaim(claim.id, null));
    try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());
    try std.testing.expectError(error.EngineQueueNotOwned, controller.completeBrokeredEngineQueue(.npu, 45, 2, 21));
    try std.testing.expectError(error.EngineQueueGenerationMismatch, controller.completeBrokeredEngineQueue(.npu, 44, 3, 21));
    try std.testing.expectError(error.QueueCompletionStale, controller.completeBrokeredEngineQueue(.npu, 44, 2, 20));
    try controller.completeBrokeredEngineQueue(.npu, 44, 2, 21);
    try std.testing.expect(try controller.releaseClaim(claim.id, null));
    try std.testing.expectEqual(@as(u16, 0), controller.activeClaimCount());
}

test "accelerator scheduler consumes brokered driver queue events" {
    var controller = Controller.init();
    controller.configure(.{
        .gpu_available = true,
    });
    controller.requireBrokeredEngineQueues();

    try std.testing.expectError(error.InvalidEngineQueueEvent, controller.observeBrokeredEngineQueueEvent(.{
        .engine = .gpu,
        .broker_task_id = 810,
        .owner_task_id = 81,
        .generation = 1,
        .completion_sequence = 30,
        .completion_interrupts_observed = 0,
        .accepts_work = true,
    }));

    try controller.observeBrokeredEngineQueueEvent(.{
        .engine = .gpu,
        .broker_task_id = 810,
        .owner_task_id = 81,
        .generation = 3,
        .completion_sequence = 40,
        .completion_interrupts_observed = 4,
        .accepts_work = true,
    });
    try std.testing.expectEqual(@as(u32, 4), controller.brokeredQueueFor(.gpu).completion_interrupts_observed);

    const claim = try controller.claim(.{
        .task_id = 81,
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
        },
        .require_accelerator = true,
    });
    try std.testing.expectEqual(Engine.gpu, claim.engine);
    try std.testing.expectEqual(@as(u32, 3), claim.queue_generation);
    try std.testing.expectEqual(@as(u64, 40), claim.queue_completion_sequence);
    try std.testing.expectError(error.QueueCompletionMissing, controller.releaseClaim(claim.id, null));

    try std.testing.expectError(error.EngineQueueNotOwned, controller.observeBrokeredEngineQueueEvent(.{
        .engine = .gpu,
        .broker_task_id = 810,
        .owner_task_id = 82,
        .generation = 3,
        .completion_sequence = 41,
        .completion_interrupts_observed = 5,
        .accepts_work = true,
    }));
    try std.testing.expectError(error.EngineQueueGenerationMismatch, controller.observeBrokeredEngineQueueEvent(.{
        .engine = .gpu,
        .broker_task_id = 810,
        .owner_task_id = 81,
        .generation = 4,
        .completion_sequence = 41,
        .completion_interrupts_observed = 5,
        .accepts_work = true,
    }));
    try std.testing.expectError(error.QueueCompletionStale, controller.observeBrokeredEngineQueueEvent(.{
        .engine = .gpu,
        .broker_task_id = 810,
        .owner_task_id = 81,
        .generation = 3,
        .completion_sequence = 40,
        .completion_interrupts_observed = 5,
        .accepts_work = true,
    }));

    try controller.observeBrokeredEngineQueueEvent(.{
        .engine = .gpu,
        .broker_task_id = 810,
        .owner_task_id = 81,
        .generation = 3,
        .completion_sequence = 41,
        .completion_interrupts_observed = 5,
        .accepts_work = true,
    });
    try std.testing.expect(try controller.releaseClaim(claim.id, null));
    try std.testing.expectEqual(@as(u16, 0), controller.activeClaimCount());
}

test "accelerator scheduler reuses released claim slots and revokes through task index" {
    var controller = Controller.init();

    var iteration: usize = 0;
    while (iteration < MAX_ENGINE_CLAIMS + 2) : (iteration += 1) {
        const claim = try controller.claim(.{
            .task_id = 70,
            .request = .{ .class = .background_light },
        });
        try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());
        try std.testing.expect(try controller.releaseClaim(claim.id, null));
        try std.testing.expectEqual(@as(u16, 0), controller.activeClaimCount());
    }

    _ = try controller.claim(.{
        .task_id = 71,
        .request = .{ .class = .background_light },
    });
    _ = try controller.claim(.{
        .task_id = 71,
        .request = .{ .class = .batch_compute },
    });
    _ = try controller.claim(.{
        .task_id = 72,
        .request = .{ .class = .foreground_interactive },
    });
    try std.testing.expectEqual(@as(u16, 3), controller.activeClaimCount());
    try std.testing.expectEqual(@as(u16, 2), try controller.revokeTaskClaims(71, null));
    try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());
}

test "accelerator scheduler claim ids stop at exhaustion" {
    var controller = Controller.init();
    controller.next_claim_id = std.math.maxInt(u64);

    const max_claim = try controller.claim(.{
        .task_id = 90,
        .request = .{ .class = .background_light },
    });
    try std.testing.expectEqual(std.math.maxInt(u64), max_claim.id);
    try std.testing.expectEqual(@as(u64, 0), controller.next_claim_id);
    try std.testing.expect(controller.findActiveClaim(0) == null);
    try std.testing.expect(try controller.releaseClaim(max_claim.id, null));
    try std.testing.expectEqual(@as(u16, 0), controller.activeClaimCount());

    try std.testing.expectError(error.ClaimIdExhausted, controller.claim(.{
        .task_id = 91,
        .request = .{ .class = .batch_compute },
    }));
    try std.testing.expectEqual(@as(u64, 0), controller.next_claim_id);
    try std.testing.expectEqual(@as(u16, 0), controller.activeClaimCount());

    var full_controller = Controller.init();
    for (0..MAX_ENGINE_CLAIMS) |index| {
        _ = try full_controller.claim(.{
            .task_id = @intCast(900 + index),
            .request = .{ .class = .background_light },
        });
    }
    const next_before_full = full_controller.next_claim_id;
    try std.testing.expectError(error.ClaimTableFull, full_controller.claim(.{
        .task_id = 999,
        .request = .{ .class = .background_light },
    }));
    try std.testing.expectEqual(next_before_full, full_controller.next_claim_id);
}

test "accelerator scheduler claim capacity preflights shared memory attachment" {
    var controller = Controller.init();
    for (0..MAX_ENGINE_CLAIMS) |index| {
        _ = try controller.claim(.{
            .task_id = @intCast(1000 + index),
            .request = .{ .class = .background_light },
        });
    }

    var shared = shared_memory.Table.init();
    const object = try shared.createWithAccess(ids.task(1001), units.kibibytes(32), .{
        .media = true,
    });
    const next_before_full = controller.next_claim_id;
    try std.testing.expectError(error.ClaimTableFull, controller.claimWithSharedMemory(.{
        .task_id = 1001,
        .request = .{
            .class = .media_export,
            .wants_media_engine = true,
            .shared_memory_bytes = units.kibibytes(32),
        },
        .require_accelerator = true,
        .shared_memory_object_id = object.id,
    }, &shared));
    try std.testing.expectEqual(next_before_full, controller.next_claim_id);
    try std.testing.expect(!(try shared.isAcceleratorAttached(object.id, .media)));
}
