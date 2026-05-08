const std = @import("std");
const ids = @import("../core/ids.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");

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
};

pub const Error = shared_memory.Error || error{
    AcceleratorRequired,
    ClaimNotFound,
    ClaimTableFull,
    EngineBusy,
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
    next_claim_id: u64 = 1,
    claims: ClaimArena = ClaimArena.init(),
    claim_task_index: ClaimTaskIndex = ClaimTaskIndex.init(),
    active_engine_claims: [ENGINE_COUNT]u64 = [_]u64{0} ** ENGINE_COUNT,
    active_claim_count: u16 = 0,

    pub fn init() Controller {
        return .{};
    }

    pub fn configure(self: *Controller, state: SystemState) void {
        self.state = state;
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
            var fallback = zeroClaim();
            fallback.id = self.allocateClaimId();
            fallback.task_id = request.task_id;
            fallback.class = request.request.class;
            fallback.engine = .cpu;
            fallback.degraded = true;
            fallback.reason = .accelerator_unavailable;
            fallback.active = true;
            const record_claim = try self.upsertClaim(fallback);
            self.markClaimActive(record_claim);
            return record_claim;
        }
        var decision = self.plan(request.request);
        if (request.require_accelerator and decision.engine == .cpu) return error.AcceleratorRequired;

        if (decision.engine != .cpu and self.activeEngineClaimId(decision.engine) != 0) {
            if (request.require_accelerator) return error.EngineBusy;
            decision.engine = .cpu;
            decision.degraded = true;
            decision.zero_copy_allowed = false;
            decision.reason = .accelerator_unavailable;
        }

        if (request.shared_memory_object_id) |object_id| {
            if (decision.engine == .cpu or !decision.zero_copy_allowed) return error.ZeroCopyUnavailable;
            const shared_table = shared orelse return error.SharedMemoryTableRequired;
            try shared_table.attachAccelerator(object_id, computeTargetFor(decision.engine));
        }

        var record = zeroClaim();
        record.id = self.allocateClaimId();
        record.task_id = request.task_id;
        record.class = decision.class;
        record.engine = decision.engine;
        record.delayed = decision.delayed;
        record.degraded = decision.degraded;
        record.zero_copy = decision.zero_copy_allowed and request.shared_memory_object_id != null;
        record.reason = decision.reason;
        record.shared_memory_object_id = request.shared_memory_object_id;
        record.active = true;
        const record_claim = try self.upsertClaim(record);
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
        if (record.shared_memory_object_id) |object_id| {
            const shared_table = shared orelse return error.SharedMemoryTableRequired;
            _ = try shared_table.detachAccelerator(object_id, computeTargetFor(record.engine));
        }
        self.markClaimInactive(record);
        _ = self.claim_task_index.remove(claimTaskKey(record.task_id), slot_index);
        _ = self.claims.removeIndex(slot_index);
        self.claims.clearDirty();
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
                self.claims.clearDirty();
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
            self.claims.clearDirty();
            return slot.claim;
        }

        const slot_index = self.claims.reserveIndex(record.id) orelse return error.ClaimTableFull;
        if (!self.claim_task_index.append(claimTaskKey(record.task_id), slot_index)) {
            _ = self.claims.removeIndex(slot_index);
            return error.ClaimTableFull;
        }
        const slot = &self.claims.slots[slot_index];
        slot.claim = record;
        self.claims.clearDirty();
        return slot.claim;
    }

    fn allocateClaimId(self: *Controller) u64 {
        defer self.next_claim_id += 1;
        return self.next_claim_id;
    }

    fn availableEngines(self: *const Controller) EngineAvailability {
        return .{
            .gpu = self.state.gpu_available and self.activeEngineClaimId(.gpu) == 0,
            .npu = self.state.npu_available and self.activeEngineClaimId(.npu) == 0,
            .media = self.state.media_available and self.activeEngineClaimId(.media) == 0,
        };
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
        .shared_memory_bytes = 8192,
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
        .shared_memory_bytes = 16 * 1024,
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

test "accelerator scheduler tracks exclusive engine claims and zero-copy attachments" {
    var controller = Controller.init();
    var shared = shared_memory.Table.init();
    const object = try shared.createWithAccess(ids.task(9), 32 * 1024, .{
        .media = true,
        .gpu = true,
    });

    const claim = try controller.claimWithSharedMemory(.{
        .task_id = 9,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = 32 * 1024,
        },
        .require_accelerator = true,
        .shared_memory_object_id = object.id,
    }, &shared);
    try std.testing.expectEqual(Engine.media, claim.engine);
    try std.testing.expect(claim.zero_copy);
    try std.testing.expect(try shared.isAcceleratorAttached(object.id, .media));
    try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());

    try std.testing.expectError(error.EngineBusy, controller.claim(.{
        .task_id = 10,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = 32 * 1024,
        },
        .require_accelerator = true,
    }));

    const degraded = try controller.claim(.{
        .task_id = 11,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = 32 * 1024,
        },
    });
    try std.testing.expectEqual(Engine.cpu, degraded.engine);
    try std.testing.expect(degraded.degraded);

    try std.testing.expect(try controller.releaseClaim(claim.id, &shared));
    try std.testing.expect(!(try shared.isAcceleratorAttached(object.id, .media)));
    try std.testing.expectEqual(@as(u16, 1), controller.activeClaimCount());
    try std.testing.expect(try controller.releaseClaim(degraded.id, null));
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
