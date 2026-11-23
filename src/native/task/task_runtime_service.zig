const std = @import("std");
const principal = @import("../core/principal.zig");
const task_runtime = @import("task_runtime.zig");
const units = @import("../core/units.zig");
const native_util = @import("../core/util.zig");
const table_backing = @import("../core/table_backing.zig");

pub const CheckpointStore = struct {
    checkpoint_state: table_backing.Lazy(task_runtime.Snapshot, null) = .{},
    has_checkpoint: bool = false,
    last_checkpoint_tick: u64 = 0,

    pub fn reset(self: *CheckpointStore) void {
        self.checkpoint_state.release();
        self.has_checkpoint = false;
        self.last_checkpoint_tick = 0;
    }

    fn prepareSnapshot(self: *CheckpointStore) error{NoSpaceLeft}!*task_runtime.Snapshot {
        return self.checkpoint_state.ensure();
    }

    fn snapshotConst(self: *const CheckpointStore) ?*const task_runtime.Snapshot {
        return self.checkpoint_state.get();
    }
};

comptime {
    if (@sizeOf(CheckpointStore) > 24) {
        @compileError("heap-backed task checkpoint stores exceed their compact layout");
    }
}

pub const Service = struct {
    service_id: u64 = 0,
    owner: principal.PrincipalId = .{ .kind = .service, .serial = 0 },
    runtime: *task_runtime.Runtime,
    checkpoint_store: ?*CheckpointStore = null,
    has_checkpoint: bool = false,
    restart_generation: u32 = 0,
    last_checkpoint_tick: u64 = 0,
    last_restart_tick: u64 = 0,

    pub fn init(runtime: *task_runtime.Runtime) Service {
        return .{
            .runtime = runtime,
        };
    }

    pub fn initInPlace(self: *Service, runtime: *task_runtime.Runtime) void {
        self.service_id = 0;
        self.owner = .{ .kind = .service, .serial = 0 };
        self.runtime = runtime;
        self.checkpoint_store = null;
        self.has_checkpoint = false;
        self.restart_generation = 0;
        self.last_checkpoint_tick = 0;
        self.last_restart_tick = 0;
    }

    pub fn initWithStoreInPlace(self: *Service, runtime: *task_runtime.Runtime, checkpoint_store: *CheckpointStore) void {
        self.initInPlace(runtime);
        self.checkpoint_store = checkpoint_store;
        if (checkpoint_store.has_checkpoint) {
            self.has_checkpoint = true;
            self.last_checkpoint_tick = checkpoint_store.last_checkpoint_tick;
        }
    }

    pub fn initWithStore(runtime: *task_runtime.Runtime, checkpoint_store: *CheckpointStore) Service {
        var service: Service = undefined;
        service.initWithStoreInPlace(runtime, checkpoint_store);
        return service;
    }

    pub fn bind(self: *Service, service_id: u64, owner: principal.PrincipalId) void {
        self.service_id = service_id;
        self.owner = owner;
    }

    pub fn runtimePtr(self: *Service) *task_runtime.Runtime {
        return self.runtime;
    }

    pub fn checkpoint(self: *Service, tick: u64) error{NoSpaceLeft}!void {
        if (self.checkpoint_store) |checkpoint_store| {
            const checkpoint_state = try checkpoint_store.prepareSnapshot();
            self.runtime.writeSnapshot(checkpoint_state);
            checkpoint_store.has_checkpoint = true;
            checkpoint_store.last_checkpoint_tick = tick;
            self.has_checkpoint = true;
            self.last_checkpoint_tick = tick;
        }
    }

    pub fn restartFromCheckpoint(self: *Service, tick: u64) bool {
        const checkpoint_store = self.checkpoint_store orelse return false;
        if (!checkpoint_store.has_checkpoint) return false;
        const checkpoint_state = checkpoint_store.snapshotConst() orelse
            native_util.impossibleByInvariant("checkpointed task runtime retains snapshot backing");

        self.runtime.restoreFromSnapshot(checkpoint_state) catch return false;
        self.has_checkpoint = true;
        self.last_checkpoint_tick = checkpoint_store.last_checkpoint_tick;
        self.restart_generation += 1;
        self.last_restart_tick = tick;
        return true;
    }
};

test "task runtime service restores checkpointed task state on restart" {
    var checkpoint_store = CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var service = Service.initWithStore(&runtime, &checkpoint_store);
    service.bind(44, .{ .kind = .service, .serial = 2 });

    const owner = principal.PrincipalId{ .kind = .app, .serial = 7 };
    const budget = task_runtime.ResourceBudget{
        .cpu_time_ticks = 4_000,
        .memory_bytes = units.kibibytes(128),
        .endpoint_slots = 4,
        .shared_memory_bytes = units.kibibytes(8),
        .background_allowed = false,
    };
    const baseline = try runtime.createTask(.{
        .owner = owner,
        .component_class = .app_component,
        .budget = budget,
        .local_only = true,
        .initial_component = .{
            .label = "baseline",
            .entry = "app.baseline",
        },
    });

    try service.checkpoint(20);
    _ = try runtime.createTask(.{
        .owner = owner,
        .component_class = .app_component,
        .budget = budget,
        .local_only = true,
        .initial_component = .{
            .label = "after-checkpoint",
            .entry = "app.after.checkpoint",
        },
    });

    try std.testing.expect(service.restartFromCheckpoint(30));
    try std.testing.expectEqual(@as(u32, 1), service.restart_generation);
    try std.testing.expectEqual(@as(u64, 30), service.last_restart_tick);
    try std.testing.expect(runtime.find(baseline.id) != null);
    try std.testing.expect(runtime.find(2) == null);
}

test "task runtime service refuses restart before a checkpoint exists" {
    var runtime = task_runtime.Runtime.init();
    var service = Service.init(&runtime);

    try std.testing.expect(!service.restartFromCheckpoint(10));
    try std.testing.expectEqual(@as(u32, 0), service.restart_generation);
}

test "task checkpoint reset wipes invalid state before reuse" {
    var checkpoint_store = CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var service = Service.initWithStore(&runtime, &checkpoint_store);
    _ = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 70 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 2,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
    });
    try service.checkpoint(20);
    try std.testing.expect(checkpoint_store.has_checkpoint);

    checkpoint_store.reset();
    try std.testing.expect(!checkpoint_store.has_checkpoint);
    try std.testing.expectEqual(@as(u64, 0), checkpoint_store.last_checkpoint_tick);
    try std.testing.expect(checkpoint_store.checkpoint_state.get() == null);

    var restarted = Service.initWithStore(&runtime, &checkpoint_store);
    try std.testing.expect(!restarted.restartFromCheckpoint(21));
    try restarted.checkpoint(22);
    try std.testing.expect(restarted.restartFromCheckpoint(23));
}

test "task runtime service can restore a persisted checkpoint after service re-instantiation" {
    var checkpoint_store = CheckpointStore{};
    var checkpointed_runtime = task_runtime.Runtime.init();
    var service = Service.initWithStore(&checkpointed_runtime, &checkpoint_store);
    service.bind(55, .{ .kind = .service, .serial = 3 });

    const owner = principal.PrincipalId{ .kind = .app, .serial = 8 };
    const budget = task_runtime.ResourceBudget{
        .cpu_time_ticks = 2_000,
        .memory_bytes = units.kibibytes(64),
        .endpoint_slots = 4,
        .shared_memory_bytes = units.kibibytes(4),
        .background_allowed = false,
    };
    const task = try checkpointed_runtime.createTask(.{
        .owner = owner,
        .component_class = .app_component,
        .budget = budget,
        .local_only = true,
        .initial_component = .{
            .label = "checkpointed",
            .entry = "app.checkpointed",
        },
    });
    _ = try checkpointed_runtime.attachComponent(task.id, .{
        .label = "sidecar",
        .entry = "app.sidecar",
    }, 43);
    try checkpointed_runtime.grantCapability(task.id, 91);
    try service.checkpoint(44);

    var restarted_runtime = task_runtime.Runtime.init();
    var restarted = Service.initWithStore(&restarted_runtime, &checkpoint_store);
    restarted.bind(55, .{ .kind = .service, .serial = 3 });

    try std.testing.expect(restarted.restartFromCheckpoint(45));
    try std.testing.expectEqual(@as(u64, 44), restarted.last_checkpoint_tick);
    try std.testing.expectEqual(@as(u32, 1), restarted.restart_generation);
    const restored = restarted_runtime.find(task.id).?;
    try std.testing.expectEqual(@as(usize, 2), restored.execution_component_count);
    try std.testing.expectEqualStrings("sidecar", restored.executionComponents()[1].labelSlice());
    try std.testing.expectEqual(@as(usize, 0), restored.capability_count);
}
