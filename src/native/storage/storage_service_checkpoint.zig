const builtin = @import("builtin");
const std = @import("std");
const object_store = @import("object_store.zig");
const root = @import("root");
const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const storage_volume = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("storage_volume.zig");
const workspace = @import("workspace.zig");

const MAX_CHECKPOINT_ATTEMPTS: u8 = 2;

const shares_root_volume = builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume");
const CheckpointVolume = if (shares_root_volume) void else storage_volume.Volume;

pub const CheckpointStore = struct {
    store: object_store.Store = object_store.Store.init(),
    workspaces: workspace.Directory = workspace.Directory.init(),
    has_persisted_state: bool = false,
    dirty: bool = false,
    last_checkpoint_generation: u64 = 0,
    last_checkpoint_error: ?storage_volume.Error = null,
    checkpoint_retry_count: u64 = 0,
    checkpoint_volume: CheckpointVolume = if (shares_root_volume) {} else storage_volume.Volume.init(),

    fn volumePtr(self: *CheckpointStore) *storage_volume.Volume {
        if (comptime shares_root_volume) {
            return storage_volume.defaultVolume();
        }
        return &self.checkpoint_volume;
    }

    pub fn adoptRootVolume(self: *CheckpointStore, root_volume: *storage_volume.Volume) void {
        if (comptime shares_root_volume) {
            std.debug.assert(root_volume == storage_volume.defaultVolume());
        } else {
            self.checkpoint_volume.adoptAttachedBackendFrom(root_volume);
        }
    }

    pub fn hasCachedPersistentState(self: *const CheckpointStore) bool {
        return self.has_persisted_state;
    }

    pub fn checkpointHealthy(self: *const CheckpointStore) bool {
        return self.last_checkpoint_error == null;
    }

    pub fn resetPreparedState(self: *CheckpointStore) void {
        self.store.reset();
        self.workspaces.reset();
        self.has_persisted_state = false;
        self.dirty = false;
        self.last_checkpoint_generation = 0;
        self.last_checkpoint_error = null;
        self.checkpoint_retry_count = 0;
    }

    pub fn loadPreparedStateFromAttachedVolume(self: *CheckpointStore) bool {
        const volume = self.volumePtr();
        if (comptime !shares_root_volume) {
            if (storage_volume.hasAttachedDevice()) {
                volume.adoptAttachedBackendFrom(storage_volume.defaultVolume());
            }
        }
        if (!volume.hasAttachedDevice()) return false;
        if (volume.loadFromVolume(&self.store, &self.workspaces)) {
            self.has_persisted_state = true;
            self.dirty = false;
            return true;
        }
        return false;
    }

    pub fn resetPersistent(self: *CheckpointStore) void {
        self.resetPreparedState();
        if (comptime !shares_root_volume) {
            self.checkpoint_volume.clearAttachedVolume();
            self.checkpoint_volume.clearAttachedBackend();
        }
    }

    pub fn preparePersistentState(self: *CheckpointStore) bool {
        if (self.has_persisted_state) return false;
        self.resetPreparedState();
        return self.loadPreparedStateFromAttachedVolume();
    }
};

pub fn makeService(
    ServiceType: type,
    checkpoint_store: *CheckpointStore,
    service_id: u64,
    task_id: u64,
    owner: anytype,
    loaded_from_volume: bool,
) ServiceType {
    return .{
        .service_id = service_id,
        .task_id = task_id,
        .owner = owner,
        .capability_table = null,
        .loaded_from_volume = loaded_from_volume,
        .checkpoint_enabled = true,
        .deferred_checkpoint_count = 0,
        .checkpoint_batch_depth = 0,
        .checkpoint_store = checkpoint_store,
        .store = &checkpoint_store.store,
        .workspaces = &checkpoint_store.workspaces,
    };
}

pub fn noteMutation(service: anytype, durable_boundary: bool) void {
    service.checkpoint_store.has_persisted_state = true;
    service.checkpoint_store.dirty = true;
    if (!service.checkpoint_enabled) return;
    if (durable_boundary and service.deferred_checkpoint_count == 0 and service.checkpoint_batch_depth == 0) {
        flushCheckpoint(service);
    }
}

pub fn flushCheckpoint(service: anytype) void {
    service.checkpoint_store.has_persisted_state = true;
    if (!service.checkpoint_store.dirty) return;
    const volume = service.checkpoint_store.volumePtr();
    if (comptime !shares_root_volume) {
        if (storage_volume.hasAttachedDevice()) {
            volume.adoptAttachedBackendFrom(storage_volume.defaultVolume());
        }
    }
    if (!volume.hasAttachedDevice()) return;
    var attempt: u8 = 1;
    const result = while (true) {
        break volume.saveToVolume(service.store, service.workspaces) catch |err| {
            if (attempt >= MAX_CHECKPOINT_ATTEMPTS or !retryableCheckpointError(err)) {
                service.checkpoint_store.last_checkpoint_error = err;
                reportFlushError(err);
                return;
            }
            attempt += 1;
            service.checkpoint_store.checkpoint_retry_count +|= 1;
            continue;
        };
    };
    service.checkpoint_store.last_checkpoint_generation = result.generation;
    service.checkpoint_store.last_checkpoint_error = null;
    service.checkpoint_store.dirty = false;
}

fn retryableCheckpointError(err: storage_volume.Error) bool {
    return switch (err) {
        error.CorruptImage, error.DurabilityBarrierFailed => true,
        else => false,
    };
}

fn reportFlushError(err: storage_volume.Error) void {
    var line_buffer: [96]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buffer,
        "ZIGOS:STORAGE:CHECKPOINT:FLUSH_ERROR error={s}",
        .{@errorName(err)},
    ) catch return;
    common.printBootMarker(line);
}
