const builtin = @import("builtin");
const object_store = @import("object_store.zig");
const root = @import("root");
const storage_volume = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("storage_volume.zig");
const workspace = @import("workspace.zig");

pub const CheckpointStore = struct {
    store: object_store.Store = object_store.Store.init(),
    workspaces: workspace.Directory = workspace.Directory.init(),
    has_persisted_state: bool = false,
    dirty: bool = false,
    last_checkpoint_generation: u64 = 0,
    last_checkpoint_error: ?storage_volume.Error = null,
    volume: storage_volume.Volume = storage_volume.Volume.init(),

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
    }

    pub fn loadPreparedStateFromAttachedVolume(self: *CheckpointStore) bool {
        if (storage_volume.hasAttachedDevice()) {
            self.volume.adoptAttachedBackendFrom(storage_volume.defaultVolume());
        }
        if (!self.volume.hasAttachedDevice()) return false;
        if (self.volume.loadFromVolume(&self.store, &self.workspaces)) {
            self.has_persisted_state = true;
            self.dirty = false;
            return true;
        }
        return false;
    }

    pub fn resetPersistent(self: *CheckpointStore) void {
        self.resetPreparedState();
        self.volume.clearAttachedVolume();
        self.volume.clearAttachedBackend();
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
    if (storage_volume.hasAttachedDevice()) {
        service.checkpoint_store.volume.adoptAttachedBackendFrom(storage_volume.defaultVolume());
    }
    if (!service.checkpoint_store.volume.hasAttachedDevice()) return;
    const result = service.checkpoint_store.volume.saveToVolume(service.store, service.workspaces) catch |err| {
        service.checkpoint_store.last_checkpoint_error = err;
        return;
    };
    service.checkpoint_store.last_checkpoint_generation = result.generation;
    service.checkpoint_store.last_checkpoint_error = null;
    service.checkpoint_store.dirty = false;
}
