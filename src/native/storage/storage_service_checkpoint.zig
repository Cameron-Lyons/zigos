const object_store = @import("object_store.zig");
const storage_volume = @import("storage_volume.zig");
const workspace = @import("workspace.zig");

pub const CheckpointStore = struct {
    store: object_store.Store = object_store.Store.init(),
    workspaces: workspace.Directory = workspace.Directory.init(),
    has_persisted_state: bool = false,
    dirty: bool = false,

    pub fn hasCachedPersistentState(self: *const CheckpointStore) bool {
        return self.has_persisted_state;
    }

    pub fn resetPreparedState(self: *CheckpointStore) void {
        self.store.reset();
        self.workspaces.reset();
        self.has_persisted_state = false;
        self.dirty = false;
    }

    pub fn loadPreparedStateFromAttachedVolume(self: *CheckpointStore) bool {
        if (!storage_volume.hasAttachedDevice()) return false;
        if (storage_volume.loadFromVolume(&self.store, &self.workspaces)) {
            self.has_persisted_state = true;
            self.dirty = false;
            return true;
        }
        return false;
    }

    pub fn resetPersistent(self: *CheckpointStore) void {
        self.resetPreparedState();
        storage_volume.clearAttachedVolume();
        storage_volume.clearAttachedBackend();
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
        .loaded_from_volume = loaded_from_volume,
        .checkpoint_enabled = true,
        .deferred_checkpoint_count = 0,
        .checkpoint_store = checkpoint_store,
        .store = &checkpoint_store.store,
        .workspaces = &checkpoint_store.workspaces,
    };
}

pub fn noteMutation(service: anytype, durable_boundary: bool) void {
    service.checkpoint_store.has_persisted_state = true;
    service.checkpoint_store.dirty = true;
    if (!service.checkpoint_enabled) return;
    if (durable_boundary and service.deferred_checkpoint_count == 0) {
        flushCheckpoint(service);
    }
}

pub fn flushCheckpoint(service: anytype) void {
    service.checkpoint_store.has_persisted_state = true;
    if (!service.checkpoint_store.dirty) return;
    if (!storage_volume.hasAttachedDevice()) return;
    _ = storage_volume.saveToVolume(service.store, service.workspaces) catch return;
    service.checkpoint_store.dirty = false;
}
