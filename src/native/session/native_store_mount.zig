const builtin = @import("builtin");
const capability = @import("../kernel_api/capability.zig");
const principal = @import("../core/principal.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const workspace_mod = @import("../storage/workspace.zig");

pub const NativeStoreMount = struct {
    storage_checkpoint_store: storage_service_mod.CheckpointStore = .{},
    storage_service_instance: storage_service_mod.Service = emptyStorageService(),
    export_package_buffer: workspace_mod.ExportPackage = workspace_mod.emptyExportPackage(),
    sync_resident_state: sync_service_mod.ResidentState = .{},

    pub fn init() NativeStoreMount {
        return .{};
    }

    pub fn resetPersistent(self: *NativeStoreMount) void {
        self.storage_checkpoint_store.resetPersistent();
        self.sync_resident_state.resetPersistent();
    }

    pub fn bindProduction(
        self: *NativeStoreMount,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        capability_table: *capability.CapabilityTable,
    ) void {
        self.storage_checkpoint_store.resetPreparedState();
        _ = adoptRootStorageVolume(&self.storage_checkpoint_store);
        const loaded_from_volume = self.storage_checkpoint_store.loadPreparedStateFromAttachedVolume();
        self.storage_service_instance = storage_service_mod.Service.bindPrepared(
            &self.storage_checkpoint_store,
            service_id,
            task_id,
            owner,
            loaded_from_volume,
        );
        self.storage_service_instance.bindCapabilityTable(capability_table);
        self.storage_service_instance.checkpoint_enabled = false;
    }

    pub fn checkpoint(self: *NativeStoreMount) void {
        _ = adoptRootStorageVolume(&self.storage_checkpoint_store);
        self.storage_service_instance.checkpoint();
    }
};

pub fn emptyStorageService() storage_service_mod.Service {
    return .{
        .service_id = 0,
        .task_id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .capability_table = null,
        .checkpoint_store = undefined,
        .store = undefined,
        .workspaces = undefined,
    };
}

pub fn adoptRootStorageVolume(checkpoint_store: *storage_service_mod.CheckpointStore) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const root = @import("root");
    if (!@hasDecl(root, "storage_volume")) return false;
    const root_volume = root.storage_volume.defaultVolume();
    if (!root_volume.hasAttachedDevice()) return false;
    if (root_volume.attached_ata_device) |device| {
        checkpoint_store.volume.attachAtaBootstrapDevice(device, root_volume.attached_backend_sector_count);
        return true;
    }
    checkpoint_store.volume.attachBackendFns(
        root_volume.attached_backend_sector_count,
        root_volume.attached_backend_read,
        root_volume.attached_backend_write,
    );
    return true;
}
