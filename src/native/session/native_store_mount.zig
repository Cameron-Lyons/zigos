const builtin = @import("builtin");
const capability = @import("../kernel_api/capability.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const principal = @import("../core/principal.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const storage_volume = @import("../storage/storage_volume.zig");
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
        _ = bootstrap_driver_port.refreshActiveStorageAttachment(service_id);
        _ = adoptRootStorageVolume(&self.storage_checkpoint_store);
        self.storage_service_instance = storage_service_mod.Service.reloadFromAttachedVolume(
            service_id,
            task_id,
            owner,
            &self.storage_checkpoint_store,
        );
        self.storage_service_instance.bindCapabilityTable(capability_table);
        self.storage_service_instance.checkpoint_enabled = false;
    }

    pub fn checkpoint(self: *NativeStoreMount) void {
        _ = bootstrap_driver_port.refreshActiveStorageAttachment(self.storage_service_instance.service_id);
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
    if (!canAdoptProductionRootVolume(root_volume)) return false;
    checkpoint_store.adoptRootVolume(root_volume);
    return true;
}

pub fn canAdoptProductionRootVolume(root_volume: anytype) bool {
    return root_volume.hasProductionStorageBackend();
}

test "native store root adoption only accepts production NVMe PCI volumes" {
    const BackendFns = struct {
        fn read(_: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
            @memset(buffer_ptr[0..buffer_len], 0);
            return true;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return true;
        }

        fn flush() callconv(.c) bool {
            return true;
        }
    };
    const production_backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };

    var volume = storage_volume.Volume.init();
    try @import("std").testing.expect(!canAdoptProductionRootVolume(&volume));

    volume.attachBackend(production_backend);
    try @import("std").testing.expect(!canAdoptProductionRootVolume(&volume));

    const undersized_nvme_backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors - 1,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };
    volume.attachNvmePciBackend(undersized_nvme_backend);
    try @import("std").testing.expect(!canAdoptProductionRootVolume(&volume));

    volume.attachNvmePciBackend(production_backend);
    try @import("std").testing.expect(canAdoptProductionRootVolume(&volume));
}
