const builtin = @import("builtin");
const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const storage_volume = @import("../storage/storage_volume.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const workspace_mod = @import("../storage/workspace.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/memory/memory.zig")
else
    struct {};

const heap_backed_checkpoint_store = builtin.target.os.tag == .freestanding;
const CheckpointStoreBacking = if (heap_backed_checkpoint_store) ?*storage_service_mod.CheckpointStore else storage_service_mod.CheckpointStore;

pub const NativeStoreMount = struct {
    storage_checkpoint_store: CheckpointStoreBacking = if (heap_backed_checkpoint_store) null else .{},
    storage_service_instance: storage_service_mod.Service = emptyStorageService(),
    export_package_buffer: workspace_mod.ExportPackage = workspace_mod.emptyExportPackage(),
    sync_resident_state: sync_service_mod.ResidentState = .{},

    pub fn init() NativeStoreMount {
        return .{};
    }

    pub fn resetPersistent(self: *NativeStoreMount) void {
        if (self.checkpointStorePtr()) |checkpoint_store| {
            checkpoint_store.resetPersistent();
            if (comptime heap_backed_checkpoint_store) {
                @memset(std.mem.asBytes(checkpoint_store), 0);
                kernel_memory.kfree(@ptrCast(checkpoint_store));
                self.storage_checkpoint_store = null;
            }
        }
        self.storage_service_instance = emptyStorageService();
        self.sync_resident_state.resetPersistent();
    }

    pub fn checkpointStorePtr(self: *NativeStoreMount) ?*storage_service_mod.CheckpointStore {
        if (comptime heap_backed_checkpoint_store) return self.storage_checkpoint_store;
        return &self.storage_checkpoint_store;
    }

    fn ensureCheckpointStore(self: *NativeStoreMount) error{NoSpaceLeft}!*storage_service_mod.CheckpointStore {
        if (self.checkpointStorePtr()) |checkpoint_store| return checkpoint_store;
        if (comptime heap_backed_checkpoint_store) {
            const allocation = kernel_memory.kmalloc(@sizeOf(storage_service_mod.CheckpointStore)) orelse return error.NoSpaceLeft;
            const checkpoint_store: *storage_service_mod.CheckpointStore = @ptrCast(@alignCast(allocation));
            @memset(std.mem.asBytes(checkpoint_store), 0);
            checkpoint_store.resetPreparedState();
            self.storage_checkpoint_store = checkpoint_store;
            return checkpoint_store;
        }
        return &self.storage_checkpoint_store;
    }

    pub fn bindProduction(
        self: *NativeStoreMount,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        capability_table: *capability.CapabilityTable,
    ) error{NoSpaceLeft}!void {
        const checkpoint_store = try self.ensureCheckpointStore();
        _ = bootstrap_driver_port.refreshActiveStorageAttachment(service_id);
        _ = adoptRootStorageVolume(checkpoint_store);
        self.storage_service_instance = storage_service_mod.Service.reloadFromAttachedVolume(
            service_id,
            task_id,
            owner,
            checkpoint_store,
        );
        self.storage_service_instance.bindCapabilityTable(capability_table);
        self.storage_service_instance.checkpoint_enabled = false;
    }

    pub fn checkpoint(self: *NativeStoreMount) void {
        const checkpoint_store = self.checkpointStorePtr() orelse
            native_util.impossibleByInvariant("bound native storage service retains checkpoint state");
        _ = bootstrap_driver_port.refreshActiveStorageAttachment(self.storage_service_instance.service_id);
        _ = adoptRootStorageVolume(checkpoint_store);
        self.storage_service_instance.checkpoint();
    }
};

comptime {
    if (heap_backed_checkpoint_store and @sizeOf(NativeStoreMount) > 80 * 1024) {
        @compileError("heap-backed native store mounts exceed their compact resident layout");
    }
}

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
