const builtin = @import("builtin");
const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const dataplane_handoff = @import("../drivers/dataplane_handoff.zig");
const ids = @import("../core/ids.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const storage_volume = @import("../storage/storage_volume.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const workspace_mod = @import("../storage/workspace.zig");
const table_backing = @import("../core/table_backing.zig");

pub const NativeStoreMount = struct {
    storage_checkpoint_store: table_backing.Lazy(storage_service_mod.CheckpointStore, storage_service_mod.CheckpointStore.initializeAllocated) = .{},
    storage_service_instance: storage_service_mod.Service = emptyStorageService(),
    export_package_backing: table_backing.Lazy(workspace_mod.ExportPackage, workspace_mod.resetExportPackage) = .{},
    sync_resident_state_backing: table_backing.Lazy(sync_service_mod.ResidentState, sync_service_mod.ResidentState.initializeAllocated) = .{},

    pub fn init() NativeStoreMount {
        return .{};
    }

    pub fn operationBusy(self: *const NativeStoreMount) bool {
        if (dataplane_handoff.operationBusy() or storage_volume.attachmentBusy()) return true;
        return if (self.storage_checkpoint_store.get()) |store| store.operationBusy() else false;
    }

    pub fn resetPersistent(self: *NativeStoreMount) bool {
        if (self.operationBusy()) return false;
        if (self.checkpointStorePtr()) |checkpoint_store| {
            if (!checkpoint_store.resetPersistent()) return false;
            self.storage_checkpoint_store.release();
        }
        self.export_package_backing.release();
        if (self.sync_resident_state_backing.get()) |resident_state| resident_state.resetPersistent();
        self.sync_resident_state_backing.release();
        self.storage_service_instance = emptyStorageService();
        return true;
    }

    pub fn checkpointStorePtr(self: *NativeStoreMount) ?*storage_service_mod.CheckpointStore {
        return self.storage_checkpoint_store.get();
    }

    pub fn exportPackagePtr(self: *NativeStoreMount) error{NoSpaceLeft}!*workspace_mod.ExportPackage {
        return self.export_package_backing.ensure();
    }

    pub fn syncResidentStatePtr(self: *NativeStoreMount) error{NoSpaceLeft}!*sync_service_mod.ResidentState {
        return self.sync_resident_state_backing.ensure();
    }

    pub fn ensureCheckpointStore(self: *NativeStoreMount) error{NoSpaceLeft}!*storage_service_mod.CheckpointStore {
        return self.storage_checkpoint_store.ensure();
    }

    pub fn bindProduction(
        self: *NativeStoreMount,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        capability_table: *capability.CapabilityTable,
    ) error{ NoSpaceLeft, StorageAttachmentUnavailable, VolumeOperationBusy }!void {
        const checkpoint_store = try self.ensureCheckpointStore();
        if (comptime builtin.target.os.tag == .freestanding) {
            if (!bootstrap_driver_port.refreshActiveStorageAttachment(service_id) or
                !adoptRootStorageVolume(checkpoint_store)) return error.StorageAttachmentUnavailable;
        } else _ = bootstrap_driver_port.refreshActiveStorageAttachment(service_id);
        self.storage_service_instance = try storage_service_mod.Service.reloadFromAttachedVolume(
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
        if (comptime builtin.target.os.tag == .freestanding) {
            if (!bootstrap_driver_port.refreshActiveStorageAttachment(self.storage_service_instance.service_id) or
                !adoptRootStorageVolume(checkpoint_store)) return;
        } else _ = bootstrap_driver_port.refreshActiveStorageAttachment(self.storage_service_instance.service_id);
        self.storage_service_instance.checkpoint();
    }
};

comptime {
    if (@sizeOf(NativeStoreMount) > 256) {
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
    const root_volume = storage_volume.defaultVolume();
    if (!canAdoptProductionRootVolume(root_volume)) return false;
    return checkpoint_store.adoptRootVolume(root_volume);
}

pub fn canAdoptProductionRootVolume(root_volume: anytype) bool {
    return root_volume.hasProductionStorageBackend();
}

test "native store initializes reuses and resets its export package buffer" {
    var mount = NativeStoreMount.init();
    defer if (!mount.resetPersistent()) @panic("storage lifecycle transition was refused");

    const first = try mount.exportPackagePtr();
    try std.testing.expect(first.workspace_id.isZero());
    try std.testing.expect(first.snapshot_id.isZero());
    try std.testing.expectEqual(@as(usize, 0), first.entry_count);
    try std.testing.expectEqual(@as(usize, 0), first.signature.signer.len);
    try std.testing.expect(first == try mount.exportPackagePtr());

    first.entry_count = 1;
    if (!mount.resetPersistent()) @panic("storage lifecycle transition was refused");
    try std.testing.expect(mount.export_package_backing.get() == null);
    const reset = try mount.exportPackagePtr();
    try std.testing.expectEqual(@as(usize, 0), reset.entry_count);
}

test "allocated checkpoint stores receive canonical arena sentinels" {
    const checkpoint_store = try std.testing.allocator.create(storage_service_mod.CheckpointStore);
    defer std.testing.allocator.destroy(checkpoint_store);
    @memset(std.mem.asBytes(checkpoint_store), 0xa5);

    checkpoint_store.initializeAllocated();

    try std.testing.expectEqual(@as(usize, 0), checkpoint_store.store.objectCount());
    try std.testing.expectEqual(@as(usize, 0), checkpoint_store.store.versionCount());
    try std.testing.expectEqual(@as(usize, 0), checkpoint_store.workspaces.workspaceCount());
    try std.testing.expectEqual(@as(usize, 0), checkpoint_store.store.objects.reserveIndex(ids.object(1)).?);
}

test "native store initializes reuses and resets its sync resident state" {
    var mount = NativeStoreMount.init();
    defer if (!mount.resetPersistent()) @panic("storage lifecycle transition was refused");

    const first = try mount.syncResidentStatePtr();
    try std.testing.expect(!first.has_persisted_state);
    try std.testing.expectEqual(@as(u64, 1), first.next_state_tick);
    try std.testing.expect(first == try mount.syncResidentStatePtr());

    first.has_persisted_state = true;
    first.next_state_tick = 8;
    if (!mount.resetPersistent()) @panic("storage lifecycle transition was refused");
    try std.testing.expect(mount.sync_resident_state_backing.get() == null);
    const reset = try mount.syncResidentStatePtr();
    try std.testing.expect(!reset.has_persisted_state);
    try std.testing.expectEqual(@as(u64, 1), reset.next_state_tick);
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

    if (!volume.attachBackend(production_backend)) @panic("storage lifecycle transition was refused");
    try @import("std").testing.expect(!canAdoptProductionRootVolume(&volume));

    const undersized_nvme_backend = storage_volume.Backend{
        .sector_count = storage_volume.required_device_sectors - 1,
        .read = BackendFns.read,
        .write = BackendFns.write,
        .flush = BackendFns.flush,
    };
    if (!volume.attachNvmePciBackend(undersized_nvme_backend)) @panic("storage lifecycle transition was refused");
    try @import("std").testing.expect(!canAdoptProductionRootVolume(&volume));

    if (!volume.attachNvmePciBackend(production_backend)) @panic("storage lifecycle transition was refused");
    try @import("std").testing.expect(canAdoptProductionRootVolume(&volume));
}

test "native store teardown retains backing for an independent suspended submit" {
    const cooperative = @import("../task/cooperative_worker.zig");
    try std.testing.expect(dataplane_handoff.reset());
    defer std.debug.assert(dataplane_handoff.reset());
    try dataplane_handoff.claim(0x1F003, 43, 3);
    const Job = struct {
        fn run(_: *anyopaque) void {
            const lease = dataplane_handoff.beginOwnedSubmit(0x1F003, 43, 3) catch unreachable;
            defer if (!dataplane_handoff.endOwnedSubmit(lease)) @panic("owned submit retains its exact lease");
            cooperative.current().?.yield();
        }
    };
    var mount = NativeStoreMount.init();
    var stack: [16 * 1024]u8 align(16) = undefined;
    var worker = cooperative.Worker{ .stack = &stack };
    try worker.start(&mount, Job.run);
    try worker.step();
    defer if (worker.state == .suspended) worker.step() catch unreachable;
    try std.testing.expect(mount.operationBusy());
    try std.testing.expect(!mount.resetPersistent());
    try worker.step();
    try std.testing.expect(!mount.operationBusy());
    try std.testing.expect(mount.resetPersistent());
}
