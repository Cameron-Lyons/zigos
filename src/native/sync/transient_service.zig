const std = @import("std");
const principal = @import("../core/principal.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("sync_service.zig");
const table_backing = @import("../core/table_backing.zig");

pub const InitError = sync_service.Error || error{NoSpaceLeft};

pub const ResidentInstance = struct {
    backing: table_backing.Lazy(sync_service.ResidentState, sync_service.ResidentState.initializeAllocated) = .{},

    /// `instance` may be uninitialized; any state it held is not released.
    pub fn initInto(instance: *ResidentInstance) error{NoSpaceLeft}!void {
        instance.* = .{};
        _ = try instance.backing.ensure();
    }

    pub fn deinit(self: *ResidentInstance) void {
        self.backing.release();
    }

    pub fn ptr(self: *ResidentInstance) *sync_service.ResidentState {
        return self.backing.get().?;
    }
};

pub const TRANSIENT_RESIDENT_STATE_INSTANCE = @sizeOf(ResidentInstance) == @sizeOf(?*sync_service.ResidentState);

pub const Instance = struct {
    backing: table_backing.Lazy(sync_service.Service, null) = .{},

    /// `instance` may be uninitialized; any state it held is not released.
    pub fn initInto(
        instance: *Instance,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        storage: *storage_service.Service,
        resident_state: *sync_service.ResidentState,
    ) InitError!void {
        instance.* = .{};
        const service = try instance.backing.ensure();
        errdefer instance.backing.release();
        try sync_service.Service.initWithStorageInto(
            service,
            service_id,
            task_id,
            owner,
            storage,
            resident_state,
        );
    }

    pub fn deinit(self: *Instance) void {
        self.backing.release();
    }

    pub fn ptr(self: *Instance) *sync_service.Service {
        return self.backing.get().?;
    }
};

test "transient resident sync state initializes on first use" {
    var resident_instance: ResidentInstance = undefined;
    try resident_instance.initInto();
    defer resident_instance.deinit();
    try std.testing.expect(!resident_instance.ptr().has_persisted_state);
    try std.testing.expectEqual(@as(u64, 1), resident_instance.ptr().next_state_tick);
}
