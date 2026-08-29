const builtin = @import("builtin");
const std = @import("std");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/memory/memory.zig")
else
    struct {};
const principal = @import("../core/principal.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("sync_service.zig");

pub const HEAP_BACKED_ON_FREESTANDING = builtin.target.os.tag == .freestanding;
const Backing = if (HEAP_BACKED_ON_FREESTANDING) ?*sync_service.Service else sync_service.Service;
const ResidentBacking = if (HEAP_BACKED_ON_FREESTANDING) ?*sync_service.ResidentState else sync_service.ResidentState;

pub const InitError = sync_service.Error || error{NoSpaceLeft};

pub const ResidentInstance = struct {
    backing: ResidentBacking = if (HEAP_BACKED_ON_FREESTANDING) null else undefined,

    pub fn initInto(instance: *ResidentInstance) error{NoSpaceLeft}!void {
        if (comptime HEAP_BACKED_ON_FREESTANDING) {
            instance.backing = null;
            const allocation = kernel_memory.kmalloc(@sizeOf(sync_service.ResidentState)) orelse
                return error.NoSpaceLeft;
            const resident_state: *sync_service.ResidentState = @ptrCast(@alignCast(allocation));
            resident_state.initializeAllocated();
            instance.backing = resident_state;
        } else {
            instance.backing.initializeAllocated();
        }
    }

    pub fn deinit(self: *ResidentInstance) void {
        if (comptime HEAP_BACKED_ON_FREESTANDING) {
            if (self.backing) |resident_state| {
                @memset(std.mem.asBytes(resident_state), 0);
                kernel_memory.kfree(@ptrCast(resident_state));
                self.backing = null;
            }
        } else {
            self.* = undefined;
        }
    }

    pub fn ptr(self: *ResidentInstance) *sync_service.ResidentState {
        if (comptime HEAP_BACKED_ON_FREESTANDING) return self.backing.?;
        return &self.backing;
    }
};

pub const TRANSIENT_RESIDENT_STATE_INSTANCE = @sizeOf(ResidentInstance) == @sizeOf(ResidentBacking);

pub const Instance = struct {
    backing: Backing = if (HEAP_BACKED_ON_FREESTANDING) null else undefined,

    pub fn initInto(
        instance: *Instance,
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        storage: *storage_service.Service,
        resident_state: *sync_service.ResidentState,
    ) InitError!void {
        if (comptime HEAP_BACKED_ON_FREESTANDING) {
            instance.backing = null;
            const allocation = kernel_memory.kmalloc(@sizeOf(sync_service.Service)) orelse
                return error.NoSpaceLeft;
            errdefer kernel_memory.kfree(allocation);
            const service: *sync_service.Service = @ptrCast(@alignCast(allocation));
            try sync_service.Service.initWithStorageInto(
                service,
                service_id,
                task_id,
                owner,
                storage,
                resident_state,
            );
            instance.backing = service;
        } else {
            try sync_service.Service.initWithStorageInto(
                &instance.backing,
                service_id,
                task_id,
                owner,
                storage,
                resident_state,
            );
        }
    }

    pub fn deinit(self: *Instance) void {
        if (comptime HEAP_BACKED_ON_FREESTANDING) {
            if (self.backing) |service| {
                @memset(std.mem.asBytes(service), 0);
                kernel_memory.kfree(@ptrCast(service));
                self.backing = null;
            }
        } else {
            self.* = undefined;
        }
    }

    pub fn ptr(self: *Instance) *sync_service.Service {
        if (comptime HEAP_BACKED_ON_FREESTANDING) return self.backing.?;
        return &self.backing;
    }
};

test "host transient sync services retain value storage" {
    if (HEAP_BACKED_ON_FREESTANDING) return;
    try std.testing.expectEqual(@sizeOf(sync_service.Service), @sizeOf(Instance));
    try std.testing.expectEqual(@sizeOf(sync_service.ResidentState), @sizeOf(ResidentInstance));

    var resident_instance: ResidentInstance = undefined;
    try resident_instance.initInto();
    defer resident_instance.deinit();
    try std.testing.expect(!resident_instance.ptr().has_persisted_state);
    try std.testing.expectEqual(@as(u64, 1), resident_instance.ptr().next_state_tick);
}
