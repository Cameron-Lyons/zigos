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

pub const InitError = sync_service.Error || error{NoSpaceLeft};

pub const Instance = struct {
    backing: Backing = if (HEAP_BACKED_ON_FREESTANDING) null else undefined,

    pub fn init(
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        storage: *storage_service.Service,
        resident_state: *sync_service.ResidentState,
    ) InitError!Instance {
        var instance = Instance{};
        if (comptime HEAP_BACKED_ON_FREESTANDING) {
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
            instance.backing = try sync_service.Service.initWithStorage(
                service_id,
                task_id,
                owner,
                storage,
                resident_state,
            );
        }
        return instance;
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
}
