// Hosted integration keeps the production archive dependency graph narrow.
const std = @import("std");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const ids = @import("../../native/core/ids.zig");

test "runtime kernel task retirement hides shared authority until accelerator detach releases its pin" {
    const task_runtime = @import("../../native/task/task_runtime.zig");
    const capability = @import("../../native/kernel_api/capability.zig");
    const endpoint = @import("../../native/kernel_api/endpoint.zig");
    const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
    var runtime = task_runtime.Runtime.init();
    defer runtime.reset();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    defer endpoints.deinit();
    const FrameOwner = struct {
        const base: u64 = 0x200000;
        storage: [shared_memory.PAGE_SIZE]u8 = @splat(0xA5),
        occupied: bool = false,
        releases: u32 = 0,

        fn allocate(raw: *anyopaque, count: u32) ?u64 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (count != 1 or self.occupied) return null;
            self.occupied = true;
            return base;
        }

        fn bytes(raw: *anyopaque, address: u64, count: u32) ?[]u8 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (address != base or count != 1 or !self.occupied) return null;
            return &self.storage;
        }

        fn release(raw: *anyopaque, address: u64, count: u32) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            std.debug.assert(address == base and count == 1 and self.occupied);
            for (self.storage) |byte| std.debug.assert(byte == 0);
            self.occupied = false;
            self.releases += 1;
        }

        fn backend(self: *@This()) shared_memory.HostedPhysicalBacking {
            return .{ .context = self, .allocate = allocate, .bytes = bytes, .release = release };
        }
    };
    var frames = FrameOwner{};
    var shared = shared_memory.Table.initWithHostedPhysicalBacking(frames.backend(), null);
    defer shared.deinit();
    var kernel: native_kernel.Kernel = undefined;
    kernel.initInPlace(.{ .kind = .policy_authority, .serial = 1 }, &runtime, &capabilities, &endpoints, &shared);
    defer kernel.deinit();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .app, .serial = 71 },
        .component_class = .app_component,
        .budget = .{ .cpu_time_ticks = 100, .memory_bytes = shared_memory.PAGE_SIZE, .endpoint_slots = 2, .shared_memory_bytes = shared_memory.PAGE_SIZE },
        .local_only = true,
    });
    const task_id = task.id;
    const object = try shared.createWithAccess(ids.task(task_id), shared_memory.PAGE_SIZE, .{ .media = true });
    const object_id = object.id;
    try shared.attachAccelerator(object_id, .media);
    try std.testing.expect(frames.occupied);
    for (frames.storage) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    frames.storage[0] = 0x42;
    try std.testing.expect(try runtime.terminateTask(task_id, 10));
    try std.testing.expectError(error.SharedMemoryNotFound, shared.descriptor(object_id));
    try shared.validateAcceleratorRelease(object_id, .media);
    try std.testing.expectError(error.AcceleratorStillAttached, shared.requireQuiescent());
    try std.testing.expect(frames.occupied);
    try std.testing.expectEqual(@as(u32, 0), frames.releases);
    try std.testing.expectEqual(@as(u8, 0x42), frames.storage[0]);
    try std.testing.expect(try shared.detachAccelerator(object_id, .media));
    try shared.requireQuiescent();
    try std.testing.expectError(error.SharedMemoryNotFound, shared.validateAcceleratorRelease(object_id, .media));
    try std.testing.expect(!frames.occupied);
    try std.testing.expectEqual(@as(u32, 1), frames.releases);
    const reused = try shared.create(ids.task(task_id + 1), shared_memory.PAGE_SIZE);
    try std.testing.expect(!reused.id.eql(object_id));
    try std.testing.expectEqual(FrameOwner.base, reused.page_base);
    for (frames.storage) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}
