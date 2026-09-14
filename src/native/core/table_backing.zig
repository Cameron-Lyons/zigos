const builtin = @import("builtin");
const std = @import("std");

pub const HEAP_BACKS_ON_ALL_TARGETS = true;
pub const UNIFIED_ALLOCATOR = true;

const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("root").kernel_memory
else
    struct {};

pub fn alloc(comptime T: type) ?*T {
    if (comptime builtin.target.os.tag == .freestanding) {
        const raw = kernel_memory.kmalloc(@sizeOf(T)) orelse return null;
        const ptr: *T = @ptrCast(@alignCast(raw));
        @memset(std.mem.asBytes(ptr), 0);
        return ptr;
    }
    const ptr = std.heap.page_allocator.create(T) catch return null;
    @memset(std.mem.asBytes(ptr), 0);
    return ptr;
}

pub fn free(comptime T: type, ptr: *T) void {
    @memset(std.mem.asBytes(ptr), 0);
    if (comptime builtin.target.os.tag == .freestanding) {
        kernel_memory.kfree(@ptrCast(ptr));
        return;
    }
    std.heap.page_allocator.destroy(ptr);
}

test "table backing allocates and frees on the host" {
    const Slot = struct { value: u64 = 0 };
    const slot = alloc(Slot) orelse return error.OutOfMemory;
    defer free(Slot, slot);
    slot.value = 9;
    try std.testing.expectEqual(@as(u64, 9), slot.value);
}
