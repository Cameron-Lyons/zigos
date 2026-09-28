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

pub fn allocBytes(length: usize) ?[]u8 {
    if (length == 0) return &.{};
    const bytes = if (comptime builtin.target.os.tag == .freestanding)
        @as([*]u8, @ptrCast(kernel_memory.kmalloc(length) orelse return null))[0..length]
    else
        std.heap.page_allocator.alloc(u8, length) catch return null;
    @memset(bytes, 0);
    return bytes;
}

pub fn freeBytes(bytes: []u8) void {
    if (bytes.len == 0) return;
    std.crypto.secureZero(u8, bytes);
    if (comptime builtin.target.os.tag == .freestanding) {
        kernel_memory.kfree(bytes.ptr);
    } else std.heap.page_allocator.free(bytes);
}

test "table backing allocates and frees on the host" {
    const Slot = struct { value: u64 = 0 };
    const slot = alloc(Slot) orelse return error.OutOfMemory;
    defer free(Slot, slot);
    slot.value = 9;
    try std.testing.expectEqual(@as(u64, 9), slot.value);
}
