const std = @import("std");
const heap = @import("memory.zig");

fn payload(ptr: *anyopaque, len: usize) []u8 {
    return @as([*]u8, @ptrCast(ptr))[0..len];
}

test "heap aligns an early-allocation tail and preserves outside bytes" {
    var arena: [4096]u8 align(32) = undefined;
    for (0..32) |offset| {
        @memset(&arena, 0xa5);
        try heap.initHostArena(arena[offset .. arena.len - 3]);
        const ptr = heap.kmalloc(113).?;
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(ptr) % 32);
        @memset(payload(ptr, 113), 0xc7);
        heap.kfree(ptr);
        for (arena[0..offset]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
        for (arena[arena.len - 3 ..]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    }
}

test "heap rejects interior pointers duplicate frees and overflowing requests" {
    var arena: [8192]u8 align(32) = undefined;
    try heap.initHostArena(&arena);
    const ptr = heap.kmalloc(256).?;
    @memset(payload(ptr, 256), 0xc7);
    heap.kfree(@ptrFromInt(@intFromPtr(ptr) + 32));
    heap.kfree(@ptrFromInt(@intFromPtr(ptr) + 1));
    heap.kfree(@ptrFromInt(std.math.maxInt(usize)));
    heap.kfree(null);
    try std.testing.expect(heap.kmalloc(0) == null);
    try std.testing.expect(heap.kmalloc(std.math.maxInt(usize)) == null);
    for (payload(ptr, 256)) |byte| try std.testing.expectEqual(@as(u8, 0xc7), byte);
    heap.kfree(ptr);
    heap.kfree(ptr);
    const first = heap.kmalloc(256).?;
    const second = heap.kmalloc(256).?;
    try std.testing.expect(first != second);
    heap.kfree(first);
    heap.kfree(second);
}

test "heap coalesces uncached spans in every release order" {
    const orders = [_][3]usize{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };
    var arena: [32768]u8 align(32) = undefined;
    for (orders) |order| {
        try heap.initHostArena(&arena);
        const blocks = [_]*anyopaque{ heap.kmalloc(8192).?, heap.kmalloc(8192).?, heap.kmalloc(8192).? };
        for (order) |index| heap.kfree(blocks[index]);
        const combined = heap.kmalloc(arena.len).?;
        try std.testing.expectEqual(@intFromPtr(&arena), @intFromPtr(combined));
        heap.kfree(combined);
    }
}

test "heap recycles every span through fragmented page-sized frees" {
    const count = heap.metadata_layout.span_capacity;
    const bytes_per_span = 8192;
    const arena = try std.testing.allocator.alignedAlloc(u8, .@"32", count * bytes_per_span);
    defer std.testing.allocator.free(arena);
    try heap.initHostArena(arena);
    var blocks: [count]*anyopaque = undefined;
    for ([_]usize{ 37, 61 }) |stride| {
        for (&blocks, 0..) |*block, index| {
            block.* = heap.kmalloc(bytes_per_span) orelse return error.OutOfMemory;
            try std.testing.expectEqual(@intFromPtr(arena.ptr) + index * bytes_per_span, @intFromPtr(block.*));
            const data = payload(block.*, bytes_per_span);
            data[0] = @truncate(index);
            data[data.len - 1] = @as(u8, @truncate(index)) ^ 0xa5;
        }
        try std.testing.expect(heap.kmalloc(1) == null);
        // Keep live neighbors between free spans, then coalesce nodes from
        // arbitrary positions in the same free list and wrapped lookup chains.
        for (0..count / 2) |index| heap.kfree(blocks[index * 2]);
        for (0..count / 2) |step| {
            const index = ((step * stride) % (count / 2)) * 2 + 1;
            const data = payload(blocks[index], bytes_per_span);
            try std.testing.expectEqual(@as(u8, @truncate(index)), data[0]);
            try std.testing.expectEqual(@as(u8, @truncate(index)) ^ 0xa5, data[data.len - 1]);
            heap.kfree(blocks[index]);
        }
        const combined = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
        try std.testing.expectEqual(@intFromPtr(arena.ptr), @intFromPtr(combined));
        heap.kfree(combined);
    }
}

test "heap keeps compact links within its metadata budget" {
    try std.testing.expectEqual(@as(usize, 2), heap.metadata_layout.index_bytes);
    try std.testing.expect(heap.metadata_layout.span_bytes <= 20);
    try std.testing.expect(heap.metadata_layout.array_bytes <= 101 * 1024);
}

test "heap preserves live payloads and free indexes under randomized fragmentation" {
    var arena: [128 * 1024]u8 align(16) = undefined;
    try heap.initHostArena(&arena);
    const Live = struct { ptr: *anyopaque, size: usize, pattern: u8 };
    var live = @as([128]?Live, @splat(null));
    var prng = std.Random.DefaultPrng.init(0x4845_4150_2026);
    const random = prng.random();
    for (0..8000) |iteration| {
        const index = random.uintLessThan(usize, live.len);
        if (live[index]) |allocation| {
            for (payload(allocation.ptr, allocation.size)) |byte| try std.testing.expectEqual(allocation.pattern, byte);
            heap.kfree(allocation.ptr);
            live[index] = null;
        } else {
            const size = random.intRangeAtMost(usize, 1, 8192);
            if (heap.kmalloc(size)) |ptr| {
                const pattern = random.int(u8);
                @memset(payload(ptr, size), pattern);
                live[index] = .{ .ptr = ptr, .size = size, .pattern = pattern };
            }
        }
        if (iteration % 31 == 0) {
            for (live) |slot| if (slot) |allocation| {
                for (payload(allocation.ptr, allocation.size)) |byte| try std.testing.expectEqual(allocation.pattern, byte);
            };
        }
    }
    for (live) |slot| if (slot) |allocation| {
        for (payload(allocation.ptr, allocation.size)) |byte| try std.testing.expectEqual(allocation.pattern, byte);
        heap.kfree(allocation.ptr);
    };
}
