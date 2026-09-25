const std = @import("std");
const Heap = @import("heap_allocator.zig").Heap;
const geometry = @import("heap_geometry.zig");
const Header = geometry.BlockHeader;
const Links = geometry.FreeLinks;

fn payload(ptr: *anyopaque, len: usize) []u8 {
    return @as([*]u8, @ptrCast(ptr))[0..len];
}

fn expectIntegrity(heap: *const Heap) !void {
    const start = @intFromPtr(heap.data.ptr);
    const end = start + heap.data.len;
    var address = start;
    var previous: ?*Header = null;
    var free_count: usize = 0;
    var live_count: usize = 0;
    while (address < end) {
        try std.testing.expect(address % geometry.block_alignment == 0);
        try std.testing.expect(end - address >= @sizeOf(Header));
        const header: *Header = @ptrFromInt(address);
        try std.testing.expectEqual(previous, header.prev);
        try std.testing.expect(header.size >= geometry.minimum_free_data_size);
        try std.testing.expectEqual(@as(usize, 0), header.size % geometry.block_alignment);
        try std.testing.expect(header.size <= end - address - @sizeOf(Header));
        const next_address = address + @sizeOf(Header) + header.size;
        const expected_next: ?*Header = if (next_address == end) null else @ptrFromInt(next_address);
        try std.testing.expectEqual(expected_next, header.next);
        const ptr: *anyopaque = @ptrFromInt(address + @sizeOf(Header));
        if (header.state == geometry.block_state_free) {
            free_count += 1;
            try std.testing.expect(heap.allocationSize(ptr) == null);
            if (previous) |prev| try std.testing.expect(prev.state != geometry.block_state_free);
        } else {
            try std.testing.expectEqual(geometry.block_state_allocated, header.state);
            try std.testing.expectEqual(header.size, heap.allocationSize(ptr).?);
            live_count += 1;
        }
        previous = header;
        address = next_address;
    }
    try std.testing.expectEqual(end, address);
    var marked: usize = 0;
    for (heap.allocation_starts) |byte| marked += @popCount(byte);
    try std.testing.expectEqual(live_count, marked);

    var listed: usize = 0;
    var expected_first: u32 = 0;
    for (heap.free_lists, 0..) |row, first| {
        var expected_second: u32 = 0;
        for (row, 0..) |head, second| {
            if (head != null) expected_second |= @as(u32, 1) << @as(u5, @intCast(second));
            var block = head;
            var previous_free: ?*Header = null;
            while (block) |header| {
                listed += 1;
                try std.testing.expect(listed <= free_count);
                const block_address = @intFromPtr(header);
                try std.testing.expect(block_address >= start and block_address <= end - @sizeOf(Header));
                try std.testing.expectEqual(geometry.block_state_free, header.state);
                const class = geometry.sizeClass(header.size);
                try std.testing.expectEqual(first, class.first);
                try std.testing.expectEqual(second, class.second);
                const links: *const Links = @ptrFromInt(block_address + @sizeOf(Header));
                try std.testing.expectEqual(previous_free, links.prev);
                previous_free = header;
                block = links.next;
            }
        }
        try std.testing.expectEqual(expected_second, heap.nonempty_second[first]);
        if (expected_second != 0) expected_first |= @as(u32, 1) << @as(u5, @intCast(first));
    }
    try std.testing.expectEqual(free_count, listed);
    try std.testing.expectEqual(expected_first, heap.nonempty_first);
}

test "heap aligns an arbitrary early-allocation tail and preserves outside bytes" {
    var arena: [4096]u8 align(16) = undefined;
    for (0..16) |offset| {
        @memset(&arena, 0xa5);
        var heap: Heap = undefined;
        try heap.init(arena[offset .. arena.len - 3]);
        const ptr = heap.allocate(113).?;
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(ptr) % 16);
        @memset(payload(ptr, 113), 0xc7);
        try expectIntegrity(&heap);
        try std.testing.expect(heap.release(ptr));
        try expectIntegrity(&heap);
        for (arena[0..offset]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
        for (arena[arena.len - 3 ..]) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    }
}

test "heap rejects unusable arenas without changing a live heap" {
    var arena: [4096]u8 align(16) = undefined;
    var heap: Heap = undefined;
    try heap.init(&arena);
    const ptr = heap.allocate(64).?;
    @memset(payload(ptr, 64), 0x73);
    var tiny: [63]u8 align(16) = [_]u8{0xac} ** 63;
    for (0..tiny.len + 1) |length| try std.testing.expectError(error.TooSmall, heap.init(tiny[0..length]));
    const too_large = try std.testing.allocator.alloc(u8, geometry.maximum_heap_bytes + 32);
    defer std.testing.allocator.free(too_large);
    try std.testing.expectError(error.TooLarge, heap.init(too_large));
    for (tiny) |byte| try std.testing.expectEqual(@as(u8, 0xac), byte);
    for (payload(ptr, 64)) |byte| try std.testing.expectEqual(@as(u8, 0x73), byte);
    try expectIntegrity(&heap);
    try std.testing.expect(heap.release(ptr));
}

test "minimum retained heap tail supports one aligned allocation" {
    const minimum = @import("heap_allocator.zig").minimum_arena_bytes;
    var arena: [minimum + 30]u8 align(16) = undefined;
    for (0..16) |offset| {
        var heap: Heap = undefined;
        try heap.init(arena[offset..][0 .. minimum + 15]);
        const allocation = heap.allocate(16).?;
        try std.testing.expect(heap.allocate(16) == null);
        try std.testing.expect(heap.release(allocation));
        try expectIntegrity(&heap);
    }
}

test "heap coalesces adjacent blocks in every release order" {
    const orders = [_][3]usize{ .{ 0, 1, 2 }, .{ 0, 2, 1 }, .{ 1, 0, 2 }, .{ 1, 2, 0 }, .{ 2, 0, 1 }, .{ 2, 1, 0 } };
    var arena: [4096]u8 align(16) = undefined;
    for (orders) |order| {
        var heap: Heap = undefined;
        try heap.init(&arena);
        const before = heap.allocate(16).?;
        const blocks = [_]*anyopaque{ heap.allocate(64).?, heap.allocate(128).?, heap.allocate(256).? };
        const after = heap.allocate(16).?;
        @memset(payload(before, 16), 0x12);
        @memset(payload(after, 16), 0x34);
        for (order) |index| {
            try std.testing.expect(heap.release(blocks[index]));
            try expectIntegrity(&heap);
        }
        const combined = heap.allocate(512).?;
        try std.testing.expectEqual(blocks[0], combined);
        for (payload(before, 16)) |byte| try std.testing.expectEqual(@as(u8, 0x12), byte);
        for (payload(after, 16)) |byte| try std.testing.expectEqual(@as(u8, 0x34), byte);
        try std.testing.expect(heap.release(before));
        try std.testing.expect(heap.release(after));
        try std.testing.expect(heap.release(combined));
        try expectIntegrity(&heap);
        const first: *const Header = @ptrCast(heap.data.ptr);
        try std.testing.expect(first.next == null);
    }
}

test "heap rejects forged interior headers foreign pointers and duplicate frees" {
    var arena: [4096]u8 align(16) = undefined;
    var heap: Heap = undefined;
    try heap.init(&arena);
    const ptr = heap.allocate(256).?;
    const fake: *Header = @ptrCast(@alignCast(ptr));
    fake.* = .{ .size = 64, .state = geometry.block_state_allocated, .next = null, .prev = null };
    const interior: *anyopaque = @ptrFromInt(@intFromPtr(ptr) + @sizeOf(Header));
    try std.testing.expect(!heap.release(interior));
    try std.testing.expect(heap.allocationSize(interior) == null);
    try std.testing.expect(!heap.release(@ptrFromInt(@intFromPtr(ptr) + 1)));
    try std.testing.expect(!heap.release(@ptrFromInt(@intFromPtr(heap.data.ptr))));
    try std.testing.expect(!heap.release(@ptrFromInt(std.math.maxInt(usize))));
    try std.testing.expect(!heap.release(null));
    try std.testing.expect(heap.allocationSize(ptr) != null);
    try expectIntegrity(&heap);
    try std.testing.expect(heap.release(ptr));
    try std.testing.expect(!heap.release(ptr));
    try expectIntegrity(&heap);
}

test "heap exhaustion and rejected sizes leave allocations intact and reusable" {
    var arena: [8192]u8 align(16) = undefined;
    var heap: Heap = undefined;
    try heap.init(&arena);
    var allocations: [256]*anyopaque = undefined;
    var count: usize = 0;
    while (heap.allocate(16)) |ptr| {
        try std.testing.expect(count < allocations.len);
        allocations[count] = ptr;
        @memset(payload(ptr, 16), @truncate(count));
        count += 1;
    }
    try std.testing.expect(count > 100);
    try std.testing.expect(heap.allocate(0) == null);
    try std.testing.expect(heap.allocate(std.math.maxInt(usize)) == null);
    try std.testing.expect(heap.allocate(geometry.maximum_heap_bytes) == null);
    try expectIntegrity(&heap);
    for (allocations[0..count], 0..) |ptr, index| {
        for (payload(ptr, 16)) |byte| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
        try std.testing.expect(heap.release(ptr));
    }
    try expectIntegrity(&heap);
    const larger = heap.allocate(4096).?;
    try std.testing.expectEqual(allocations[0], larger);
    try std.testing.expect(heap.release(larger));
}

test "heap preserves live payloads and free indexes under randomized fragmentation" {
    var arena: [128 * 1024]u8 align(16) = undefined;
    var heap: Heap = undefined;
    try heap.init(&arena);
    const Live = struct { ptr: *anyopaque, size: usize, pattern: u8 };
    var live = [_]?Live{null} ** 128;
    var prng = std.Random.DefaultPrng.init(0x4845_4150_2026);
    const random = prng.random();
    for (0..8000) |iteration| {
        const index = random.uintLessThan(usize, live.len);
        if (live[index]) |allocation| {
            for (payload(allocation.ptr, allocation.size)) |byte| try std.testing.expectEqual(allocation.pattern, byte);
            try std.testing.expect(heap.release(allocation.ptr));
            live[index] = null;
        } else {
            const size = random.intRangeAtMost(usize, 1, 8192);
            if (heap.allocate(size)) |ptr| {
                try std.testing.expect(heap.allocationSize(ptr).? >= size);
                const pattern = random.int(u8);
                @memset(payload(ptr, size), pattern);
                live[index] = .{ .ptr = ptr, .size = size, .pattern = pattern };
            }
        }
        if (iteration % 31 == 0) {
            try expectIntegrity(&heap);
            for (live) |slot| if (slot) |allocation| {
                for (payload(allocation.ptr, allocation.size)) |byte| try std.testing.expectEqual(allocation.pattern, byte);
            };
        }
    }
    for (live) |slot| if (slot) |allocation| {
        for (payload(allocation.ptr, allocation.size)) |byte| try std.testing.expectEqual(allocation.pattern, byte);
        try std.testing.expect(heap.release(allocation.ptr));
    };
    try expectIntegrity(&heap);
    const first: *const Header = @ptrCast(heap.data.ptr);
    try std.testing.expect(first.next == null);
    try std.testing.expectEqual(heap.data.len - @sizeOf(Header), first.size);
}
