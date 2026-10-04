const std = @import("std");
const heap = @import("memory.zig");
const cpu_identity = @import("../cpu_identity.zig");
const heap_geometry = @import("heap_geometry.zig");

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

test "heap reclaims adjacent cached pages for a larger allocation" {
    var arena: [8 * 4096]u8 align(32) = undefined;
    for ([_]usize{ 1, 3, 5, 7 }) |stride| {
        try heap.initHostArena(&arena);
        var blocks: [8]*anyopaque = undefined;
        for (&blocks) |*block| block.* = heap.kmalloc(4096) orelse return error.OutOfMemory;
        for (0..blocks.len) |step| heap.kfree(blocks[(step * stride) % blocks.len]);
        const combined = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
        try std.testing.expectEqual(@intFromPtr(&arena), @intFromPtr(combined));
        heap.kfree(combined);
    }
}

test "heap reclaims every cached class while preserving a live neighbor" {
    const cached_bytes = 8 * 8160;
    var arena: [cached_bytes + 32]u8 align(32) = undefined;
    try heap.initHostArena(&arena);
    const guard = heap.kmalloc(32) orelse return error.OutOfMemory;
    @memset(payload(guard, 32), 0xc7);
    var blocks: [8 * heap_geometry.size_classes.len]*anyopaque = undefined;
    for (heap_geometry.size_classes, 0..) |size, class| {
        for (0..8) |index| blocks[class * 8 + index] = heap.kmalloc(size) orelse return error.OutOfMemory;
    }
    for (0..blocks.len) |step| heap.kfree(blocks[(step * 37) % blocks.len]);
    // Pressure must reclaim caches without consuming or relocating the guard.
    try std.testing.expect(heap.kmalloc(arena.len) == null);
    const combined = heap.kmalloc(cached_bytes) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(&arena) + 32, @intFromPtr(combined));
    @memset(payload(combined, cached_bytes), 0xa5);
    for (payload(guard, 32)) |byte| try std.testing.expectEqual(@as(u8, 0xc7), byte);
    heap.kfree(combined);
    heap.kfree(guard);
    const entire = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(&arena), @intFromPtr(entire));
    heap.kfree(entire);
}

test "heap reclaims remote CPU magazines and retires old recent identities" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    var arena: [8 * 4096]u8 align(32) = undefined;
    try heap.initHostArena(&arena);
    var blocks: [8]*anyopaque = undefined;
    for (&blocks, 0..) |*block, index| {
        cpu_identity.setIndexForTest(@intCast(index));
        block.* = heap.kmalloc(4096) orelse return error.OutOfMemory;
    }
    for (blocks, 0..) |block, index| {
        cpu_identity.setIndexForTest(@intCast((index + 1) % heap.MAGAZINE_CPUS));
        heap.kfree(block);
    }
    cpu_identity.setIndexForTest(0);
    const combined = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(&arena), @intFromPtr(combined));
    @memset(payload(combined, arena.len), 0xc7);
    // Old starts now inside the combined live allocation must be rejected on
    // each original CPU, even though their span IDs were coalesced and recycled.
    for (1..blocks.len) |index| {
        cpu_identity.setIndexForTest(@intCast(index));
        heap.kfree(blocks[index]);
    }
    try std.testing.expect(heap.kmalloc(32) == null);
    for (payload(combined, arena.len)) |byte| try std.testing.expectEqual(@as(u8, 0xc7), byte);
    heap.kfree(combined);
    cpu_identity.setIndexForTest(0);
    const recovered = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(combined), @intFromPtr(recovered));
    heap.kfree(recovered);
}

test "heap pressure recycles cached spans at metadata capacity" {
    const count = heap.metadata_layout.span_capacity;
    const arena = try std.testing.allocator.alignedAlloc(u8, .@"32", count * 4096);
    defer std.testing.allocator.free(arena);
    try heap.initHostArena(arena);
    var blocks: [count]*anyopaque = undefined;
    for (&blocks, 0..) |*block, index| {
        block.* = heap.kmalloc(4096) orelse return error.OutOfMemory;
        @memset(payload(block.*, 4096), @truncate(index));
    }
    for (blocks[0..8]) |block| heap.kfree(block);
    const reclaimed = heap.kmalloc(8 * 4096) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(arena.ptr), @intFromPtr(reclaimed));
    for (blocks[8..], 8..) |block, index| {
        for (payload(block, 4096)) |byte| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    }
    heap.kfree(reclaimed);
    for (0..count - 8) |step| heap.kfree(blocks[8 + (step * 61) % (count - 8)]);
    const combined = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(arena.ptr), @intFromPtr(combined));
    heap.kfree(combined);
}

test "heap recovers remote cached metadata before consuming a large unsplit tail" {
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    const count = heap.metadata_layout.span_capacity - 1;
    const arena = try std.testing.allocator.alignedAlloc(u8, .@"32", 16 * 1024 * 1024);
    defer std.testing.allocator.free(arena);
    try heap.initHostArena(arena);
    var blocks: [count]*anyopaque = undefined;
    for (&blocks, 0..) |*block, index| {
        block.* = heap.kmalloc(32) orelse return error.OutOfMemory;
        @memset(payload(block.*, 32), @truncate(index));
    }
    for (blocks[0..8]) |block| heap.kfree(block);
    cpu_identity.setIndexForTest(1);
    const small = heap.kmalloc(32) orelse return error.OutOfMemory;
    const page = heap.kmalloc(4096) orelse return error.OutOfMemory;
    @memset(payload(small, 32), 0xa5);
    @memset(payload(page, 4096), 0xc7);
    for (blocks[8..], 8..) |block, index| {
        for (payload(block, 32)) |byte| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    }
    heap.kfree(small);
    heap.kfree(page);
    for (blocks[8..]) |block| heap.kfree(block);
    const recovered = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(arena.ptr), @intFromPtr(recovered));
    heap.kfree(recovered);
}

test "heap preserves an unsplit tail when no metadata can be reclaimed" {
    const count = heap.metadata_layout.span_capacity - 1;
    const arena = try std.testing.allocator.alignedAlloc(u8, .@"32", 16 * 1024 * 1024);
    defer std.testing.allocator.free(arena);
    try heap.initHostArena(arena);
    var blocks: [count]*anyopaque = undefined;
    for (&blocks) |*block| block.* = heap.kmalloc(32) orelse return error.OutOfMemory;
    const tail_bytes = arena.len - count * 32;
    const tail = heap.kmalloc(tail_bytes) orelse return error.OutOfMemory;
    @memset(payload(tail, tail_bytes), 0xc7);
    try std.testing.expect(heap.kmalloc(32) == null);
    heap.kfree(tail);
    // This smaller request still succeeds by owning the complete free tail;
    // every metadata slot is live and no magazine can supply a recycled ID.
    const small = heap.kmalloc(32) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(tail), @intFromPtr(small));
    for (payload(small, tail_bytes)) |byte| try std.testing.expectEqual(@as(u8, 0xc7), byte);
    try std.testing.expect(heap.kmalloc(4096) == null);
    heap.kfree(small);
    for (blocks) |block| heap.kfree(block);
    const recovered = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(arena.ptr), @intFromPtr(recovered));
    heap.kfree(recovered);
}

test "heap finds a later exact fit before reclaiming split metadata" {
    const count = heap.metadata_layout.span_capacity - 4;
    const arena = try std.testing.allocator.alignedAlloc(u8, .@"32", 1024 * 1024);
    defer std.testing.allocator.free(arena);
    try heap.initHostArena(arena);
    const larger = heap.kmalloc(16384) orelse return error.OutOfMemory;
    var blocks: [count]*anyopaque = undefined;
    for (&blocks) |*block| block.* = heap.kmalloc(32) orelse return error.OutOfMemory;
    const exact = heap.kmalloc(8192) orelse return error.OutOfMemory;
    const separator = heap.kmalloc(32) orelse return error.OutOfMemory;
    // Both free spans remain isolated, and all 4096 metadata IDs stay used.
    // The oversized span is now first in the shared overflow-class list.
    heap.kfree(exact);
    heap.kfree(larger);
    const chosen = heap.kmalloc(8192) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(exact), @intFromPtr(chosen));
    const preserved = heap.kmalloc(16384) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(larger), @intFromPtr(preserved));
    heap.kfree(chosen);
    heap.kfree(preserved);
    heap.kfree(separator);
    for (blocks) |block| heap.kfree(block);
    const recovered = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(arena.ptr), @intFromPtr(recovered));
    heap.kfree(recovered);
}

test "heap pressure and cached reuse preserve concurrently owned payloads" {
    const spin = @import("../utils/spin.zig");
    const Live = struct { pointer: *anyopaque, size: usize, pattern: u8 };
    const Mailbox = struct {
        lock: spin.Lock = .{},
        ready: bool = false,
        live: ?Live = null,
    };
    const Worker = struct {
        failed: *bool,
        serial: usize,
        mailboxes: *[4]Mailbox,
        start: *bool,
        cancel: *bool,

        fn run(self: @This()) void {
            const previous_cpu = cpu_identity.currentIndex();
            defer cpu_identity.setIndexForTest(previous_cpu);
            cpu_identity.setIndexForTest(@intCast(self.serial + 1));
            while (!@atomicLoad(bool, self.start, .acquire)) spin.hint();
            if (@atomicLoad(bool, self.cancel, .acquire)) return;
            for (0..500) |iteration| {
                var live: [8]?Live = @splat(null);
                for (&live, 0..) |*entry, slot| {
                    const size = heap_geometry.size_classes[(self.serial + iteration + slot) % heap_geometry.size_classes.len];
                    if (heap.kmalloc(size)) |pointer| {
                        const pattern: u8 = @truncate(self.serial * 37 + iteration + slot);
                        @memset(payload(pointer, size), pattern);
                        entry.* = .{ .pointer = pointer, .size = size, .pattern = pattern };
                    }
                }
                for (live[0 .. live.len - 1]) |entry| if (entry) |allocation| {
                    for (payload(allocation.pointer, allocation.size)) |byte| {
                        if (byte != allocation.pattern) @atomicStore(bool, self.failed, true, .release);
                    }
                    heap.kfree(allocation.pointer);
                };
                // Transfer exclusive payload ownership to a different modeled
                // CPU. Mailbox locks are released before entering the heap.
                const outgoing = &self.mailboxes[self.serial];
                while (true) {
                    outgoing.lock.acquire();
                    if (!outgoing.ready) {
                        outgoing.live = live[live.len - 1];
                        outgoing.ready = true;
                        outgoing.lock.release();
                        break;
                    }
                    outgoing.lock.release();
                    spin.hint();
                }
                const incoming = &self.mailboxes[(self.serial + self.mailboxes.len - 1) % self.mailboxes.len];
                const received = received: while (true) {
                    incoming.lock.acquire();
                    if (incoming.ready) {
                        const allocation = incoming.live;
                        incoming.live = null;
                        incoming.ready = false;
                        incoming.lock.release();
                        break :received allocation;
                    }
                    incoming.lock.release();
                    spin.hint();
                };
                if (received) |allocation| {
                    for (payload(allocation.pointer, allocation.size)) |byte| {
                        if (byte != allocation.pattern) @atomicStore(bool, self.failed, true, .release);
                    }
                    heap.kfree(allocation.pointer);
                }
            }
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    var arena: [64 * 1024]u8 align(32) = undefined;
    try heap.initHostArena(&arena);
    var failed = false;
    var start = false;
    var cancel = false;
    var mailboxes: [4]Mailbox = @splat(.{});
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&threads, 0..) |*thread, serial| {
        thread.* = std.Thread.spawn(.{}, Worker.run, .{Worker{
            .failed = &failed,
            .serial = serial,
            .mailboxes = &mailboxes,
            .start = &start,
            .cancel = &cancel,
        }}) catch |err| {
            @atomicStore(bool, &cancel, true, .release);
            @atomicStore(bool, &start, true, .release);
            return err;
        };
        started += 1;
    }
    @atomicStore(bool, &start, true, .release);
    for (0..1000) |_| {
        if (heap.kmalloc(32 * 1024)) |large| {
            @memset(payload(large, 32 * 1024), 0xa5);
            for (payload(large, 32 * 1024)) |byte| {
                if (byte != 0xa5) @atomicStore(bool, &failed, true, .release);
            }
            heap.kfree(large);
        }
    }
    for (threads[0..started]) |thread| thread.join();
    started = 0;
    try std.testing.expect(!@atomicLoad(bool, &failed, .acquire));
    const recovered = heap.kmalloc(arena.len) orelse return error.OutOfMemory;
    try std.testing.expectEqual(@intFromPtr(&arena), @intFromPtr(recovered));
    heap.kfree(recovered);
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
