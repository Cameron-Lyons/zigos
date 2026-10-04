const std = @import("std");
const heap = @import("heap_allocator").heap;

var arena: [16 * 1024 * 1024]u8 align(32) = undefined;
const Workload = enum { hot_reuse, fragmented_fit, fragmented_exhausted, page_batches, cached_pressure };
const PAGE_BATCH_COUNT = 512;
const PAGE_BATCH_BYTES = 8192;

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Heap allocator host benchmark: 16 MiB arena, 1024 separated free blocks; cached pressure uses 32 KiB\n", .{});
    if (comptime @hasDecl(heap, "metadata_layout")) {
        try output.interface.print("Allocator array metadata: {d} bytes, {d} bytes/span, {d} bytes/index\n", .{
            heap.metadata_layout.array_bytes, heap.metadata_layout.span_bytes, heap.metadata_layout.index_bytes,
        });
    }
    try output.interface.flush();
    inline for (comptime std.meta.tags(Workload)) |workload| {
        const iterations: u32 = switch (workload) {
            .hot_reuse => 200_000,
            .page_batches => 40,
            else => 2000,
        };
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            try heap.initHostArena(if (workload == .cached_pressure) arena[0 .. 32 * 1024] else &arena);
            if (workload == .fragmented_fit or workload == .fragmented_exhausted)
                try fragment(workload == .fragmented_exhausted);
            for (0..if (workload == .page_batches) @as(usize, 2) else 100) |_| _ = try runIteration(workload);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..iterations) |_| {
                checksum +%= try runIteration(workload);
                std.mem.doNotOptimizeAway(&arena);
            }
            sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
        }
        std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
        const elapsed = @as(f64, @floatFromInt(samples[2])) / @as(f64, @floatFromInt(iterations));
        try output.interface.print("{s}: {d:.2} ns/iteration (median of 5, {d} iterations/sample), checksum={d}\n", .{
            @tagName(workload), elapsed, iterations, checksum,
        });
        try output.interface.flush();
    }
    try output.interface.flush();
}

fn fragment(exhaust: bool) !void {
    var holes: [1024]*anyopaque = undefined;
    for (&holes) |*hole| {
        hole.* = heap.kmalloc(64) orelse return error.OutOfMemory;
        _ = heap.kmalloc(16) orelse return error.OutOfMemory;
    }
    if (exhaust) {
        while (heap.kmalloc(4096) != null) {}
        while (heap.kmalloc(16) != null) {}
    }
    for (holes) |hole| heap.kfree(hole);
}

fn runIteration(comptime workload: Workload) !u64 {
    if (workload == .page_batches) return pageBatch();
    if (workload == .cached_pressure) return cachedPressure();
    const size: usize = if (workload == .hot_reuse) 64 else 3072;
    const allocation = heap.kmalloc(size);
    if (workload == .fragmented_exhausted) {
        if (allocation != null) return error.UnexpectedAllocation;
        return 1;
    }
    const ptr = allocation orelse return error.OutOfMemory;
    // Expose the live allocation so allocation/free cannot cancel out.
    std.mem.doNotOptimizeAway(&arena);
    heap.kfree(ptr);
    return size;
}

fn cachedPressure() !u64 {
    var allocations: [8]*anyopaque = undefined;
    var count: usize = 0;
    errdefer for (allocations[0..count]) |ptr| heap.kfree(ptr);
    for (&allocations, 0..) |*allocation, index| {
        allocation.* = heap.kmalloc(4096) orelse return error.OutOfMemory;
        count += 1;
        @as([*]u8, @ptrCast(allocation.*))[0] = @truncate(index);
    }
    var checksum: u64 = 0;
    for (0..allocations.len) |step| {
        const index = (step * 3) % allocations.len;
        const byte = @as([*]u8, @ptrCast(allocations[index]))[0];
        if (byte != @as(u8, @truncate(index))) return error.CorruptPayload;
        checksum += byte;
    }
    for (0..allocations.len) |step| heap.kfree(allocations[(step * 3) % allocations.len]);
    count = 0;
    const combined = heap.kmalloc(32 * 1024) orelse return error.CachedHeapUnavailable;
    std.mem.doNotOptimizeAway(&arena);
    heap.kfree(combined);
    return checksum;
}

fn pageBatch() !u64 {
    var allocations: [PAGE_BATCH_COUNT]*anyopaque = undefined;
    var count: usize = 0;
    errdefer for (allocations[0..count]) |ptr| heap.kfree(ptr);
    for (&allocations, 0..) |*allocation, index| {
        allocation.* = heap.kmalloc(PAGE_BATCH_BYTES) orelse return error.OutOfMemory;
        count += 1;
        const bytes = @as([*]u8, @ptrCast(allocation.*))[0..PAGE_BATCH_BYTES];
        bytes[0] = @truncate(index);
        bytes[bytes.len - 1] = @as(u8, @truncate(index)) ^ 0xa5;
    }
    std.mem.doNotOptimizeAway(&arena);
    var checksum: u64 = 0;
    // Odd-stride order is a permutation: keep live neighbors around free spans
    // and exercise allocation-start lookups and arbitrary free-list unlinking.
    for (0..PAGE_BATCH_COUNT) |step| {
        const index = (step * 73) % PAGE_BATCH_COUNT;
        const bytes = @as([*]u8, @ptrCast(allocations[index]))[0..PAGE_BATCH_BYTES];
        if (bytes[0] != @as(u8, @truncate(index)) or bytes[bytes.len - 1] != (@as(u8, @truncate(index)) ^ 0xa5))
            return error.CorruptPayload;
        checksum += bytes[0] + @as(u64, bytes[bytes.len - 1]);
    }
    for (0..PAGE_BATCH_COUNT) |step| heap.kfree(allocations[(step * 73) % PAGE_BATCH_COUNT]);
    return checksum;
}
