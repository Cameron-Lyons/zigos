const std = @import("std");
const heap = @import("heap_allocator").heap;

var arena: [16 * 1024 * 1024]u8 align(16) = undefined;
const Workload = enum { hot_reuse, fragmented_fit, fragmented_exhausted };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Heap allocator host benchmark: 16 MiB arena, 1024 separated free blocks\n", .{});
    inline for (comptime std.meta.tags(Workload)) |workload| {
        const iterations: u32 = if (workload == .hot_reuse) 200_000 else 2000;
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            try heap.initHostArena(&arena);
            if (workload != .hot_reuse) try fragment(workload == .fragmented_exhausted);
            for (0..100) |_| _ = try runIteration(workload);
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
