const std = @import("std");
const Heap = @import("heap_allocator").Heap;

var arena: [16 * 1024 * 1024]u8 align(16) = undefined;
const Workload = enum { hot_reuse, fragmented_fit, fragmented_exhausted };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Heap allocator host benchmark: 16 MiB arena, 4096 separated free blocks\n", .{});
    inline for (comptime std.meta.tags(Workload)) |workload| {
        const iterations: u32 = if (workload == .hot_reuse) 200_000 else 2000;
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            var heap: Heap = undefined;
            try heap.init(&arena);
            if (workload != .hot_reuse) try fragment(&heap, workload == .fragmented_exhausted);
            for (0..100) |_| _ = try runIteration(workload, &heap);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..iterations) |_| {
                checksum +%= try runIteration(workload, &heap);
                std.mem.doNotOptimizeAway(&heap);
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

fn fragment(heap: *Heap, exhaust: bool) !void {
    var holes: [4096]*anyopaque = undefined;
    for (&holes) |*hole| {
        hole.* = heap.allocate(64) orelse return error.OutOfMemory;
        _ = heap.allocate(16) orelse return error.OutOfMemory;
    }
    if (exhaust) {
        while (heap.allocate(4096) != null) {}
        while (heap.allocate(16) != null) {}
    }
    for (holes) |hole| if (!heap.release(hole)) return error.InvalidRelease;
}

fn runIteration(comptime workload: Workload, heap: *Heap) !u64 {
    const size: usize = if (workload == .hot_reuse) 64 else 3072;
    const allocation = heap.allocate(size);
    if (workload == .fragmented_exhausted) {
        if (allocation != null) return error.UnexpectedAllocation;
        return 1;
    }
    const ptr = allocation orelse return error.OutOfMemory;
    // Expose the live allocation so allocation/free cannot cancel out.
    std.mem.doNotOptimizeAway(&arena);
    std.mem.doNotOptimizeAway(heap);
    if (!heap.release(ptr)) return error.InvalidRelease;
    return size;
}
