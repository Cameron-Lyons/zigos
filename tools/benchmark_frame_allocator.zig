const std = @import("std");
const frames = @import("frame_allocator");

const managed_bytes = 64 * 1024 * 1024 * 1024;
const page_size = 4096;
const Allocator = frames.Fixed(managed_bytes, page_size);
var storage: Allocator.Storage = undefined;

const Workload = enum { hot_reuse, sparse_page, sparse_run, exhausted_zone };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Frame allocator host benchmark: 64 GiB aperture, {d} bytes of metadata\n", .{@sizeOf(Allocator.Storage)});
    inline for (comptime std.meta.tags(Workload)) |workload| {
        const iterations: u32 = if (workload == .hot_reuse) 1_000_000 else 4_000;
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            var allocator = Allocator.init(&storage);
            if (workload != .hot_reuse) {
                try allocator.reserve(.{ .base = 0, .count = Allocator.total_frames - 64 });
            }
            try allocator.sealReservations();
            for (0..100) |_| _ = try runIteration(workload, &allocator);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..iterations) |_| {
                checksum +%= try runIteration(workload, &allocator);
                std.mem.doNotOptimizeAway(&allocator);
            }
            const end = std.Io.Clock.awake.now(init.io);
            sample.* = @intCast(start.durationTo(end).toNanoseconds());
        }
        std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
        const ns_per_iteration = @as(f64, @floatFromInt(samples[samples.len / 2])) / @as(f64, @floatFromInt(iterations));
        try output.interface.print("{s}: {d:.2} ns/iteration (median of 5, {d} iterations/sample), checksum={d}\n", .{
            @tagName(workload), ns_per_iteration, iterations, checksum,
        });
    }
    try output.interface.flush();
}

fn runIteration(comptime workload: Workload, allocator: *Allocator) !u64 {
    if (workload != .hot_reuse) allocator.search_frame_hint = 0;
    if (workload == .exhausted_zone) {
        // Keep free memory outside the requested range so global exhaustion
        // shortcuts cannot hide the cost of a bounded failed allocation.
        if (allocator.allocateBelow(1, managed_bytes - 64 * page_size) != null) return error.UnexpectedAllocation;
        return 1;
    }
    const expected_base: u64 = if (workload == .hot_reuse) 0 else managed_bytes - 64 * page_size;
    if (workload == .hot_reuse or workload == .sparse_page) {
        // Match the single-page API used by paging.allocGeneralFrame.
        const base = allocator.allocateFrameBetween(0, managed_bytes) orelse return error.OutOfMemory;
        if (base != expected_base) return error.UnexpectedAddress;
        // Expose the live allocation so allocation/free cannot cancel out.
        std.mem.doNotOptimizeAway(allocator);
        try allocator.releaseFrame(base);
        return base / page_size + 1;
    }
    const run = allocator.allocate(32) orelse return error.OutOfMemory;
    if (run.base != expected_base) return error.UnexpectedAddress;
    std.mem.doNotOptimizeAway(allocator);
    try allocator.release(run);
    return run.base / page_size + run.count;
}
