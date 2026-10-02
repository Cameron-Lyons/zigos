const std = @import("std");
const ring = @import("ipc_ring");

const SLOTS = 8;
const ITERATIONS = 200_000;
const Workload = enum { split_receive, single_receive, full_queue };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("IPC ring host benchmark: 8 slots, full 88-byte payloads; split receive is a same-build comparison\n", .{});
    inline for (comptime std.meta.tags(Workload)) |workload| {
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            var storage: [ring.minimumBytes(SLOTS)]u8 align(ring.STORAGE_ALIGNMENT) = undefined;
            _ = try ring.init(&storage, SLOTS * ring.SLOT_BYTES);
            const record = ring.Record{ .payload_len = ring.PAYLOAD_BYTES, .bytes = @splat('x'), .correlation_id = 17 };
            if (workload == .full_queue) {
                for (0..SLOTS) |_| try ring.pushRecord(&storage, record);
            }
            for (0..1000) |_| _ = try iteration(workload, &storage, record);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..ITERATIONS) |_| checksum +%= try iteration(workload, &storage, record);
            sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
        }
        std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
        const elapsed = @as(f64, @floatFromInt(samples[2])) / ITERATIONS;
        try output.interface.print("{s}: {d:.2} ns/iteration (median of 5, {d} iterations/sample), checksum={d}\n", .{
            @tagName(workload), elapsed, ITERATIONS, checksum,
        });
    }
    try output.interface.flush();
}

fn iteration(comptime workload: Workload, storage: []u8, record: ring.Record) !u64 {
    std.mem.doNotOptimizeAway(storage);
    if (workload == .full_queue) {
        ring.pushRecord(storage, record) catch |err| {
            if (err != error.RingFull) return err;
            return 1;
        };
        return error.ExpectedBackpressure;
    }
    try ring.pushRecord(storage, record);
    var out: [ring.PAYLOAD_BYTES]u8 = undefined;
    const received = if (workload == .single_receive)
        try ring.receive(storage, &out)
    else split: {
        const pending = try ring.peekRecord(storage);
        if (pending.payload_len > out.len) return error.PayloadTooLarge;
        const received = try ring.popRecord(storage);
        @memcpy(out[0..received.payload_len], received.bytes[0..received.payload_len]);
        break :split received;
    };
    std.mem.doNotOptimizeAway(&out);
    return received.correlation_id + out[received.payload_len - 1];
}
