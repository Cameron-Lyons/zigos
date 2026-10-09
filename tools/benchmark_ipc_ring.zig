const std = @import("std");
const ring = @import("ipc_ring");

const SLOTS = 8;
const ITERATIONS = 200_000;
const Workload = enum { split_receive, single_receive, full_queue };
const Enqueue = enum { record, payload };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("IPC ring host benchmark ({s}, {s}): 8 slots, full 88-byte payloads; split receive is a same-build comparison\n", .{
        @tagName(@import("builtin").target.cpu.arch), @import("builtin").target.cpu.model.name,
    });
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
    try output.interface.print("Endpoint enqueue: staged full record versus direct owned payload; user-memory staging excluded equally\n", .{});
    var payload: [ring.PAYLOAD_BYTES]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index * 19 + 1);
    for ([_]usize{ 0, 1, 17, ring.PAYLOAD_BYTES }) |payload_len| {
        inline for (comptime std.meta.tags(Enqueue)) |enqueue| {
            var samples: [5]u64 = undefined;
            var checksum: u64 = 0;
            for (&samples) |*sample| {
                var storage: [ring.minimumBytes(SLOTS)]u8 align(ring.STORAGE_ALIGNMENT) = undefined;
                _ = try ring.init(&storage, SLOTS * ring.SLOT_BYTES);
                const header = ring.RecordHeader{
                    .sender_endpoint_id = 11,
                    .sender_task_id = 22,
                    .correlation_id = 33,
                    .attached_capability_id = 44,
                    .flags = 5,
                    .payload_len = @intCast(payload_len),
                    .move_attached = 1,
                };
                for (0..1000) |_| _ = try enqueueIteration(enqueue, &storage, header, payload[0..payload_len]);
                const start = std.Io.Clock.awake.now(init.io);
                for (0..ITERATIONS) |_| checksum +%= try enqueueIteration(enqueue, &storage, header, payload[0..payload_len]);
                sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
            }
            std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
            try output.interface.print("{d} bytes, {s}: {d:.2} ns/send+receive (median of 5), checksum={d}\n", .{
                payload_len, @tagName(enqueue), @as(f64, @floatFromInt(samples[2])) / ITERATIONS, checksum,
            });
        }
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

noinline fn enqueueIteration(comptime enqueue: Enqueue, storage: []u8, header: ring.RecordHeader, payload: []const u8) !u64 {
    std.mem.doNotOptimizeAway(storage);
    if (enqueue == .record) {
        var record = ring.Record{};
        inline for (@typeInfo(ring.RecordHeader).@"struct".field_names) |field_name| {
            @field(record, field_name) = @field(header, field_name);
        }
        if (payload.len != 0) @memcpy(record.bytes[0..payload.len], payload);
        try ring.pushRecord(storage, record);
    } else {
        try ring.pushPayload(storage, header, payload);
    }
    var out: [ring.PAYLOAD_BYTES]u8 = undefined;
    const received = try ring.receive(storage, &out);
    if (!std.mem.eql(u8, payload, out[0..received.payload_len])) return error.PayloadMismatch;
    std.mem.doNotOptimizeAway(&out);
    return received.correlation_id + if (received.payload_len != 0) @as(u64, out[received.payload_len - 1]) else @as(u64, 0);
}
