const std = @import("std");
const endpoint = @import("endpoint");

const ITERATIONS = 200_000;
const FANOUTS = [_]usize{ 1, 8, 32, endpoint.MAX_ENDPOINTS - 1 };
const Workload = enum { empty, late_pending, send_drain };
const Lookup = enum { scanned, counted };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Endpoint readiness host benchmark: original owner scan vs maintained counts, same build\n", .{});
    inline for (FANOUTS) |fanout| {
        inline for (comptime std.meta.tags(Workload)) |workload| {
            inline for (comptime std.meta.tags(Lookup)) |lookup| {
                var samples: [5]u64 = undefined;
                var checksum: u64 = 0;
                for (&samples) |*sample| {
                    var fixture = try Fixture.create(fanout, workload);
                    defer fixture.table.deinit();
                    for (0..1000) |_| _ = try iteration(lookup, workload, &fixture);
                    const start = std.Io.Clock.awake.now(init.io);
                    for (0..ITERATIONS) |_| checksum +%= try iteration(lookup, workload, &fixture);
                    sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
                }
                std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
                const elapsed = @as(f64, @floatFromInt(samples[2])) / ITERATIONS;
                try output.interface.print("{d} endpoints, {s}, {s}: {d:.2} ns/iteration (median of 5), checksum={d}\n", .{
                    fanout, @tagName(workload), @tagName(lookup), elapsed, checksum,
                });
            }
        }
    }
    try output.interface.flush();
}

const Fixture = struct {
    table: endpoint.Table,
    sender_id: endpoint.ids.EndpointId,
    owner_id: endpoint.ids.TaskId,
    receiver_id: endpoint.ids.EndpointId,

    fn create(fanout: usize, comptime workload: Workload) !Fixture {
        var fixture = Fixture{
            .table = endpoint.Table.init(),
            .sender_id = endpoint.ids.EndpointId.zero,
            .owner_id = endpoint.ids.task(20),
            .receiver_id = endpoint.ids.EndpointId.zero,
        };
        errdefer fixture.table.deinit();
        const sender = try fixture.table.create(endpoint.ids.task(10), "sender", .{});
        fixture.sender_id = sender.id;
        for (0..fanout) |_| {
            fixture.receiver_id = (try fixture.table.create(fixture.owner_id, "receiver", .{})).id;
        }
        try fixture.table.connect(fixture.sender_id, fixture.receiver_id);
        if (workload == .late_pending) {
            _ = try fixture.table.send(fixture.sender_id, endpoint.ids.task(10), 17, "message", null, false);
        }
        return fixture;
    }
};

fn pending(comptime lookup: Lookup, table: *const endpoint.Table, owner_id: endpoint.ids.TaskId) bool {
    if (lookup == .counted) return table.hasPendingForTask(owner_id);
    // Retain the original implementation as a conservative same-build baseline.
    // Both paths pay the new send/drain accounting cost in the roundtrip case.
    var slot_index = table.owner_index.head(owner_id.raw());
    while (slot_index != endpoint.no_index) : (slot_index = table.owner_index.next(slot_index)) {
        if (table.arena.slots[slot_index].endpoint.queue_len != 0) return true;
    }
    return false;
}

fn iteration(comptime lookup: Lookup, comptime workload: Workload, fixture: *Fixture) !u64 {
    std.mem.doNotOptimizeAway(&fixture.table);
    if (workload != .send_drain) {
        const ready = pending(lookup, &fixture.table, fixture.owner_id);
        if (ready != (workload == .late_pending)) return error.UnexpectedReadiness;
        return @intFromBool(ready);
    }
    _ = try fixture.table.send(fixture.sender_id, endpoint.ids.task(10), 17, "message", null, false);
    if (!pending(lookup, &fixture.table, fixture.owner_id)) return error.MissedMessage;
    var out: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    const received = (try fixture.table.recvInto(fixture.receiver_id, &out)) orelse return error.MissedMessage;
    if (pending(lookup, &fixture.table, fixture.owner_id)) return error.MissedDrain;
    std.mem.doNotOptimizeAway(&out);
    return received.correlation_id + out[received.len - 1];
}
