const std = @import("std");
const id_index = @import("id_index");

const CAPACITY = 512;
const LIVE_KEYS = 128;
const ITERATIONS = 200_000;
const Workload = enum {
    sequential_hit,
    sequential_miss,
    generation_hit,
    generation_miss,
    cycled_empty_miss,
    steady_churn,
};

const State = struct {
    table: id_index.Table(CAPACITY) = id_index.emptyTable(CAPACITY),
    live_ids: [LIVE_KEYS]u64 = @splat(0),
    next_id: u64 = CAPACITY + LIVE_KEYS + 1,
};

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("ID index host benchmark: {d} buckets, {d} live keys, {d} bytes/table\n", .{ CAPACITY, LIVE_KEYS, @sizeOf(id_index.Table(CAPACITY)) });
    try output.interface.print("Empty misses and steady churn start after every home bucket has been visited; generation keys share one slot number.\n", .{});

    inline for (comptime std.meta.tags(Workload)) |workload| {
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            var state = initialize(workload);
            for (0..1_000) |i| checksum +%= try iteration(workload, &state, i);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..ITERATIONS) |i| checksum +%= try iteration(workload, &state, i);
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

fn initialize(comptime workload: Workload) State {
    var state = State{};
    if (workload == .cycled_empty_miss or workload == .steady_churn) {
        // Find a key for each home using this build's hash. Both revisions see
        // every bucket, even when comparing different bucket hash functions.
        var visited: [CAPACITY]bool = @splat(false);
        var remaining: usize = CAPACITY;
        var candidate: u64 = 1;
        while (remaining != 0) : (candidate += 1) {
            const home = id_index.hash(candidate, CAPACITY);
            if (visited[home]) continue;
            id_index.insertAbsent(CAPACITY, &state.table, candidate, 0, "benchmark ids are nonzero");
            id_index.remove(CAPACITY, &state.table, candidate);
            visited[home] = true;
            remaining -= 1;
        }
    }
    if (workload != .cycled_empty_miss) {
        for (&state.live_ids, 0..) |*id, i| {
            id.* = keyFor(workload, i);
            id_index.insertAbsent(CAPACITY, &state.table, id.*, i, "benchmark ids are nonzero");
        }
    }
    return state;
}

fn iteration(comptime workload: Workload, state: *State, iteration_index: usize) !u64 {
    std.mem.doNotOptimizeAway(&state.table);
    const slot = iteration_index % LIVE_KEYS;
    if (workload == .steady_churn) {
        const previous = id_index.lookup(CAPACITY, &state.table, state.live_ids[slot]) orelse return error.MissingLiveKey;
        if (previous != slot) return error.WrongLiveSlot;
        id_index.remove(CAPACITY, &state.table, state.live_ids[slot]);
        const replacement = state.next_id;
        state.next_id += 1;
        state.live_ids[slot] = replacement;
        id_index.insertAbsent(CAPACITY, &state.table, replacement, slot, "benchmark ids are nonzero");
        const found = id_index.lookup(CAPACITY, &state.table, replacement) orelse return error.MissingReplacement;
        if (found != slot) return error.WrongReplacementSlot;
        if (id_index.lookup(CAPACITY, &state.table, state.next_id) != null) return error.UnexpectedHit;
        return previous + found + 1;
    }
    if (workload == .cycled_empty_miss) {
        const query: u64 = @intCast(iteration_index + CAPACITY + 1);
        if (id_index.lookup(CAPACITY, &state.table, query) != null) return error.UnexpectedHit;
        return query & 0xFF;
    }
    if (workload == .sequential_miss or workload == .generation_miss) {
        const query = keyFor(workload, slot + LIVE_KEYS);
        if (id_index.lookup(CAPACITY, &state.table, query) != null) return error.UnexpectedHit;
        return query & 0xFF;
    }
    const found = id_index.lookup(CAPACITY, &state.table, state.live_ids[slot]) orelse return error.MissingLiveKey;
    if (found != slot) return error.WrongLiveSlot;
    return found;
}

fn keyFor(comptime workload: Workload, index: usize) u64 {
    return switch (workload) {
        .generation_hit, .generation_miss => (@as(u64, index + 1) << 32) | 7,
        else => @intCast(index + 1),
    };
}
