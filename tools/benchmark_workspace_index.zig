const std = @import("std");
const index_module = @import("workspace_index");
const index = index_module.workspace_index;
const id_index = index_module.id_index;

const PATH_CAPACITY = 192;
const OBJECT_CAPACITY = 96;
const LIVE_ENTRIES = 64;
const PATH_COUNT = 4_096;
const ITERATIONS = 200_000;
const Workload = enum { path_hit, object_hit, churned_path_miss, churned_object_miss, steady_churn };

const Entry = struct {
    path: []const u8,
    object_id: struct {
        value: u64,
        pub fn raw(self: @This()) u64 {
            return self.value;
        }
    },

    pub fn pathSlice(self: *const @This()) []const u8 {
        return self.path;
    }
};

const State = struct {
    paths: [PATH_CAPACITY]index.EntryIndexSlot = index.emptyEntryIndexTable(PATH_CAPACITY),
    objects: [OBJECT_CAPACITY]index.EntryObjectIndexSlot = index.emptyEntryObjectIndexTable(OBJECT_CAPACITY),
    entries: [LIVE_ENTRIES]Entry = undefined,
    next_serial: u64 = LIVE_ENTRIES,
};

pub fn main(init: std.process.Init) !void {
    var path_buffers: [PATH_COUNT][32]u8 = undefined;
    var path_pool: [PATH_COUNT][]const u8 = undefined;
    for (&path_pool, 0..) |*path, i| path.* = try std.fmt.bufPrint(&path_buffers[i], "documents/path-{d:0>4}", .{i});
    var output_buffer: [2_048]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Workspace index host benchmark: {d} path buckets + {d} object buckets, {d} bytes/table pair\n", .{
        PATH_CAPACITY, OBJECT_CAPACITY, @sizeOf(@FieldType(State, "paths")) + @sizeOf(@FieldType(State, "objects")),
    });
    try output.interface.print("Empty misses start after every home has been visited; steady churn keeps {d} canonical entries live.\n", .{LIVE_ENTRIES});
    inline for (comptime std.meta.tags(Workload)) |workload| {
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        for (&samples) |*sample| {
            var state = initialize(workload, &path_pool);
            for (0..1_000) |i| checksum +%= try iteration(workload, &state, &path_pool, i);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..ITERATIONS) |i| checksum +%= try iteration(workload, &state, &path_pool, i);
            sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
        }
        std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
        try output.interface.print("{s}: {d:.2} ns/iteration (median of 5, {d} iterations/sample), checksum={d}\n", .{
            @tagName(workload), @as(f64, @floatFromInt(samples[2])) / ITERATIONS, ITERATIONS, checksum,
        });
    }
    try output.interface.flush();
}

fn initialize(comptime workload: Workload, path_pool: *const [PATH_COUNT][]const u8) State {
    var state = State{};
    // Exercise every home using this revision's hash before retaining live
    // entries. This also catches miss costs left behind by an empty directory.
    var path_homes: [PATH_CAPACITY]bool = @splat(false);
    var object_homes: [OBJECT_CAPACITY]bool = @splat(false);
    var path_remaining: usize = PATH_CAPACITY;
    var object_remaining: usize = OBJECT_CAPACITY;
    var candidate: u64 = 1;
    var path_buffer: [32]u8 = undefined;
    while (path_remaining != 0 or object_remaining != 0) : (candidate += 1) {
        const path = std.fmt.bufPrint(&path_buffer, "retired-{d}", .{candidate}) catch unreachable;
        const entries = [_]Entry{.{ .path = path, .object_id = .{ .value = candidate } }};
        const raw_path_hash = index.pathHash(path);
        const path_home = id_index.hash(if (raw_path_hash == 0) 1 else raw_path_hash, PATH_CAPACITY);
        if (!path_homes[path_home]) {
            index.insertEntryPathSlot(PATH_CAPACITY, &state.paths, &entries, path, 0);
            index.removeEntryPathSlot(PATH_CAPACITY, &state.paths, &entries, path, 0);
            path_homes[path_home] = true;
            path_remaining -= 1;
        }
        const object_home = id_index.hash(candidate, OBJECT_CAPACITY);
        if (!object_homes[object_home]) {
            index.insertEntryObjectSlot(OBJECT_CAPACITY, &state.objects, candidate, 0);
            removeObject(OBJECT_CAPACITY, &state.objects, &entries, 0, candidate);
            object_homes[object_home] = true;
            object_remaining -= 1;
        }
    }
    if (workload != .churned_path_miss and workload != .churned_object_miss) {
        for (&state.entries, 0..) |*entry, slot| {
            entry.* = .{ .path = path_pool[slot], .object_id = .{ .value = slot + 1 } };
            index.insertEntryPathSlot(PATH_CAPACITY, &state.paths, &state.entries, entry.path, slot);
            index.insertEntryObjectSlot(OBJECT_CAPACITY, &state.objects, entry.object_id.raw(), slot);
        }
    }
    return state;
}

fn iteration(comptime workload: Workload, state: *State, path_pool: *const [PATH_COUNT][]const u8, iteration_index: usize) !u64 {
    std.mem.doNotOptimizeAway(state);
    if (workload == .churned_path_miss) {
        if (index.findIndexedEntryPath(PATH_CAPACITY, &state.paths, state.entries[0..0], "missing/path") != null) return error.UnexpectedPath;
        return 1;
    }
    if (workload == .churned_object_miss) {
        if (index.findIndexedEntryObject(OBJECT_CAPACITY, &state.objects, state.entries[0..0], @as(u64, 999_999)) != null) return error.UnexpectedObject;
        return 1;
    }
    const slot = iteration_index % LIVE_ENTRIES;
    if (workload == .path_hit) {
        const found = index.findIndexedEntryPath(PATH_CAPACITY, &state.paths, &state.entries, state.entries[slot].path) orelse return error.MissingPath;
        if (found != slot) return error.WrongPathSlot;
        return found;
    }
    if (workload == .object_hit) {
        const found = index.findIndexedEntryObject(OBJECT_CAPACITY, &state.objects, &state.entries, state.entries[slot].object_id.raw()) orelse return error.MissingObject;
        if (found != slot) return error.WrongObjectSlot;
        return found;
    }
    const previous = state.entries[slot];
    index.removeEntryPathSlot(PATH_CAPACITY, &state.paths, &state.entries, previous.path, slot);
    removeObject(OBJECT_CAPACITY, &state.objects, &state.entries, slot, previous.object_id.raw());
    const serial = state.next_serial;
    state.next_serial += 1;
    state.entries[slot] = .{ .path = path_pool[@intCast(serial % PATH_COUNT)], .object_id = .{ .value = serial + 1 } };
    const replacement = state.entries[slot];
    index.insertEntryPathSlot(PATH_CAPACITY, &state.paths, &state.entries, replacement.path, slot);
    index.insertEntryObjectSlot(OBJECT_CAPACITY, &state.objects, replacement.object_id.raw(), slot);
    if (index.findIndexedEntryPath(PATH_CAPACITY, &state.paths, &state.entries, previous.path) != null) return error.RetainedPath;
    if (index.findIndexedEntryObject(OBJECT_CAPACITY, &state.objects, &state.entries, previous.object_id.raw()) != null) return error.RetainedObject;
    const found_path = index.findIndexedEntryPath(PATH_CAPACITY, &state.paths, &state.entries, replacement.path) orelse return error.MissingReplacementPath;
    const found_object = index.findIndexedEntryObject(OBJECT_CAPACITY, &state.objects, &state.entries, replacement.object_id.raw()) orelse return error.MissingReplacementObject;
    if (found_path != slot or found_object != slot) return error.WrongReplacementSlot;
    return found_path + found_object + 1;
}

fn removeObject(comptime capacity: usize, slots: *[capacity]index.EntryObjectIndexSlot, entries: anytype, slot: usize, object_id: u64) void {
    // Keep this tool runnable against the frozen parent API for paired timing.
    if (comptime @typeInfo(@TypeOf(index.removeEntryObjectSlot)).@"fn".params.len == 5) {
        index.removeEntryObjectSlot(capacity, slots, entries, slot, object_id);
    } else {
        index.removeEntryObjectSlot(capacity, slots, slot, object_id);
    }
}
