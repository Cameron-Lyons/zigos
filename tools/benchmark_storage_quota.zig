const std = @import("std");
const storage = @import("storage_quota");
const quota = storage.quota;
const workspace = storage.workspace;
const Directory = workspace.Directory;
const Store = storage.Store;
const Usage = quota.ProductCapacityUsage;

const ITERATIONS = 1_000_000;
const SAMPLE_COUNT = 7;
const Workload = enum { empty, sparse, full, malformed };
const Method = enum { previous, current };

pub fn main(init: std.process.Init) !void {
    const store = try init.gpa.create(Store);
    defer init.gpa.destroy(store);
    store.* = Store.init();
    store.max_blob_payload_bytes = 4_096;
    const directory = try init.gpa.create(Directory);
    defer init.gpa.destroy(directory);
    var output_buffer: [2_048]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Storage quota host benchmark: {d} workspace + {d} snapshot slots, paired old/current scans\n", .{
        workspace.MAX_WORKSPACES, workspace.MAX_SNAPSHOTS,
    });
    try output.interface.print("Median of {d} alternating-order samples, {d} evaluations/sample; hosted informational timings.\n", .{ SAMPLE_COUNT, ITERATIONS });
    inline for (comptime std.meta.tags(Workload)) |workload| {
        configure(directory, workload);
        // Verify both functions over changing valid entry counts, including the
        // sparse last slots and slots excluded by other malformed metadata.
        for (0..workspace.MAX_WORKSPACE_ENTRIES + 1) |entry_count| {
            varyEntries(directory, entry_count);
            if (!std.meta.eql(previousUsage(store, directory), currentUsage(store, directory))) return error.UsageMismatch;
        }
        var previous_samples: [SAMPLE_COUNT]u64 = undefined;
        var current_samples: [SAMPLE_COUNT]u64 = undefined;
        var checksum: u64 = 0;
        for (0..SAMPLE_COUNT) |sample| {
            const old_first = sample % 2 == 0;
            const first = if (old_first)
                measure(.previous, store, directory, init.io)
            else
                measure(.current, store, directory, init.io);
            const second = if (old_first)
                measure(.current, store, directory, init.io)
            else
                measure(.previous, store, directory, init.io);
            if (first.checksum != second.checksum) return error.ChecksumMismatch;
            previous_samples[sample] = if (old_first) first.nanoseconds else second.nanoseconds;
            current_samples[sample] = if (old_first) second.nanoseconds else first.nanoseconds;
            checksum +%= first.checksum;
        }
        std.mem.sort(u64, &previous_samples, {}, std.sort.asc(u64));
        std.mem.sort(u64, &current_samples, {}, std.sort.asc(u64));
        try output.interface.print("{s}: previous={d:.2} ns current={d:.2} ns/evaluation, checksum={d}\n", .{
            @tagName(workload),
            @as(f64, @floatFromInt(previous_samples[SAMPLE_COUNT / 2])) / ITERATIONS,
            @as(f64, @floatFromInt(current_samples[SAMPLE_COUNT / 2])) / ITERATIONS,
            checksum,
        });
    }
    try output.interface.flush();
}

fn configure(directory: *Directory, comptime workload: Workload) void {
    directory.* = Directory.init();
    if (workload == .empty) return;
    for (&directory.workspaces.slots, 0..) |*slot, index| {
        slot.in_use = workload != .sparse or index == workspace.MAX_WORKSPACES - 1;
        slot.workspace.label_len = 8;
        slot.workspace.counts.entry_count = @intCast(index + 1);
        slot.workspace.counts.entry_mutation_count = @intCast(index * 2);
        slot.workspace.counts.share_grant_count = 1;
        slot.workspace.counts.deleted_count = 2;
        if (workload == .malformed and index % 3 == 0) slot.workspace.counts.share_grant_count = workspace.MAX_SHARE_GRANTS + 1;
    }
    for (&directory.snapshots.slots, 0..) |*slot, index| {
        slot.in_use = workload != .sparse or index == workspace.MAX_SNAPSHOTS - 1;
        slot.snapshot.label_len = 8;
        slot.snapshot.entry_count = @intCast(index + 1);
        if (workload == .malformed and index % 3 == 0) slot.snapshot.label_len = workspace.MAX_WORKSPACE_LABEL_BYTES + 1;
    }
}

fn varyEntries(directory: *Directory, iteration: usize) void {
    directory.workspaces.slots[workspace.MAX_WORKSPACES - 1].workspace.counts.entry_count = @intCast(iteration % (workspace.MAX_WORKSPACE_ENTRIES + 1));
    directory.snapshots.slots[workspace.MAX_SNAPSHOTS - 1].snapshot.entry_count = @intCast((iteration * 3) % (workspace.MAX_WORKSPACE_ENTRIES + 1));
}

fn measure(comptime method: Method, store: *const Store, directory: *Directory, io: std.Io) struct { nanoseconds: u64, checksum: u64 } {
    var checksum: u64 = 0;
    for (0..1_000) |iteration| {
        varyEntries(directory, iteration);
        checksum +%= evaluate(method, store, directory);
    }
    const start = std.Io.Clock.awake.now(io);
    for (0..ITERATIONS) |iteration| {
        varyEntries(directory, iteration);
        checksum +%= evaluate(method, store, directory);
    }
    return .{
        .nanoseconds = @intCast(start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds()),
        .checksum = checksum,
    };
}

fn evaluate(comptime method: Method, store: *const Store, directory: *const Directory) u64 {
    std.mem.doNotOptimizeAway(store);
    std.mem.doNotOptimizeAway(directory);
    const usage = switch (method) {
        .previous => previousUsage(store, directory),
        .current => currentUsage(store, directory),
    };
    return usage.object_payload_bytes + usage.object_records + usage.version_records + usage.blob_records +
        usage.chunk_records + usage.workspaces + usage.snapshots + usage.max_workspace_entries;
}

noinline fn currentUsage(store: *const Store, directory: *const Directory) Usage {
    return quota.productCapacityUsage(store, directory);
}

// Frozen two-pass implementation, compiled beside the current implementation
// with the same host target and compiler. Persistability predicates are shared.
noinline fn previousUsage(store: *const Store, directory: *const Directory) Usage {
    var usage = Usage{
        .object_records = store.objectCount(),
        .version_records = store.versionCount(),
        .blob_records = store.blobCount(),
        .chunk_records = store.chunkCount(),
        .workspaces = quota.workspaceCount(directory),
        .snapshots = quota.snapshotCount(directory),
        .object_payload_bytes = store.maxBlobPayloadBytes(),
    };
    for (&directory.workspaces.slots) |*slot| {
        if (!quota.persistableWorkspaceSlot(slot)) continue;
        usage.max_workspace_entries = @max(usage.max_workspace_entries, slot.workspace.counts.entry_count);
    }
    for (&directory.snapshots.slots) |*slot| {
        if (!quota.persistableSnapshotSlot(slot)) continue;
        usage.max_workspace_entries = @max(usage.max_workspace_entries, slot.snapshot.entry_count);
    }
    return usage;
}
