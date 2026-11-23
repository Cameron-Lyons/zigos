const std = @import("std");
const native_util = @import("../../core/util.zig");
const object_store = @import("../../storage/object_store.zig");
const workspace = @import("../../storage/workspace.zig");

const max_mutations = workspace.MAX_WORKSPACE_ENTRY_MUTATIONS;
const capacity: usize = max_mutations * 2;
const MutationIndex = u8;
const no_mutation: MutationIndex = std.math.maxInt(MutationIndex);
// One path hash per mutation plus the latest-mutation bit set.
pub const LATEST_SIZE_CEILING_BYTES: usize = max_mutations * @sizeOf(u64) + 32;

comptime {
    if (max_mutations >= no_mutation) {
        @compileError("latest mutation indexes cannot represent the workspace mutation capacity");
    }
}

/// Marks the newest mutation of every path in a bounded workspace change log
/// and keeps each mutation's path hash, so replication hashes each path once.
pub const Latest = struct {
    latest: std.bit_set.Static(max_mutations) = .empty,
    path_hashes: [max_mutations]u64 = undefined,

    pub fn isLatest(self: *const Latest, mutation_index: usize) bool {
        return self.latest.isSet(mutation_index);
    }

    pub fn pathHash(self: *const Latest, mutation_index: usize) u64 {
        return self.path_hashes[mutation_index];
    }
};

comptime {
    if (@sizeOf(Latest) > LATEST_SIZE_CEILING_BYTES) {
        @compileError("latest mutation set exceeds its compact size ceiling");
    }
}

pub fn build(changes: []const workspace.EntryMutation) Latest {
    if (changes.len > max_mutations) {
        native_util.impossibleByInvariant("latest mutation set requires a bounded workspace change log");
    }
    var result = Latest{};
    for (changes, result.path_hashes[0..changes.len]) |*change, *path_hash| {
        path_hash.* = change.entry.pathHash();
    }
    markLatest(changes, &result);
    return result;
}

// Later mutations of a path replace earlier ones in an open-addressed table
// keyed by the exact path; the survivors are the latest mutations.
fn markLatest(changes: []const workspace.EntryMutation, result: *Latest) void {
    var slots: [capacity]MutationIndex = @as([capacity]MutationIndex, @splat(no_mutation));
    for (changes, 0..) |*change, mutation_index| {
        const path_hash = result.path_hashes[mutation_index];
        var slot_index: usize = @intCast(path_hash % capacity);
        var probes: usize = 0;
        while (true) : ({
            probes += 1;
            slot_index = (slot_index + 1) % capacity;
        }) {
            if (probes == capacity) native_util.impossibleByInvariant("latest mutation table capacity covers workspace changes");
            const slot = &slots[slot_index];
            if (slot.* == no_mutation or (result.path_hashes[slot.*] == path_hash and
                std.mem.eql(u8, changes[slot.*].entry.pathSlice(), change.entry.pathSlice())))
            {
                slot.* = @intCast(mutation_index);
                break;
            }
        }
    }
    for (slots) |slot| {
        if (slot != no_mutation) result.latest.set(slot);
    }
}

test "latest mutation set tracks newest mutation per path" {
    var changes: [4]workspace.EntryMutation = undefined;
    changes[0] = .{
        .generation = 1,
        .entry = try workspace.Entry.init("documents/notes.md", object_store.ids.object(1), object_store.ids.version(10), .document),
    };
    changes[1] = .{
        .generation = 2,
        .entry = try workspace.Entry.init("assets/cover.jpg", object_store.ids.object(2), object_store.ids.version(20), .media_asset),
    };
    changes[2] = .{
        .generation = 3,
        .entry = try workspace.Entry.init("documents/notes.md", object_store.ids.object(1), object_store.ids.version(11), .document),
    };
    changes[3] = .{
        .generation = 4,
        .entry = try workspace.Entry.init("documents/todo.md", object_store.ids.object(3), object_store.ids.version(30), .document),
    };

    const latest = build(changes[0..]);
    try std.testing.expect(!latest.isLatest(0));
    try std.testing.expect(latest.isLatest(1));
    try std.testing.expect(latest.isLatest(2));
    try std.testing.expect(latest.isLatest(3));
    for (changes, 0..) |change, index| try std.testing.expectEqual(change.entry.pathHash(), latest.pathHash(index));
}

test "latest mutation set resolves colliding paths and repeated deletions exactly" {
    var colliding_entries: [3]workspace.Entry = undefined;
    var count: usize = 0;
    var home: usize = 0;
    for (0..capacity * 32) |candidate| {
        var path_buffer: [48]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "documents/probe-{d}.md", .{candidate});
        const entry = try workspace.Entry.init(path, object_store.ids.object(candidate + 1), object_store.ids.version(candidate + 1), .document);
        const entry_home = entry.pathHash() % capacity;
        if (count == 0) home = entry_home;
        if (entry_home != home) continue;
        colliding_entries[count] = entry;
        count += 1;
        if (count == colliding_entries.len) break;
    }
    try std.testing.expectEqual(colliding_entries.len, count);

    var changes = [_]workspace.EntryMutation{
        .{ .generation = 1, .entry = colliding_entries[0] },
        .{ .generation = 1, .entry = colliding_entries[1] },
        .{ .generation = 1, .entry = colliding_entries[2] },
        .{ .generation = 2, .entry = colliding_entries[1] },
        .{ .generation = 3, .entry = colliding_entries[0] },
        .{ .generation = 4, .entry = colliding_entries[2] },
    };
    changes[3].entry.object_id = object_store.ids.ObjectId.zero;
    changes[3].entry.version_id = object_store.ids.VersionId.zero;
    const latest = build(&changes);
    for (0..3) |index| try std.testing.expect(!latest.isLatest(index));
    for (3..6) |index| try std.testing.expect(latest.isLatest(index));

    // A full-hash collision must still resolve the exact canonical path
    // instead of merging distinct entries.
    var equal_hashes = Latest{};
    @memset(equal_hashes.path_hashes[0..changes.len], colliding_entries[0].pathHash());
    markLatest(&changes, &equal_hashes);
    for (0..3) |index| try std.testing.expect(!equal_hashes.isLatest(index));
    for (3..6) |index| try std.testing.expect(equal_hashes.isLatest(index));
}

test "latest mutation set covers the full log and its highest mutation index" {
    var changes: [max_mutations]workspace.EntryMutation = undefined;
    for (&changes, 0..) |*change, index| {
        var path_buffer: [48]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "documents/full-log-{d}.md", .{index});
        change.* = .{
            .generation = @intCast(index + 1),
            .entry = try workspace.Entry.init(path, object_store.ids.object(index + 1), object_store.ids.version(index + 1), .document),
        };
    }
    const unique = build(&changes);
    for (0..changes.len) |index| try std.testing.expect(unique.isLatest(index));

    for (&changes) |*change| change.entry = changes[0].entry;
    const repeated = build(&changes);
    for (0..changes.len - 1) |index| try std.testing.expect(!repeated.isLatest(index));
    try std.testing.expect(repeated.isLatest(changes.len - 1));

    const empty = build(&.{});
    try std.testing.expectEqual(@as(usize, 0), empty.latest.count());
}
