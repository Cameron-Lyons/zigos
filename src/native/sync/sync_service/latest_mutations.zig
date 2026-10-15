const std = @import("std");
const native_util = @import("../../core/util.zig");
const object_store = @import("../../storage/object_store.zig");
const workspace = @import("../../storage/workspace.zig");

pub const capacity: usize = workspace.MAX_WORKSPACE_ENTRY_MUTATIONS * 2;
pub const MutationIndex = u8;
pub const COMPACT_MUTATION_INDEX_METADATA = true;
pub const SLOT_SIZE_CEILING_BYTES: usize = 9;
pub const INDEX_SIZE_CEILING_BYTES: usize = capacity * SLOT_SIZE_CEILING_BYTES;

comptime {
    if (workspace.MAX_WORKSPACE_ENTRY_MUTATIONS > std.math.maxInt(MutationIndex)) {
        @compileError("latest mutation indexes cannot represent the workspace mutation capacity");
    }
}

// Split references from hashes to avoid per-slot padding. Only references need
// initialization; a hash is written before its reference becomes occupied.
const no_mutation: MutationIndex = std.math.maxInt(MutationIndex);

pub const Index = struct {
    mutation_indices: [capacity]MutationIndex = @as([capacity]MutationIndex, @splat(no_mutation)),
    path_hashes: [capacity]u64 = undefined,

    fn put(self: *Index, changes: []const workspace.EntryMutation, mutation_index: usize) void {
        requireMutationBounds(changes, mutation_index);
        const entry = &changes[mutation_index].entry;
        const path_hash = entry.pathHash();
        const path = entry.pathSlice();
        var slot_index = slotStart(path_hash);
        var probes: usize = 0;
        while (probes < capacity) : ({
            probes += 1;
            slot_index = (slot_index + 1) % capacity;
        }) {
            const slot = &self.mutation_indices[slot_index];
            if (slot.* == no_mutation) {
                self.path_hashes[slot_index] = path_hash;
                slot.* = @intCast(mutation_index);
                return;
            }
            if (self.path_hashes[slot_index] == path_hash and std.mem.eql(u8, changes[slot.*].entry.pathSlice(), path)) {
                slot.* = @intCast(mutation_index);
                return;
            }
        }
        native_util.impossibleByInvariant("latest mutation index capacity covers workspace changes");
    }

    pub fn latestIndexFor(
        self: *const Index,
        changes: []const workspace.EntryMutation,
        path_hash: u64,
        path: []const u8,
    ) ?usize {
        var slot_index = slotStart(path_hash);
        var probes: usize = 0;
        while (probes < capacity) : ({
            probes += 1;
            slot_index = (slot_index + 1) % capacity;
        }) {
            const slot = self.mutation_indices[slot_index];
            if (slot == no_mutation) return null;
            if (self.path_hashes[slot_index] == path_hash and std.mem.eql(u8, changes[slot].entry.pathSlice(), path)) {
                return slot;
            }
        }
        return null;
    }

    pub fn isLatest(self: *const Index, changes: []const workspace.EntryMutation, mutation_index: usize) bool {
        requireMutationBounds(changes, mutation_index);
        const entry = &changes[mutation_index].entry;
        return self.latestIndexFor(changes, entry.pathHash(), entry.pathSlice()) == mutation_index;
    }
};

comptime {
    if (@sizeOf(Index) > INDEX_SIZE_CEILING_BYTES) {
        @compileError("latest mutation index exceeds its compact size ceiling");
    }
}

pub fn build(changes: []const workspace.EntryMutation) Index {
    if (changes.len > workspace.MAX_WORKSPACE_ENTRY_MUTATIONS) {
        native_util.impossibleByInvariant("latest mutation index requires a bounded workspace change log");
    }
    var index = Index{};
    for (changes, 0..) |_, mutation_index| {
        index.put(changes, mutation_index);
    }
    return index;
}

fn requireMutationBounds(changes: []const workspace.EntryMutation, mutation_index: usize) void {
    if (changes.len > workspace.MAX_WORKSPACE_ENTRY_MUTATIONS or mutation_index >= changes.len) {
        native_util.impossibleByInvariant("latest mutation reference belongs to a bounded workspace change log");
    }
}

fn slotStart(path_hash: u64) usize {
    return @intCast(path_hash % capacity);
}

test "latest mutation index uses capacity-sized slot metadata" {
    try std.testing.expect(COMPACT_MUTATION_INDEX_METADATA);
    try std.testing.expectEqual([capacity]MutationIndex, @FieldType(Index, "mutation_indices"));
    try std.testing.expectEqual([capacity]u64, @FieldType(Index, "path_hashes"));
    try std.testing.expect(@sizeOf(Index) <= INDEX_SIZE_CEILING_BYTES);
}

test "latest mutation index tracks newest mutation per path hash" {
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
    try std.testing.expect(!latest.isLatest(changes[0..], 0));
    try std.testing.expect(latest.isLatest(changes[0..], 1));
    try std.testing.expect(latest.isLatest(changes[0..], 2));
    try std.testing.expect(latest.isLatest(changes[0..], 3));
    try std.testing.expectEqual(@as(?usize, 2), latest.latestIndexFor(
        changes[0..],
        changes[0].entry.pathHash(),
        "documents/notes.md",
    ));
}

test "latest mutation index resolves colliding paths and repeated deletions exactly" {
    var colliding_entries: [4]workspace.Entry = undefined;
    var count: usize = 0;
    var home: usize = 0;
    for (0..capacity * 32) |candidate| {
        var path_buffer: [48]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "documents/probe-{d}.md", .{candidate});
        const entry = try workspace.Entry.init(path, object_store.ids.object(candidate + 1), object_store.ids.version(candidate + 1), .document);
        const entry_home = slotStart(entry.pathHash());
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
    for (0..3) |index| try std.testing.expect(!latest.isLatest(&changes, index));
    for (3..6) |index| try std.testing.expect(latest.isLatest(&changes, index));
    for ([_][2]usize{ .{ 0, 4 }, .{ 1, 3 }, .{ 2, 5 } }) |pair| {
        const entry = &colliding_entries[pair[0]];
        try std.testing.expectEqual(@as(?usize, pair[1]), latest.latestIndexFor(&changes, entry.pathHash(), entry.pathSlice()));
    }
    const absent = &colliding_entries[3];
    try std.testing.expectEqual(@as(?usize, null), latest.latestIndexFor(&changes, absent.pathHash(), absent.pathSlice()));

    // Simulate a full-hash collision as well as a shared home. Hash equality
    // must still resolve the exact canonical path instead of merging entries.
    var equal_hashes = latest;
    const shared_hash = colliding_entries[0].pathHash();
    for (&equal_hashes.path_hashes, equal_hashes.mutation_indices) |*hash, index| {
        if (index != no_mutation) hash.* = shared_hash;
    }
    for ([_][2]usize{ .{ 0, 4 }, .{ 1, 3 }, .{ 2, 5 } }) |pair| {
        try std.testing.expectEqual(@as(?usize, pair[1]), equal_hashes.latestIndexFor(&changes, shared_hash, colliding_entries[pair[0]].pathSlice()));
    }
    try std.testing.expectEqual(@as(?usize, null), equal_hashes.latestIndexFor(&changes, shared_hash, absent.pathSlice()));
}

test "latest mutation index covers the full log and its highest mutation index" {
    var changes: [workspace.MAX_WORKSPACE_ENTRY_MUTATIONS]workspace.EntryMutation = undefined;
    for (&changes, 0..) |*change, index| {
        var path_buffer: [48]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "documents/full-log-{d}.md", .{index});
        change.* = .{
            .generation = @intCast(index + 1),
            .entry = try workspace.Entry.init(path, object_store.ids.object(index + 1), object_store.ids.version(index + 1), .document),
        };
    }
    const unique = build(&changes);
    for (&changes, 0..) |_, index| try std.testing.expect(unique.isLatest(&changes, index));

    for (&changes) |*change| change.entry = changes[0].entry;
    const repeated = build(&changes);
    for (0..changes.len - 1) |index| try std.testing.expect(!repeated.isLatest(&changes, index));
    try std.testing.expect(repeated.isLatest(&changes, changes.len - 1));
    try std.testing.expectEqual(@as(?usize, changes.len - 1), repeated.latestIndexFor(&changes, changes[0].entry.pathHash(), changes[0].entry.pathSlice()));

    const empty = build(&.{});
    try std.testing.expectEqual(@as(?usize, null), empty.latestIndexFor(&.{}, changes[0].entry.pathHash(), changes[0].entry.pathSlice()));
}
