const std = @import("std");
const native_util = @import("../../core/util.zig");
const object_store = @import("../../storage/object_store.zig");
const workspace = @import("../../storage/workspace.zig");

pub const capacity: usize = workspace.MAX_WORKSPACE_ENTRY_MUTATIONS * 2;
pub const MutationIndex = u8;
pub const COMPACT_MUTATION_INDEX_METADATA = true;
pub const SLOT_SIZE_CEILING_BYTES: usize = 16;
pub const INDEX_SIZE_CEILING_BYTES: usize = capacity * SLOT_SIZE_CEILING_BYTES;

comptime {
    if (workspace.MAX_WORKSPACE_ENTRY_MUTATIONS > std.math.maxInt(MutationIndex)) {
        @compileError("latest mutation indexes cannot represent the workspace mutation capacity");
    }
}

const Slot = struct {
    in_use: bool = false,
    path_hash: u64 = 0,
    mutation_index: MutationIndex = 0,
};

pub const Index = struct {
    slots: [capacity]Slot = [_]Slot{Slot{}} ** capacity,

    pub fn put(self: *Index, changes: []const workspace.EntryMutation, mutation_index: usize) void {
        const entry = &changes[mutation_index].entry;
        const path_hash = entry.pathHash();
        const path = entry.pathSlice();
        var slot_index = slotStart(path_hash);
        var probes: usize = 0;
        while (probes < self.slots.len) : ({
            probes += 1;
            slot_index = (slot_index + 1) % self.slots.len;
        }) {
            const slot = &self.slots[slot_index];
            if (!slot.in_use) {
                slot.* = .{
                    .in_use = true,
                    .path_hash = path_hash,
                    .mutation_index = @intCast(mutation_index),
                };
                return;
            }
            if (slot.path_hash == path_hash and std.mem.eql(u8, changes[slot.mutation_index].entry.pathSlice(), path)) {
                slot.mutation_index = @intCast(mutation_index);
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
        while (probes < self.slots.len) : ({
            probes += 1;
            slot_index = (slot_index + 1) % self.slots.len;
        }) {
            const slot = &self.slots[slot_index];
            if (!slot.in_use) return null;
            if (slot.path_hash == path_hash and std.mem.eql(u8, changes[slot.mutation_index].entry.pathSlice(), path)) {
                return slot.mutation_index;
            }
        }
        return null;
    }

    pub fn isLatest(self: *const Index, changes: []const workspace.EntryMutation, mutation_index: usize) bool {
        const entry = &changes[mutation_index].entry;
        return self.latestIndexFor(changes, entry.pathHash(), entry.pathSlice()) == mutation_index;
    }
};

comptime {
    if (@sizeOf(Slot) > SLOT_SIZE_CEILING_BYTES or @sizeOf(Index) > INDEX_SIZE_CEILING_BYTES) {
        @compileError("latest mutation index exceeds its compact size ceiling");
    }
}

pub fn build(changes: []const workspace.EntryMutation) Index {
    var index = Index{};
    for (changes, 0..) |_, mutation_index| {
        index.put(changes, mutation_index);
    }
    return index;
}

fn slotStart(path_hash: u64) usize {
    return @intCast(path_hash % capacity);
}

test "latest mutation index uses capacity-sized slot metadata" {
    try std.testing.expect(COMPACT_MUTATION_INDEX_METADATA);
    try std.testing.expectEqual(MutationIndex, @FieldType(Slot, "mutation_index"));
    try std.testing.expect(@sizeOf(Slot) <= SLOT_SIZE_CEILING_BYTES);
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
