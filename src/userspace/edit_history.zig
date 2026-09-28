const std = @import("std");

pub const MAX_EDITS = 32;
pub const BYTE_CAPACITY = 1024;

const Edit = struct {
    revision: u64,
    position: u16,
    removed_length: u16,
    inserted_length: u16,
    cursor: u16,
    anchor: u16,

    fn byteLength(self: Edit) usize {
        return @as(usize, self.removed_length) + self.inserted_length;
    }
};

pub const Change = struct {
    position: usize,
    remove_length: usize,
    insert: []const u8,
    cursor: u16,
    anchor: u16,
};

// A task-private log of changed bytes, not full document snapshots. Oldest
// complete edits are retired under either budget. Revision identities survive
// eviction and branching so delayed save receipts cannot bless another edit.
pub const History = struct {
    edits: [MAX_EDITS]Edit = [_]Edit{std.mem.zeroes(Edit)} ** MAX_EDITS,
    bytes: [BYTE_CAPACITY]u8 = [_]u8{0} ** BYTE_CAPACITY,
    base_revision: u64 = 0,
    next_revision: u64 = 1,
    saved_revision: ?u64 = 0,
    byte_length: u16 = 0,
    length: u8 = 0,
    index: u8 = 0,
    join_typing: bool = false,
    saved_feedback: bool = false,

    pub fn revision(self: *const History) ?u64 {
        if (self.next_revision == std.math.maxInt(u64)) return null;
        return if (self.index == 0) self.base_revision else self.edits[self.index - 1].revision;
    }

    pub fn isSaved(self: *const History) bool {
        const current = self.revision() orelse return false;
        return self.saved_revision != null and self.saved_revision.? == current;
    }

    pub fn markSaved(self: *History, saved_revision: ?u64) void {
        self.saved_revision = saved_revision;
        self.saved_feedback = true;
    }

    pub fn breakGroup(self: *History) void {
        self.join_typing = false;
    }

    pub fn remember(self: *History, position: u16, removed: []const u8, inserted: []const u8, cursor: u16, anchor: u16, typing: bool) void {
        std.debug.assert(removed.len + inserted.len <= BYTE_CAPACITY);
        if (self.next_revision == std.math.maxInt(u64)) {
            @memset(&self.bytes, 0);
            self.byte_length = 0;
            self.length = 0;
            self.index = 0;
            self.saved_revision = null;
            self.breakGroup();
            return;
        }
        const retained = self.offset(self.index);
        @memset(self.bytes[retained..self.byte_length], 0);
        self.byte_length = @intCast(retained);
        self.length = self.index;
        if (typing and self.join_typing and removed.len == 0 and self.length != 0) {
            const previous = &self.edits[self.length - 1];
            if (previous.removed_length == 0 and position == previous.position + previous.inserted_length and
                self.saved_revision != previous.revision and self.byte_length + inserted.len <= BYTE_CAPACITY)
            {
                @memcpy(self.bytes[self.byte_length..][0..inserted.len], inserted);
                self.byte_length += @intCast(inserted.len);
                previous.inserted_length += @intCast(inserted.len);
                previous.revision = self.next_revision;
                self.next_revision += 1;
                return;
            }
        }
        while (self.length == MAX_EDITS or self.byte_length + removed.len + inserted.len > BYTE_CAPACITY) self.retireOldest();
        @memcpy(self.bytes[self.byte_length..][0..removed.len], removed);
        @memcpy(self.bytes[self.byte_length + removed.len ..][0..inserted.len], inserted);
        self.byte_length += @intCast(removed.len + inserted.len);
        self.edits[self.length] = .{
            .revision = self.next_revision,
            .position = position,
            .removed_length = @intCast(removed.len),
            .inserted_length = @intCast(inserted.len),
            .cursor = cursor,
            .anchor = anchor,
        };
        self.next_revision += 1;
        self.length += 1;
        self.index = self.length;
        self.join_typing = typing and removed.len == 0;
    }

    pub fn undo(self: *History) ?Change {
        self.breakGroup();
        if (self.index == 0) return null;
        self.index -= 1;
        const edit = self.edits[self.index];
        return .{
            .position = edit.position,
            .remove_length = edit.inserted_length,
            .insert = self.bytes[self.offset(self.index)..][0..edit.removed_length],
            .cursor = edit.cursor,
            .anchor = edit.anchor,
        };
    }

    pub fn redo(self: *History) ?Change {
        self.breakGroup();
        if (self.index == self.length) return null;
        const edit = self.edits[self.index];
        const payload_offset = self.offset(self.index) + edit.removed_length;
        self.index += 1;
        return .{
            .position = edit.position,
            .remove_length = edit.removed_length,
            .insert = self.bytes[payload_offset..][0..edit.inserted_length],
            .cursor = edit.position + edit.inserted_length,
            .anchor = edit.position + edit.inserted_length,
        };
    }

    fn offset(self: *const History, index: usize) usize {
        var result: usize = 0;
        for (self.edits[0..index]) |edit| result += edit.byteLength();
        return result;
    }

    fn retireOldest(self: *History) void {
        const old = self.edits[0];
        const retired = old.byteLength();
        const remaining = self.byte_length - retired;
        std.mem.copyForwards(u8, self.bytes[0..remaining], self.bytes[retired..self.byte_length]);
        @memset(self.bytes[remaining..self.byte_length], 0);
        self.byte_length = @intCast(remaining);
        self.base_revision = old.revision;
        self.length -= 1;
        self.index -= 1;
        std.mem.copyForwards(Edit, self.edits[0..self.length], self.edits[1..][0..self.length]);
    }
};

comptime {
    if (@sizeOf(History) > 1920) @compileError("edit history exceeds its task-local budget");
}

test "edit history evicts complete records under both budgets and never reuses branch revisions" {
    var history = History{};
    for (0..MAX_EDITS + 8) |index| history.remember(@intCast(index), "", "x", @intCast(index), @intCast(index), false);
    try std.testing.expectEqual(MAX_EDITS, history.length);
    for (0..MAX_EDITS) |_| try std.testing.expect(history.undo() != null);
    try std.testing.expect(history.undo() == null);
    try std.testing.expectEqual(@as(?u64, 8), history.revision());
    try std.testing.expect(!history.isSaved());
    _ = history.redo();
    const discarded_revision = history.edits[history.index].revision;
    history.remember(9, "", "z", 9, 9, false);
    history.markSaved(discarded_revision);
    try std.testing.expect(!history.isSaved());
    try std.testing.expect(history.redo() == null);
    try std.testing.expect(std.mem.allEqual(u8, history.bytes[history.byte_length..], 0));

    history = .{};
    const full_a = [_]u8{'a'} ** 512;
    const full_b = [_]u8{'b'} ** 512;
    history.remember(0, &full_a, &full_b, 512, 0, false);
    history.remember(0, &full_b, "c", 512, 0, false);
    try std.testing.expectEqual(@as(u8, 1), history.length);
    const change = history.undo().?;
    try std.testing.expectEqualStrings(&full_b, change.insert);
    try std.testing.expectEqual(@as(usize, 1), change.remove_length);
    try std.testing.expect(history.undo() == null);
    try std.testing.expectEqualStrings("c", history.redo().?.insert);
    try std.testing.expect(std.mem.allEqual(u8, history.bytes[history.byte_length..], 0));
}

test "edit history stops issuing save identities at revision exhaustion" {
    var history = History{ .next_revision = std.math.maxInt(u64) - 1 };
    history.remember(0, "", "a", 0, 0, false);
    try std.testing.expect(history.revision() == null);
    history.remember(1, "", "b", 1, 1, false);
    history.markSaved(null);
    try std.testing.expect(!history.isSaved());
    try std.testing.expect(history.undo() == null);
    try std.testing.expect(history.redo() == null);
    try std.testing.expect(std.mem.allEqual(u8, &history.bytes, 0));
}
