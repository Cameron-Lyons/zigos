const std = @import("std");

pub const MAX_DOCUMENTS: usize = 32;
pub const MAX_RESULTS: usize = 8;
pub const MAX_TITLE_BYTES: usize = 64;
pub const MAX_BODY_BYTES: usize = 192;

pub const SearchResult = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    score: u16,
    title_len: usize,
    title: [MAX_TITLE_BYTES]u8,

    pub fn titleSlice(self: *const SearchResult) []const u8 {
        return self.title[0..self.title_len];
    }
};

pub const Error = error{
    DocumentTableFull,
};

pub const DocumentRecord = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    title_len: usize,
    title: [MAX_TITLE_BYTES]u8,
    body_len: usize,
    body: [MAX_BODY_BYTES]u8,

    pub fn titleSlice(self: *const DocumentRecord) []const u8 {
        return self.title[0..self.title_len];
    }

    pub fn bodySlice(self: *const DocumentRecord) []const u8 {
        return self.body[0..self.body_len];
    }
};

const DocumentSlot = struct {
    in_use: bool = false,
    record: DocumentRecord = zeroDocument(),
};

pub const Service = struct {
    documents: [MAX_DOCUMENTS]DocumentSlot = [_]DocumentSlot{DocumentSlot{}} ** MAX_DOCUMENTS,

    pub fn init() Service {
        return .{};
    }

    pub fn upsert(
        self: *Service,
        workspace_id: u64,
        object_id: u64,
        version_id: u64,
        title: []const u8,
        body: []const u8,
    ) Error!void {
        if (self.findSlot(workspace_id, object_id)) |slot| {
            slot.record.version_id = version_id;
            slot.record.title_len = copyText(&slot.record.title, title);
            slot.record.body_len = copyText(&slot.record.body, body);
            return;
        }

        for (&self.documents) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.record = zeroDocument();
            slot.record.workspace_id = workspace_id;
            slot.record.object_id = object_id;
            slot.record.version_id = version_id;
            slot.record.title_len = copyText(&slot.record.title, title);
            slot.record.body_len = copyText(&slot.record.body, body);
            return;
        }
        return error.DocumentTableFull;
    }

    pub fn remove(self: *Service, workspace_id: u64, object_id: u64) bool {
        const slot = self.findSlot(workspace_id, object_id) orelse return false;
        slot.* = .{};
        return true;
    }

    pub fn query(
        self: *const Service,
        permitted_workspaces: []const u64,
        needle: []const u8,
        output: *[MAX_RESULTS]SearchResult,
    ) []const SearchResult {
        if (needle.len == 0) return output[0..0];

        var count: usize = 0;
        for (self.documents) |slot| {
            if (!slot.in_use) continue;
            if (!workspaceAllowed(permitted_workspaces, slot.record.workspace_id)) continue;

            const title_hits = countOccurrencesFold(slot.record.titleSlice(), needle);
            const body_hits = countOccurrencesFold(slot.record.bodySlice(), needle);
            const score = title_hits * 4 + body_hits;
            if (score == 0) continue;
            if (count >= output.len) continue;

            output[count] = .{
                .workspace_id = slot.record.workspace_id,
                .object_id = slot.record.object_id,
                .version_id = slot.record.version_id,
                .score = @intCast(score),
                .title_len = slot.record.title_len,
                .title = slot.record.title,
            };
            count += 1;
        }

        std.sort.heap(SearchResult, output[0..count], {}, compareResults);
        return output[0..count];
    }

    fn findSlot(self: *Service, workspace_id: u64, object_id: u64) ?*DocumentSlot {
        for (&self.documents) |*slot| {
            if (!slot.in_use) continue;
            if (slot.record.workspace_id == workspace_id and slot.record.object_id == object_id) return slot;
        }
        return null;
    }
};

fn compareResults(_: void, left: SearchResult, right: SearchResult) bool {
    if (left.score == right.score) return left.object_id < right.object_id;
    return left.score > right.score;
}

fn workspaceAllowed(permitted_workspaces: []const u64, workspace_id: u64) bool {
    for (permitted_workspaces) |allowed| {
        if (allowed == workspace_id) return true;
    }
    return false;
}

fn countOccurrencesFold(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0 or haystack.len < needle.len) return 0;

    var count: usize = 0;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matches = true;
        for (needle, 0..) |byte, offset| {
            if (std.ascii.toLower(haystack[index + offset]) != std.ascii.toLower(byte)) {
                matches = false;
                break;
            }
        }
        if (matches) count += 1;
    }
    return count;
}

fn zeroDocument() DocumentRecord {
    return .{
        .workspace_id = 0,
        .object_id = 0,
        .version_id = 0,
        .title_len = 0,
        .title = [_]u8{0} ** MAX_TITLE_BYTES,
        .body_len = 0,
        .body = [_]u8{0} ** MAX_BODY_BYTES,
    };
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

test "indexing service remains permission aware and updates ranked results" {
    var service = Service.init();
    try service.upsert(1, 100, 1, "Alpha Notes", "alpha alpha roadmap");
    try service.upsert(1, 101, 2, "Quarterly Report", "finance alpha summary");
    try service.upsert(2, 200, 1, "Private Contract", "alpha restricted");

    var results_buffer: [MAX_RESULTS]SearchResult = undefined;
    const workspace_one = [_]u64{1};
    const results = service.query(&workspace_one, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqual(@as(u64, 100), results[0].object_id);
    try std.testing.expectEqualStrings("Alpha Notes", results[0].titleSlice());
    try std.testing.expectEqual(@as(u64, 101), results[1].object_id);

    try std.testing.expect(service.remove(1, 100));
    const updated = service.query(&workspace_one, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 1), updated.len);
    try std.testing.expectEqual(@as(u64, 101), updated[0].object_id);
    try std.testing.expectEqual(@as(u64, 2), updated[0].version_id);
}
