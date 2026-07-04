const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const copyTextExact = native_util.copyTextExact;

pub const MAX_DOCUMENTS: usize = 32;
pub const MAX_RESULTS: usize = 8;
pub const MAX_TITLE_BYTES: usize = 64;
pub const MAX_BODY_BYTES: usize = 192;

pub const SearchResult = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    index_generation: u64 = 0,
    score: u16,
    title_hits: u16 = 0,
    body_hits: u16 = 0,
    sensitivity: manifest.DataSensitivity = .internal_data,
    title_fingerprint: u64 = 0,
    title_len: usize,
    title: [MAX_TITLE_BYTES]u8,

    pub fn titleSlice(self: *const SearchResult) []const u8 {
        return self.title[0..self.title_len];
    }
};

pub const Error = error{
    BodyTooLong,
    DocumentTableFull,
    PolicyDenied,
    TitleTooLong,
};

pub const DocumentRecord = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    title_len: usize,
    title: [MAX_TITLE_BYTES]u8,
    body_len: usize,
    body: [MAX_BODY_BYTES]u8,
    sensitivity: manifest.DataSensitivity = .internal_data,

    pub fn titleSlice(self: *const DocumentRecord) []const u8 {
        return self.title[0..self.title_len];
    }

    pub fn bodySlice(self: *const DocumentRecord) []const u8 {
        return self.body[0..self.body_len];
    }
};

pub const SemanticQueryRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    permitted_workspaces: []const u64,
    query: []const u8,
    local_model: bool = false,
    encrypted_index: bool = false,
    redacted_snippets: bool = false,
    now_ticks: u64,
    detail: []const u8 = "",
};

const DocumentSlot = struct {
    in_use: bool = false,
    record: DocumentRecord = zeroDocument(),
};

const DocumentArena = indexed_arena.IndexedArenaWithKey(u64, DocumentSlot, MAX_DOCUMENTS, MAX_DOCUMENTS * 2, documentSlotKey);
const DocumentWorkspaceIndex = indexed_arena.MultimapIndex(MAX_DOCUMENTS, MAX_DOCUMENTS, MAX_DOCUMENTS * 2);

pub const Service = struct {
    generation: u64 = 1,
    documents: DocumentArena = DocumentArena.init(),
    workspace_index: DocumentWorkspaceIndex = DocumentWorkspaceIndex.init(),

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
        return self.upsertClassified(workspace_id, object_id, version_id, title, body, .internal_data);
    }

    pub fn upsertClassified(
        self: *Service,
        workspace_id: u64,
        object_id: u64,
        version_id: u64,
        title: []const u8,
        body: []const u8,
        sensitivity: manifest.DataSensitivity,
    ) Error!void {
        const record = try makeDocument(workspace_id, object_id, version_id, title, body, sensitivity);
        if (self.findSlot(workspace_id, object_id)) |slot| {
            slot.record = record;
            self.bumpGeneration();
            return;
        }

        const key = documentKey(workspace_id, object_id);
        const slot_index = self.documents.reserveIndex(key) orelse return error.DocumentTableFull;
        if (!self.workspace_index.append(workspace_id, slot_index)) {
            _ = self.documents.removeIndex(slot_index);
            return error.DocumentTableFull;
        }
        const slot = &self.documents.slots[slot_index];
        slot.record = record;
        self.bumpGeneration();
    }

    pub fn remove(self: *Service, workspace_id: u64, object_id: u64) bool {
        const key = documentKey(workspace_id, object_id);
        const slot_index = self.documents.slotIndexOf(key) orelse return false;
        const slot = &self.documents.slots[slot_index];
        if (slot.record.workspace_id != workspace_id or slot.record.object_id != object_id) {
            native_util.impossibleByInvariant("indexing service document key points at the wrong document");
        }
        _ = self.workspace_index.remove(workspace_id, slot_index);
        if (!self.documents.removeIndex(slot_index)) {
            native_util.impossibleByInvariant("indexed document slot disappeared during removal");
        }
        self.bumpGeneration();
        return true;
    }

    pub fn query(
        self: *const Service,
        permitted_workspaces: []const u64,
        needle: []const u8,
        output: *[MAX_RESULTS]SearchResult,
    ) []const SearchResult {
        if (needle.len == 0) return output[0..0];

        const snapshot_generation = self.generation;
        var count: usize = 0;
        for (permitted_workspaces, 0..) |workspace_id, workspace_scope_index| {
            if (workspaceAlreadyVisited(permitted_workspaces[0..workspace_scope_index], workspace_id)) continue;
            var slot_index = self.workspace_index.head(workspace_id);
            while (slot_index != indexed_arena.no_index) : (slot_index = self.workspace_index.next(slot_index)) {
                const slot = self.documentSlotForWorkspaceIndex(workspace_id, slot_index);
                const candidate = scoreDocument(&slot.record, needle, snapshot_generation) orelse continue;
                retainRankedResult(output, &count, candidate);
            }
        }

        std.sort.heap(SearchResult, output[0..count], {}, compareResults);
        return output[0..count];
    }

    pub fn semanticQuery(
        self: *const Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: SemanticQueryRequest,
        output: *[MAX_RESULTS]SearchResult,
        ledger: ?*event_ledger.Ledger,
    ) (Error || event_ledger.Error)![]const SearchResult {
        if (request.query.len == 0) return output[0..0];
        const sensitivity = self.permittedWorkspaceSensitivity(request.permitted_workspaces);
        const decision = policies.semanticMemoryDecision(subjects, .{
            .sensitivity = sensitivity,
            .query_bytes = request.query.len,
            .local_model = request.local_model,
            .encrypted_index = request.encrypted_index,
            .redacted_snippets = request.redacted_snippets,
        });
        if (!decision.allowed) {
            try recordSemanticQuery(ledger, request, false);
            return error.PolicyDenied;
        }
        try recordSemanticQuery(ledger, request, true);
        const result_count = self.query(request.permitted_workspaces, request.query, output).len;
        const results = output[0..result_count];
        if (request.redacted_snippets) redactResultTitles(results);
        return results;
    }

    pub fn permittedWorkspaceSensitivity(self: *const Service, permitted_workspaces: []const u64) manifest.DataSensitivity {
        var result: manifest.DataSensitivity = .public_data;
        for (permitted_workspaces, 0..) |workspace_id, workspace_scope_index| {
            if (workspaceAlreadyVisited(permitted_workspaces[0..workspace_scope_index], workspace_id)) continue;
            var slot_index = self.workspace_index.head(workspace_id);
            while (slot_index != indexed_arena.no_index) : (slot_index = self.workspace_index.next(slot_index)) {
                const slot = self.documentSlotForWorkspaceIndex(workspace_id, slot_index);
                result = maxSensitivity(result, slot.record.sensitivity);
            }
        }
        return result;
    }

    fn findSlot(self: *Service, workspace_id: u64, object_id: u64) ?*DocumentSlot {
        const slot = self.documents.get(documentKey(workspace_id, object_id)) orelse return null;
        if (slot.record.workspace_id != workspace_id or slot.record.object_id != object_id) {
            native_util.impossibleByInvariant("indexing service document index points at the wrong document");
        }
        return slot;
    }

    fn bumpGeneration(self: *Service) void {
        self.generation +|= 1;
    }

    fn documentSlotForWorkspaceIndex(self: *const Service, workspace_id: u64, slot_index: usize) *const DocumentSlot {
        if (slot_index >= self.documents.slots.len) {
            native_util.impossibleByInvariant("indexing service workspace index points outside document slots");
        }
        const slot = &self.documents.slots[slot_index];
        if (!slot.in_use) {
            native_util.impossibleByInvariant("indexing service workspace index points at a free document slot");
        }
        if (slot.record.workspace_id != workspace_id) {
            native_util.impossibleByInvariant("indexing service workspace index points at the wrong workspace");
        }
        return slot;
    }
};

fn recordSemanticQuery(
    ledger: ?*event_ledger.Ledger,
    request: SemanticQueryRequest,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSemanticMemory(
            request.subject,
            request.task_id,
            allowed,
            request.local_model,
            request.encrypted_index,
            request.redacted_snippets,
            request.query.len,
            request.now_ticks,
            request.detail,
        );
    }
}

fn documentSlotKey(slot: *const DocumentSlot) u64 {
    return documentKey(slot.record.workspace_id, slot.record.object_id);
}

fn documentKey(workspace_id: u64, object_id: u64) u64 {
    const DOCUMENT_KEY_BYTES: usize = 16;
    var bytes: [DOCUMENT_KEY_BYTES]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], workspace_id, .little);
    std.mem.writeInt(u64, bytes[8..16], object_id, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(hash_seeds.document_index_key, &bytes));
}

fn compareResults(_: void, left: SearchResult, right: SearchResult) bool {
    if (left.score == right.score) return left.object_id < right.object_id;
    return left.score > right.score;
}

fn worstResultIndex(results: []const SearchResult) usize {
    var worst_index: usize = 0;
    for (results[1..], 1..) |result, index| {
        if (compareResults({}, results[worst_index], result)) worst_index = index;
    }
    return worst_index;
}

fn scoreDocument(record: *const DocumentRecord, needle: []const u8, generation: u64) ?SearchResult {
    const title_hits = countOccurrencesFold(record.titleSlice(), needle);
    const body_hits = countOccurrencesFold(record.bodySlice(), needle);
    const score = title_hits * 4 + body_hits;
    if (score == 0) return null;

    return .{
        .workspace_id = record.workspace_id,
        .object_id = record.object_id,
        .version_id = record.version_id,
        .index_generation = generation,
        .score = @intCast(score),
        .title_hits = @intCast(@min(title_hits, std.math.maxInt(u16))),
        .body_hits = @intCast(@min(body_hits, std.math.maxInt(u16))),
        .sensitivity = record.sensitivity,
        .title_fingerprint = hashTitle(record.titleSlice()),
        .title_len = record.title_len,
        .title = record.title,
    };
}

fn retainRankedResult(output: *[MAX_RESULTS]SearchResult, count: *usize, candidate: SearchResult) void {
    if (count.* < output.len) {
        output[count.*] = candidate;
        count.* += 1;
        return;
    }

    const worst_index = worstResultIndex(output[0..count.*]);
    if (compareResults({}, candidate, output[worst_index])) {
        output[worst_index] = candidate;
    }
}

fn workspaceAlreadyVisited(previous_workspaces: []const u64, workspace_id: u64) bool {
    for (previous_workspaces) |visited| {
        if (visited == workspace_id) return true;
    }
    return false;
}

fn maxSensitivity(left: manifest.DataSensitivity, right: manifest.DataSensitivity) manifest.DataSensitivity {
    return if (@intFromEnum(right) > @intFromEnum(left)) right else left;
}

fn makeDocument(
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    title: []const u8,
    body: []const u8,
    sensitivity: manifest.DataSensitivity,
) Error!DocumentRecord {
    var record = zeroDocument();
    record.workspace_id = workspace_id;
    record.object_id = object_id;
    record.version_id = version_id;
    record.title_len = copyTextExact(&record.title, title) catch return error.TitleTooLong;
    record.body_len = copyTextExact(&record.body, body) catch return error.BodyTooLong;
    record.sensitivity = sensitivity;
    return record;
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

fn redactResultTitles(results: []SearchResult) void {
    for (results) |*result| {
        result.title_len = 0;
        result.title = [_]u8{0} ** MAX_TITLE_BYTES;
    }
}

fn hashTitle(title: []const u8) u64 {
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(0x7365_6d61_6e74_6963, title));
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
        .sensitivity = .internal_data,
    };
}

test "indexing service remains permission aware and updates ranked results" {
    var service = Service.init();
    try service.upsert(1, 100, 1, "Alpha Notes", "alpha alpha roadmap");
    try service.upsert(1, 101, 2, "Quarterly Report", "finance alpha summary");
    try service.upsert(2, 200, 1, "Private Contract", "alpha restricted");
    try std.testing.expectEqual(@as(u64, 4), service.generation);
    try std.testing.expectEqual(@as(usize, 3), service.documents.countInUse());
    try std.testing.expectEqual(@as(usize, 2), service.workspace_index.count(1));
    try std.testing.expectEqual(@as(usize, 1), service.workspace_index.count(2));

    var results_buffer: [MAX_RESULTS]SearchResult = undefined;
    const workspace_one = [_]u64{1};
    const results = service.query(&workspace_one, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqual(@as(u64, 100), results[0].object_id);
    try std.testing.expectEqual(service.generation, results[0].index_generation);
    try std.testing.expectEqualStrings("Alpha Notes", results[0].titleSlice());
    try std.testing.expect(results[0].title_fingerprint != 0);
    try std.testing.expectEqual(@as(u64, 101), results[1].object_id);
    const duplicate_workspace_scope = [_]u64{ 1, 1 };
    const deduped_results = service.query(&duplicate_workspace_scope, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 2), deduped_results.len);

    try std.testing.expect(service.remove(1, 100));
    try std.testing.expectEqual(@as(u64, 5), service.generation);
    try std.testing.expectEqual(@as(usize, 2), service.documents.countInUse());
    try std.testing.expectEqual(@as(usize, 1), service.workspace_index.count(1));
    const updated = service.query(&workspace_one, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 1), updated.len);
    try std.testing.expectEqual(@as(u64, 101), updated[0].object_id);
    try std.testing.expectEqual(@as(u64, 2), updated[0].version_id);
    try std.testing.expectEqual(service.generation, updated[0].index_generation);
}

test "indexing service rejects overlong document text without partial updates" {
    var service = Service.init();
    const oversized_title = [_]u8{'t'} ** (MAX_TITLE_BYTES + 1);
    const oversized_body = [_]u8{'b'} ** (MAX_BODY_BYTES + 1);

    try std.testing.expectError(error.TitleTooLong, service.upsert(1, 100, 1, oversized_title[0..], "body"));
    try std.testing.expectEqual(@as(usize, 0), service.documents.countInUse());
    try std.testing.expectEqual(@as(u64, 1), service.generation);

    try service.upsert(1, 100, 1, "Original", "body");
    try std.testing.expectEqual(@as(u64, 2), service.generation);

    try std.testing.expectError(error.BodyTooLong, service.upsert(1, 100, 2, "Updated", oversized_body[0..]));
    const slot = service.findSlot(1, 100).?;
    try std.testing.expectEqual(@as(u64, 1), slot.record.version_id);
    try std.testing.expectEqualStrings("Original", slot.record.titleSlice());
    try std.testing.expectEqualStrings("body", slot.record.bodySlice());
    try std.testing.expectEqual(@as(u64, 2), service.generation);
}

test "indexing service keeps highest ranked results after buffer fills" {
    var service = Service.init();
    for (0..MAX_RESULTS) |index| {
        try service.upsert(1, 100 + @as(u64, @intCast(index)), 1, "Low Match", "alpha");
    }
    try service.upsert(1, 999, 1, "Alpha Priority", "alpha alpha alpha");

    var results_buffer: [MAX_RESULTS]SearchResult = undefined;
    const workspace_one = [_]u64{1};
    const results = service.query(&workspace_one, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, MAX_RESULTS), results.len);
    try std.testing.expectEqual(@as(u64, 999), results[0].object_id);
    try std.testing.expectEqual(@as(u16, 7), results[0].score);
    for (results) |result| {
        try std.testing.expect(result.object_id != 107);
    }
}

test "semantic memory queries are local policy gated and redacted" {
    var service = Service.init();
    try service.upsertClassified(1, 100, 1, "Alpha Notes", "private semantic roadmap", .private_user_data);
    try service.upsertClassified(2, 200, 1, "Hidden Notes", "private semantic roadmap", .private_user_data);

    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .organization,
        .subject_id = 707,
        .issuer = .{ .kind = .policy_authority, .serial = 707 },
        .label = "semantic-memory",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, .{
        .label = "semantic-memory-policy",
        .seed = @import("../core/signing.zig").seedFromByte(0xE1),
    });

    var ledger = event_ledger.Ledger.init();
    var results_buffer: [MAX_RESULTS]SearchResult = undefined;
    const workspace_one = [_]u64{1};
    const allowed = try service.semanticQuery(&policies, .{ .organization_id = 707 }, .{
        .subject = .{ .kind = .app, .serial = 707 },
        .task_id = 708,
        .permitted_workspaces = &workspace_one,
        .query = "semantic",
        .local_model = true,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 10,
        .detail = "private semantic query text",
    }, &results_buffer, &ledger);
    try std.testing.expectEqual(@as(usize, 1), allowed.len);
    try std.testing.expectEqual(@as(u64, 100), allowed[0].object_id);
    try std.testing.expectEqual(service.generation, allowed[0].index_generation);
    try std.testing.expect(allowed[0].title_fingerprint != 0);
    try std.testing.expectEqual(@as(usize, 0), allowed[0].titleSlice().len);

    try std.testing.expectError(error.PolicyDenied, service.semanticQuery(&policies, .{ .organization_id = 707 }, .{
        .subject = .{ .kind = .app, .serial = 707 },
        .task_id = 708,
        .permitted_workspaces = &workspace_one,
        .query = "semantic",
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 11,
        .detail = "private remote semantic query",
    }, &results_buffer, &ledger));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), summary.semantic_memory_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.semantic_memory_remote_denials);
    var export_buffer: [1024]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private semantic query") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=semantic_memory") != null);
}
