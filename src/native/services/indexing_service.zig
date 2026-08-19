const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const copyTextExact = native_util.copyTextExact;

pub const MAX_DOCUMENTS: usize = 32;
pub const MAX_RESULTS: usize = 8;
pub const MAX_TITLE_BYTES: usize = 64;
pub const MAX_BODY_BYTES: usize = 192;
pub const BOUNDED_DOCUMENT_SCAN = true;
pub const DENSE_DOCUMENT_TABLE = true;
pub const COMPACT_DOCUMENT_METADATA = true;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 9_232;

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

    title: []const u8,

    pub fn titleSlice(self: *const SearchResult) []const u8 {
        return self.title;
    }
};

pub const Error = error{
    BodyTooLong,
    DocumentTableFull,
    PolicyDenied,
    TitleTooLong,
};

pub const DocumentRecord = struct {
    workspace_id: u64 = 0,
    object_id: u64 = 0,
    version_id: u64 = 0,
    title_len: u8 = 0,
    title: [MAX_TITLE_BYTES]u8 = [_]u8{0} ** MAX_TITLE_BYTES,
    body_len: u8 = 0,
    body: [MAX_BODY_BYTES]u8 = [_]u8{0} ** MAX_BODY_BYTES,
    sensitivity: manifest.DataSensitivity = .internal_data,

    pub fn titleSlice(self: *const DocumentRecord) []const u8 {
        return self.title[0..@as(usize, self.title_len)];
    }

    pub fn bodySlice(self: *const DocumentRecord) []const u8 {
        return self.body[0..@as(usize, self.body_len)];
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

pub const Service = struct {
    generation: u64 = 1,
    documents: [MAX_DOCUMENTS]DocumentRecord = [_]DocumentRecord{.{}} ** MAX_DOCUMENTS,
    document_count: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("indexing service exceeds its fixed-state size ceiling");
        }
    }

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
        if (self.findSlot(workspace_id, object_id)) |existing| {
            existing.* = record;
            self.bumpGeneration();
            return;
        }

        const slot_index = self.documentCount();
        if (slot_index >= MAX_DOCUMENTS) return error.DocumentTableFull;
        self.documents[slot_index] = record;
        self.document_count += 1;
        self.bumpGeneration();
    }

    pub fn remove(self: *Service, workspace_id: u64, object_id: u64) bool {
        const slot_index = self.documentSlotIndex(workspace_id, object_id) orelse return false;
        const last_slot_index = self.documentCount() - 1;
        self.documents[slot_index] = self.documents[last_slot_index];
        self.documents[last_slot_index] = .{};
        self.document_count -= 1;
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
        if (needle.len > MAX_BODY_BYTES) return output[0..0];

        var folded_needle_buffer: [MAX_BODY_BYTES]u8 = undefined;
        for (needle, 0..) |byte, index| {
            folded_needle_buffer[index] = std.ascii.toLower(byte);
        }
        const folded_needle = folded_needle_buffer[0..needle.len];

        const snapshot_generation = self.generation;
        var count: usize = 0;
        for (self.documents[0..self.documentCount()]) |*record| {
            if (!workspacePermitted(permitted_workspaces, record.workspace_id)) continue;
            const candidate = scoreDocument(record, folded_needle, snapshot_generation) orelse continue;
            retainRankedResult(output, &count, candidate);
        }

        std.sort.insertion(SearchResult, output[0..count], {}, compareResults);
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
        for (self.documents[0..self.documentCount()]) |*record| {
            if (!workspacePermitted(permitted_workspaces, record.workspace_id)) continue;
            result = maxSensitivity(result, record.sensitivity);
        }
        return result;
    }

    pub fn documentCount(self: *const Service) usize {
        return @intCast(self.document_count);
    }

    fn findSlot(self: *Service, workspace_id: u64, object_id: u64) ?*DocumentRecord {
        const slot_index = self.documentSlotIndex(workspace_id, object_id) orelse return null;
        return &self.documents[slot_index];
    }

    fn documentSlotIndex(self: *const Service, workspace_id: u64, object_id: u64) ?usize {
        for (self.documents[0..self.documentCount()], 0..) |record, slot_index| {
            if (record.workspace_id == workspace_id and record.object_id == object_id) return slot_index;
        }
        return null;
    }

    fn workspaceDocumentCount(self: *const Service, workspace_id: u64) usize {
        var count: usize = 0;
        for (self.documents[0..self.documentCount()]) |record| {
            if (record.workspace_id == workspace_id) count += 1;
        }
        return count;
    }

    fn bumpGeneration(self: *Service) void {
        self.generation +|= 1;
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

fn scoreDocument(record: *const DocumentRecord, folded_needle: []const u8, generation: u64) ?SearchResult {
    comptime std.debug.assert(MAX_TITLE_BYTES * 4 + MAX_BODY_BYTES <= std.math.maxInt(u16));
    const title_hits = countOccurrencesFolded(record.titleSlice(), folded_needle);
    const body_hits = countOccurrencesFolded(record.bodySlice(), folded_needle);
    const score = title_hits * 4 + body_hits;
    if (score == 0) return null;

    return .{
        .workspace_id = record.workspace_id,
        .object_id = record.object_id,
        .version_id = record.version_id,
        .index_generation = generation,
        .score = @intCast(score),
        .title_hits = @intCast(title_hits),
        .body_hits = @intCast(body_hits),
        .sensitivity = record.sensitivity,
        .title_fingerprint = hashTitle(record.titleSlice()),
        .title = record.titleSlice(),
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

fn workspacePermitted(permitted_workspaces: []const u64, workspace_id: u64) bool {
    for (permitted_workspaces) |permitted| {
        if (permitted == workspace_id) return true;
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
    var record = DocumentRecord{};
    record.workspace_id = workspace_id;
    record.object_id = object_id;
    record.version_id = version_id;
    record.title_len = @intCast(copyTextExact(&record.title, title) catch return error.TitleTooLong);
    record.body_len = @intCast(copyTextExact(&record.body, body) catch return error.BodyTooLong);
    record.sensitivity = sensitivity;
    return record;
}

fn countOccurrencesFolded(haystack: []const u8, folded_needle: []const u8) usize {
    if (folded_needle.len == 0 or haystack.len < folded_needle.len) return 0;

    var count: usize = 0;
    var index: usize = 0;
    while (index + folded_needle.len <= haystack.len) : (index += 1) {
        var matches = true;
        for (folded_needle, 0..) |byte, offset| {
            if (std.ascii.toLower(haystack[index + offset]) != byte) {
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
        result.title = "";
    }
}

fn hashTitle(title: []const u8) u64 {
    const fingerprint = std.hash.Wyhash.hash(0x7365_6d61_6e74_6963, title);
    return if (fingerprint == 0) 1 else fingerprint;
}

test "indexing service remains permission aware and updates ranked results" {
    var service = Service.init();
    try service.upsert(1, 100, 1, "Alpha Notes", "alpha alpha roadmap");
    try service.upsert(1, 101, 2, "Quarterly Report", "finance alpha summary");
    try service.upsert(2, 200, 1, "Private Contract", "alpha restricted");
    try std.testing.expectEqual(@as(u64, 4), service.generation);
    try std.testing.expectEqual(@as(usize, 3), service.documentCount());
    try std.testing.expectEqual(@as(usize, 2), service.workspaceDocumentCount(1));
    try std.testing.expectEqual(@as(usize, 1), service.workspaceDocumentCount(2));

    var results_buffer: [MAX_RESULTS]SearchResult = undefined;
    const workspace_one = [_]u64{1};
    const results = service.query(&workspace_one, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqual(@as(u64, 100), results[0].object_id);
    try std.testing.expectEqual(service.generation, results[0].index_generation);
    try std.testing.expectEqualStrings("Alpha Notes", results[0].titleSlice());
    try std.testing.expect(results[0].title_fingerprint != 0);
    try std.testing.expectEqual(@as(u64, 101), results[1].object_id);
    const mixed_case_results = service.query(&workspace_one, "AlPhA", &results_buffer);
    try std.testing.expectEqual(@as(usize, 2), mixed_case_results.len);
    try std.testing.expectEqual(@as(u64, 100), mixed_case_results[0].object_id);
    const oversized_query = [_]u8{'a'} ** (MAX_BODY_BYTES + 1);
    try std.testing.expectEqual(@as(usize, 0), service.query(&workspace_one, &oversized_query, &results_buffer).len);
    const duplicate_workspace_scope = [_]u64{ 1, 1 };
    const deduped_results = service.query(&duplicate_workspace_scope, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 2), deduped_results.len);

    try std.testing.expect(service.remove(1, 100));
    try std.testing.expectEqual(@as(u64, 5), service.generation);
    try std.testing.expectEqual(@as(usize, 2), service.documentCount());
    try std.testing.expectEqual(@as(usize, 1), service.workspaceDocumentCount(1));
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
    try std.testing.expectEqual(@as(usize, 0), service.documentCount());
    try std.testing.expectEqual(@as(u64, 1), service.generation);

    try service.upsert(1, 100, 1, "Original", "body");
    try std.testing.expectEqual(@as(u64, 2), service.generation);

    try std.testing.expectError(error.BodyTooLong, service.upsert(1, 100, 2, "Updated", oversized_body[0..]));
    const record = service.findSlot(1, 100).?;
    try std.testing.expectEqual(@as(u64, 1), record.version_id);
    try std.testing.expectEqualStrings("Original", record.titleSlice());
    try std.testing.expectEqualStrings("body", record.bodySlice());
    try std.testing.expectEqual(@as(u64, 2), service.generation);
}

test "indexing service compacts removals and refills its bounded table" {
    var service = Service.init();
    for (0..MAX_DOCUMENTS) |index| {
        try service.upsert(
            @intCast(1 + index % 2),
            @intCast(100 + index),
            1,
            "bounded document",
            "searchable body",
        );
    }
    try std.testing.expectEqual(MAX_DOCUMENTS, service.documentCount());

    const generation_before_full = service.generation;
    try std.testing.expectError(error.DocumentTableFull, service.upsert(3, 999, 1, "overflow", "searchable overflow"));
    try std.testing.expectEqual(generation_before_full, service.generation);

    const retired_slot_index = service.documentSlotIndex(2, 105).?;
    const last_object_id = service.documents[MAX_DOCUMENTS - 1].object_id;
    try std.testing.expect(service.remove(2, 105));
    try std.testing.expectEqual(MAX_DOCUMENTS - 1, service.documentCount());
    try std.testing.expectEqual(last_object_id, service.documents[retired_slot_index].object_id);
    try std.testing.expectEqual(@as(u64, 0), service.documents[MAX_DOCUMENTS - 1].object_id);

    try service.upsert(3, 999, 2, "replacement", "searchable replacement");
    try std.testing.expectEqual(MAX_DOCUMENTS, service.documentCount());
    try std.testing.expectEqual(MAX_DOCUMENTS - 1, service.documentSlotIndex(3, 999).?);
    try std.testing.expect(!service.remove(2, 105));
}

test "borrowed result titles follow document lifetime boundaries" {
    var service = Service.init();
    try service.upsert(1, 100, 1, "Alpha Notes", "alpha roadmap");

    const workspace_one = [_]u64{1};
    const source_slot_index = service.documentSlotIndex(1, 100).?;
    var results_buffer: [MAX_RESULTS]SearchResult = undefined;

    {
        const results = service.query(&workspace_one, "alpha", &results_buffer);
        const source = &service.documents[source_slot_index];
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expect(results[0].title.ptr == source.titleSlice().ptr);
        try std.testing.expectEqualStrings("Alpha Notes", results[0].titleSlice());
    }

    try service.upsert(2, 200, 1, "Other Notes", "alpha reference");
    try std.testing.expectEqual(source_slot_index, service.documentSlotIndex(1, 100).?);
    {
        const results = service.query(&workspace_one, "alpha", &results_buffer);
        const source = &service.documents[source_slot_index];
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expect(results[0].title.ptr == source.titleSlice().ptr);
    }

    const generation_before_update = service.generation;
    try service.upsert(1, 100, 2, "Updated Notes", "updated alpha roadmap");
    try std.testing.expect(service.generation > generation_before_update);
    {
        const results = service.query(&workspace_one, "alpha", &results_buffer);
        const source = &service.documents[source_slot_index];
        try std.testing.expectEqual(@as(usize, 1), results.len);
        try std.testing.expectEqual(@as(u64, 2), results[0].version_id);
        try std.testing.expect(results[0].title.ptr == source.titleSlice().ptr);
        try std.testing.expectEqualStrings("Updated Notes", results[0].titleSlice());
    }

    const generation_before_remove = service.generation;
    try std.testing.expect(service.remove(1, 100));
    try std.testing.expect(service.generation > generation_before_remove);
    try std.testing.expectEqual(@as(usize, 0), service.query(&workspace_one, "alpha", &results_buffer).len);
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
