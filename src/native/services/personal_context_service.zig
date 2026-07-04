const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const indexing_service = @import("indexing_service.zig");
const manifest = @import("../policy/manifest.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_CONTEXT_LEASES: usize = 16;

pub const Error = event_ledger.Error || indexing_service.Error || error{
    LeaseExpired,
    LeaseNotFound,
    LeasePrivacyMismatch,
    LeaseRevoked,
    LeaseSensitivityMismatch,
    LeaseTableFull,
    PolicyDenied,
    QueryBudgetExceeded,
    ReceiptIdExhausted,
    SourceMismatch,
    WorkspaceScopeMismatch,
};

pub const LeaseRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    workspace_id: u64,
    sensitivity: manifest.DataSensitivity = .private_user_data,
    max_query_bytes: usize,
    expires_at_ticks: u64,
    local_model: bool = true,
    encrypted_index: bool = true,
    redacted_snippets: bool = true,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const QueryRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    lease_id: u64,
    workspace_id: u64,
    query_bytes: usize,
    local_model: bool = true,
    encrypted_index: bool = true,
    redacted_snippets: bool = true,
    now_ticks: u64,
    detail: []const u8 = "",
    query: []const u8 = "",
};

pub const RevokeRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    lease_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const ContextLease = struct {
    id: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    task_id: u64 = 0,
    workspace_id: u64 = 0,
    sensitivity: manifest.DataSensitivity = .private_user_data,
    byte_limit: usize = 0,
    bytes_used: usize = 0,
    expires_at_ticks: u64 = 0,
    local_model: bool = false,
    encrypted_index: bool = false,
    redacted_snippets: bool = false,
    revoked: bool = false,
    revocation_generation: u32 = 0,
    last_consumed_receipt_id: u64 = 0,

    pub fn remainingBytes(self: ContextLease) usize {
        if (self.bytes_used >= self.byte_limit) return 0;
        return self.byte_limit - self.bytes_used;
    }
};

pub const QueryResult = struct {
    lease_id: u64,
    workspace_id: u64,
    index_generation: u64 = 0,
    bytes_used: usize,
    bytes_remaining: usize,
};

pub const RetrievalResult = struct {
    accounting: QueryResult,
    results: []const indexing_service.SearchResult,
};

pub const ContextPack = struct {
    workspace_id: u64,
    object_id: u64,
    version_id: u64,
    index_generation: u64,
    score: u16,
    title_hits: u16,
    body_hits: u16,
    sensitivity: manifest.DataSensitivity,
    title_fingerprint: u64,
    flags: u16,
};

pub const PackResult = struct {
    accounting: QueryResult,
    packs: []const ContextPack,
    receipt: ContextPackReceipt,
};

pub const ContextPackReceipt = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    lease_id: u64,
    receipt_id: u64,
    workspace_id: u64,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    bytes_used: usize,
    bytes_remaining: usize,
    pack_count: u16,
    index_generation: u64,
    lease_revocation_generation: u32,
    privacy_mode_flags: u16,
    max_pack_sensitivity: manifest.DataSensitivity,
    request_fingerprint: crypto_hash.Digest,
    query_fingerprint: crypto_hash.Digest,
    pack_digest: crypto_hash.Digest,
    receipt_digest: crypto_hash.Digest,

    pub fn complete(self: ContextPackReceipt) bool {
        return self.receipt_id != 0 and
            self.index_generation != 0 and
            self.issued_at_ticks < self.expires_at_ticks and
            !std.mem.eql(u8, &self.request_fingerprint, &crypto_hash.zero_digest) and
            !std.mem.eql(u8, &self.query_fingerprint, &crypto_hash.zero_digest) and
            !std.mem.eql(u8, &self.pack_digest, &crypto_hash.zero_digest) and
            !std.mem.eql(u8, &self.receipt_digest, &crypto_hash.zero_digest);
    }

    pub fn freshAt(self: ContextPackReceipt, now_ticks: u64) bool {
        return self.complete() and now_ticks >= self.issued_at_ticks and now_ticks < self.expires_at_ticks;
    }
};

pub const PACK_FLAG_REDACTED: u16 = 0x0001;
pub const PACK_FLAG_LOCAL_MODEL: u16 = 0x0002;
pub const PACK_FLAG_ENCRYPTED_INDEX: u16 = 0x0004;

const Slot = struct {
    in_use: bool = false,
    lease: ContextLease = .{},
};

fn slotLeaseKey(slot: *const Slot) u64 {
    return slot.lease.id;
}

const LeaseArena = indexed_arena.IndexedArenaWithKey(u64, Slot, MAX_CONTEXT_LEASES, MAX_CONTEXT_LEASES * 2, slotLeaseKey);

pub const Service = struct {
    next_lease_id: u64 = 1,
    next_receipt_id: u64 = 1,
    slots: LeaseArena = LeaseArena.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn issueLease(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: LeaseRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*ContextLease {
        if (request.task_id == 0 or request.subject.serial == 0 or request.expires_at_ticks <= request.now_ticks or request.max_query_bytes == 0) {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, request.max_query_bytes, request.now_ticks, request.detail);
            return error.PolicyDenied;
        }

        const decision = policies.semanticMemoryDecision(subjects, .{
            .sensitivity = request.sensitivity,
            .query_bytes = request.max_query_bytes,
            .local_model = request.local_model,
            .encrypted_index = request.encrypted_index,
            .redacted_snippets = request.redacted_snippets,
        });
        if (!decision.allowed) {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, request.max_query_bytes, request.now_ticks, request.detail);
            return error.PolicyDenied;
        }

        const lease_id = self.next_lease_id;
        const lease = ContextLease{
            .id = lease_id,
            .subject = request.subject,
            .task_id = request.task_id,
            .workspace_id = request.workspace_id,
            .sensitivity = request.sensitivity,
            .byte_limit = request.max_query_bytes,
            .expires_at_ticks = request.expires_at_ticks,
            .local_model = request.local_model,
            .encrypted_index = request.encrypted_index,
            .redacted_snippets = request.redacted_snippets,
        };

        const slot = self.slots.reserve(lease_id) orelse {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, request.max_query_bytes, request.now_ticks, request.detail);
            return error.LeaseTableFull;
        };
        errdefer _ = self.slots.remove(lease_id);
        try recordSemantic(ledger, request.subject, request.task_id, true, request.local_model, request.encrypted_index, request.redacted_snippets, request.max_query_bytes, request.now_ticks, request.detail);
        slot.lease = lease;
        self.advanceNextLeaseId();
        return &slot.lease;
    }

    pub fn query(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: QueryRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!QueryResult {
        const query_bytes = meteredQueryBytes(request);
        const lease = try self.validateQueryLease(request, query_bytes, ledger);

        const decision = policies.semanticMemoryDecision(subjects, .{
            .sensitivity = lease.sensitivity,
            .query_bytes = query_bytes,
            .local_model = request.local_model,
            .encrypted_index = request.encrypted_index,
            .redacted_snippets = request.redacted_snippets,
        });
        if (!decision.allowed) {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.PolicyDenied;
        }

        try recordSemantic(ledger, request.subject, request.task_id, true, request.local_model, request.encrypted_index, request.redacted_snippets, query_bytes, request.now_ticks, request.detail);
        lease.bytes_used += query_bytes;
        return .{
            .lease_id = lease.id,
            .workspace_id = lease.workspace_id,
            .index_generation = 0,
            .bytes_used = lease.bytes_used,
            .bytes_remaining = lease.remainingBytes(),
        };
    }

    pub fn retrieve(
        self: *Service,
        index: *const indexing_service.Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: QueryRequest,
        output: *[indexing_service.MAX_RESULTS]indexing_service.SearchResult,
        ledger: ?*event_ledger.Ledger,
    ) Error!RetrievalResult {
        const query_bytes = request.query.len;
        const lease = try self.validateQueryLease(request, query_bytes, ledger);
        var workspace_scope = [_]u64{lease.workspace_id};
        const workspace_sensitivity = index.permittedWorkspaceSensitivity(&workspace_scope);
        if (sensitivityExceeds(workspace_sensitivity, lease.sensitivity)) {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.LeaseSensitivityMismatch;
        }
        const results = try index.semanticQuery(policies, subjects, .{
            .subject = request.subject,
            .task_id = request.task_id,
            .permitted_workspaces = &workspace_scope,
            .query = request.query,
            .local_model = request.local_model,
            .encrypted_index = request.encrypted_index,
            .redacted_snippets = request.redacted_snippets,
            .now_ticks = request.now_ticks,
            .detail = request.detail,
        }, output, ledger);
        lease.bytes_used += query_bytes;
        return .{
            .accounting = .{
                .lease_id = lease.id,
                .workspace_id = lease.workspace_id,
                .index_generation = index.generation,
                .bytes_used = lease.bytes_used,
                .bytes_remaining = lease.remainingBytes(),
            },
            .results = results,
        };
    }

    pub fn retrievePacks(
        self: *Service,
        index: *const indexing_service.Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: QueryRequest,
        scratch_results: *[indexing_service.MAX_RESULTS]indexing_service.SearchResult,
        output: *[indexing_service.MAX_RESULTS]ContextPack,
        ledger: ?*event_ledger.Ledger,
    ) Error!PackResult {
        if (self.next_receipt_id == std.math.maxInt(u64)) return error.ReceiptIdExhausted;
        const retrieval = try self.retrieve(index, policies, subjects, request, scratch_results, ledger);
        for (retrieval.results, 0..) |result, result_index| {
            output[result_index] = contextPackFromResult(result, request);
        }
        const lease = self.find(request.lease_id).?;
        const packs = output[0..retrieval.results.len];
        const receipt_id = self.next_receipt_id;
        self.next_receipt_id += 1;
        return .{
            .accounting = retrieval.accounting,
            .packs = packs,
            .receipt = issuePackReceipt(receipt_id, request, lease.*, retrieval.accounting, packs),
        };
    }

    pub fn revoke(self: *Service, request: RevokeRequest, ledger: ?*event_ledger.Ledger) Error!void {
        const lease = self.find(request.lease_id) orelse {
            try recordSemantic(ledger, request.subject, request.task_id, false, true, true, true, 0, request.now_ticks, request.detail);
            return error.LeaseNotFound;
        };
        if (!lease.subject.eql(request.subject) or lease.task_id != request.task_id) {
            try recordSemantic(ledger, request.subject, request.task_id, false, lease.local_model, lease.encrypted_index, lease.redacted_snippets, 0, request.now_ticks, request.detail);
            return error.SourceMismatch;
        }
        try recordSemantic(ledger, request.subject, request.task_id, true, lease.local_model, lease.encrypted_index, lease.redacted_snippets, 0, request.now_ticks, request.detail);
        lease.revoked = true;
        lease.revocation_generation +|= 1;
    }

    pub fn find(self: *Service, lease_id: u64) ?*ContextLease {
        const slot = self.slots.get(lease_id) orelse return null;
        return &slot.lease;
    }

    pub fn findConst(self: *const Service, lease_id: u64) ?*const ContextLease {
        const slot = self.slots.getConst(lease_id) orelse return null;
        return &slot.lease;
    }

    fn advanceNextLeaseId(self: *Service) void {
        self.next_lease_id +%= 1;
        if (self.next_lease_id == 0) self.next_lease_id = 1;
    }

    pub fn consumePackReceipt(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        receipt: ContextPackReceipt,
        request: QueryRequest,
        accounting: QueryResult,
        packs: []const ContextPack,
        current_index_generation: u64,
        now_ticks: u64,
        ledger: ?*event_ledger.Ledger,
        detail: []const u8,
    ) Error!bool {
        if (!verifyPackReceiptForLiveLease(self, receipt, request, accounting, packs, current_index_generation, now_ticks)) {
            try recordSemanticReceipt(ledger, receipt.receipt_id, request, false, now_ticks, detail);
            return false;
        }
        const lease = self.find(receipt.lease_id) orelse return false;
        const decision = policies.semanticMemoryDecision(subjects, .{
            .sensitivity = lease.sensitivity,
            .query_bytes = meteredQueryBytes(request),
            .local_model = request.local_model,
            .encrypted_index = request.encrypted_index,
            .redacted_snippets = request.redacted_snippets,
        });
        if (!decision.allowed) {
            try recordSemanticReceipt(ledger, receipt.receipt_id, request, false, now_ticks, detail);
            return false;
        }
        if (receipt.receipt_id <= lease.last_consumed_receipt_id) {
            try recordSemanticReceipt(ledger, receipt.receipt_id, request, false, now_ticks, detail);
            return false;
        }
        try recordSemanticReceipt(ledger, receipt.receipt_id, request, true, now_ticks, detail);
        lease.last_consumed_receipt_id = receipt.receipt_id;
        return true;
    }

    fn validateQueryLease(
        self: *Service,
        request: QueryRequest,
        query_bytes: usize,
        ledger: ?*event_ledger.Ledger,
    ) Error!*ContextLease {
        const lease = self.find(request.lease_id) orelse {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.LeaseNotFound;
        };
        if (!lease.subject.eql(request.subject) or lease.task_id != request.task_id) {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.SourceMismatch;
        }
        if (lease.revoked) {
            try recordSemantic(ledger, request.subject, request.task_id, false, lease.local_model, lease.encrypted_index, lease.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.LeaseRevoked;
        }
        if (request.now_ticks >= lease.expires_at_ticks) {
            try recordSemantic(ledger, request.subject, request.task_id, false, lease.local_model, lease.encrypted_index, lease.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.LeaseExpired;
        }
        if (lease.workspace_id != request.workspace_id) {
            try recordSemantic(ledger, request.subject, request.task_id, false, lease.local_model, lease.encrypted_index, lease.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.WorkspaceScopeMismatch;
        }
        if (privacyFlagsFromLease(lease.*) != privacyFlagsFromRequest(request)) {
            try recordSemantic(ledger, request.subject, request.task_id, false, request.local_model, request.encrypted_index, request.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.LeasePrivacyMismatch;
        }
        if (query_bytes == 0 or query_bytes > lease.remainingBytes()) {
            try recordSemantic(ledger, request.subject, request.task_id, false, lease.local_model, lease.encrypted_index, lease.redacted_snippets, query_bytes, request.now_ticks, request.detail);
            return error.QueryBudgetExceeded;
        }
        return lease;
    }
};

pub fn verifyPackReceipt(
    receipt: ContextPackReceipt,
    request: QueryRequest,
    accounting: QueryResult,
    packs: []const ContextPack,
) bool {
    if (!receipt.complete()) return false;
    if (!receipt.subject.eql(request.subject)) return false;
    if (receipt.task_id != request.task_id or receipt.lease_id != request.lease_id) return false;
    if (receipt.workspace_id != request.workspace_id or receipt.workspace_id != accounting.workspace_id) return false;
    if (receipt.issued_at_ticks != request.now_ticks) return false;
    if (receipt.index_generation != accounting.index_generation) return false;
    if (receipt.bytes_used != accounting.bytes_used or receipt.bytes_remaining != accounting.bytes_remaining) return false;
    if (receipt.pack_count != packs.len) return false;
    if (receipt.privacy_mode_flags != privacyFlagsFromRequest(request)) return false;
    if (receipt.max_pack_sensitivity != maxPackSensitivity(packs)) return false;
    if (!packsMatchReceiptEnvelope(receipt, packs)) return false;
    const request_fingerprint = digestRequestEnvelope(request);
    if (!std.mem.eql(u8, &receipt.request_fingerprint, &request_fingerprint)) return false;
    const query_fingerprint = digestQuery(request.query);
    if (!std.mem.eql(u8, &receipt.query_fingerprint, &query_fingerprint)) return false;
    const pack_digest = digestPacks(packs);
    if (!std.mem.eql(u8, &receipt.pack_digest, &pack_digest)) return false;
    const expected = digestReceiptFields(receipt);
    return std.mem.eql(u8, &receipt.receipt_digest, &expected);
}

pub fn verifyPackReceiptAt(
    receipt: ContextPackReceipt,
    request: QueryRequest,
    accounting: QueryResult,
    packs: []const ContextPack,
    now_ticks: u64,
) bool {
    return receipt.freshAt(now_ticks) and verifyPackReceipt(receipt, request, accounting, packs);
}

pub fn verifyPackReceiptForLiveLease(
    service: *const Service,
    receipt: ContextPackReceipt,
    request: QueryRequest,
    accounting: QueryResult,
    packs: []const ContextPack,
    current_index_generation: u64,
    now_ticks: u64,
) bool {
    if (!verifyPackReceiptAt(receipt, request, accounting, packs, now_ticks)) return false;
    if (receipt.index_generation != current_index_generation) return false;
    const lease = service.findConst(receipt.lease_id) orelse return false;
    return !lease.revoked and
        lease.revocation_generation == receipt.lease_revocation_generation and
        receipt.receipt_id > lease.last_consumed_receipt_id and
        lease.bytes_used == receipt.bytes_used and
        lease.remainingBytes() == receipt.bytes_remaining and
        !sensitivityExceeds(receipt.max_pack_sensitivity, lease.sensitivity) and
        privacyFlagsFromLease(lease.*) == receipt.privacy_mode_flags and
        lease.subject.eql(receipt.subject) and
        lease.task_id == receipt.task_id and
        lease.workspace_id == receipt.workspace_id and
        lease.expires_at_ticks == receipt.expires_at_ticks;
}

fn issuePackReceipt(
    receipt_id: u64,
    request: QueryRequest,
    lease: ContextLease,
    accounting: QueryResult,
    packs: []const ContextPack,
) ContextPackReceipt {
    var receipt = ContextPackReceipt{
        .subject = request.subject,
        .task_id = request.task_id,
        .lease_id = lease.id,
        .receipt_id = receipt_id,
        .workspace_id = lease.workspace_id,
        .issued_at_ticks = request.now_ticks,
        .expires_at_ticks = lease.expires_at_ticks,
        .bytes_used = accounting.bytes_used,
        .bytes_remaining = accounting.bytes_remaining,
        .pack_count = @intCast(packs.len),
        .index_generation = accounting.index_generation,
        .lease_revocation_generation = lease.revocation_generation,
        .privacy_mode_flags = privacyFlagsFromRequest(request),
        .max_pack_sensitivity = maxPackSensitivity(packs),
        .request_fingerprint = digestRequestEnvelope(request),
        .query_fingerprint = digestQuery(request.query),
        .pack_digest = digestPacks(packs),
        .receipt_digest = crypto_hash.zero_digest,
    };
    receipt.receipt_digest = digestReceiptFields(receipt);
    return receipt;
}

fn contextPackFromResult(result: indexing_service.SearchResult, request: QueryRequest) ContextPack {
    const flags = privacyFlagsFromRequest(request);
    return .{
        .workspace_id = result.workspace_id,
        .object_id = result.object_id,
        .version_id = result.version_id,
        .index_generation = result.index_generation,
        .score = result.score,
        .title_hits = result.title_hits,
        .body_hits = result.body_hits,
        .sensitivity = result.sensitivity,
        .title_fingerprint = result.title_fingerprint,
        .flags = flags,
    };
}

pub fn privacyFlagsFromRequest(request: QueryRequest) u16 {
    var flags: u16 = 0;
    if (request.redacted_snippets) flags |= PACK_FLAG_REDACTED;
    if (request.local_model) flags |= PACK_FLAG_LOCAL_MODEL;
    if (request.encrypted_index) flags |= PACK_FLAG_ENCRYPTED_INDEX;
    return flags;
}

pub fn meteredQueryBytes(request: QueryRequest) usize {
    if (request.query.len != 0) return request.query.len;
    return request.query_bytes;
}

fn packsMatchReceiptEnvelope(receipt: ContextPackReceipt, packs: []const ContextPack) bool {
    for (packs) |pack| {
        if (pack.workspace_id != receipt.workspace_id) return false;
        if (pack.index_generation != receipt.index_generation) return false;
        if (pack.flags != receipt.privacy_mode_flags) return false;
    }
    return true;
}

fn maxPackSensitivity(packs: []const ContextPack) manifest.DataSensitivity {
    var result: manifest.DataSensitivity = .public_data;
    for (packs) |pack| {
        if (sensitivityExceeds(pack.sensitivity, result)) result = pack.sensitivity;
    }
    return result;
}

fn sensitivityExceeds(actual: manifest.DataSensitivity, limit: manifest.DataSensitivity) bool {
    return @intFromEnum(actual) > @intFromEnum(limit);
}

fn privacyFlagsFromLease(lease: ContextLease) u16 {
    var flags: u16 = 0;
    if (lease.redacted_snippets) flags |= PACK_FLAG_REDACTED;
    if (lease.local_model) flags |= PACK_FLAG_LOCAL_MODEL;
    if (lease.encrypted_index) flags |= PACK_FLAG_ENCRYPTED_INDEX;
    return flags;
}

fn digestQuery(query: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "schema", "zigos.personal-context.query");
    crypto_hash.updateBytes(&hasher, "query", query);
    return crypto_hash.finalize(&hasher);
}

fn digestRequestEnvelope(request: QueryRequest) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "schema", "zigos.personal-context.request-envelope");
    const subject_key = request.subject.keyBytes();
    crypto_hash.updateBytes(&hasher, "subject", &subject_key);
    crypto_hash.updateInt(&hasher, "task-id", request.task_id);
    crypto_hash.updateInt(&hasher, "lease-id", request.lease_id);
    crypto_hash.updateInt(&hasher, "workspace-id", request.workspace_id);
    crypto_hash.updateInt(&hasher, "issued-at-ticks", request.now_ticks);
    crypto_hash.updateInt(&hasher, "query-bytes", request.query.len);
    crypto_hash.updateInt(&hasher, "privacy-mode-flags", privacyFlagsFromRequest(request));
    const query_fingerprint = digestQuery(request.query);
    crypto_hash.updateBytes(&hasher, "query-fingerprint", &query_fingerprint);
    return crypto_hash.finalize(&hasher);
}

fn digestPacks(packs: []const ContextPack) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "schema", "zigos.personal-context.packs");
    crypto_hash.updateInt(&hasher, "pack-count", packs.len);
    for (packs) |pack| {
        crypto_hash.updateInt(&hasher, "workspace-id", pack.workspace_id);
        crypto_hash.updateInt(&hasher, "object-id", pack.object_id);
        crypto_hash.updateInt(&hasher, "version-id", pack.version_id);
        crypto_hash.updateInt(&hasher, "index-generation", pack.index_generation);
        crypto_hash.updateInt(&hasher, "score", pack.score);
        crypto_hash.updateInt(&hasher, "title-hits", pack.title_hits);
        crypto_hash.updateInt(&hasher, "body-hits", pack.body_hits);
        crypto_hash.updateEnum(&hasher, "sensitivity", pack.sensitivity);
        crypto_hash.updateInt(&hasher, "title-fingerprint", pack.title_fingerprint);
        crypto_hash.updateInt(&hasher, "flags", pack.flags);
    }
    return crypto_hash.finalize(&hasher);
}

fn digestReceiptFields(receipt: ContextPackReceipt) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "schema", "zigos.personal-context.receipt");
    const subject_key = receipt.subject.keyBytes();
    crypto_hash.updateBytes(&hasher, "subject", &subject_key);
    crypto_hash.updateInt(&hasher, "task-id", receipt.task_id);
    crypto_hash.updateInt(&hasher, "lease-id", receipt.lease_id);
    crypto_hash.updateInt(&hasher, "receipt-id", receipt.receipt_id);
    crypto_hash.updateInt(&hasher, "workspace-id", receipt.workspace_id);
    crypto_hash.updateInt(&hasher, "issued-at-ticks", receipt.issued_at_ticks);
    crypto_hash.updateInt(&hasher, "expires-at-ticks", receipt.expires_at_ticks);
    crypto_hash.updateInt(&hasher, "bytes-used", receipt.bytes_used);
    crypto_hash.updateInt(&hasher, "bytes-remaining", receipt.bytes_remaining);
    crypto_hash.updateInt(&hasher, "pack-count", receipt.pack_count);
    crypto_hash.updateInt(&hasher, "index-generation", receipt.index_generation);
    crypto_hash.updateInt(&hasher, "lease-revocation-generation", receipt.lease_revocation_generation);
    crypto_hash.updateInt(&hasher, "privacy-mode-flags", receipt.privacy_mode_flags);
    crypto_hash.updateEnum(&hasher, "max-pack-sensitivity", receipt.max_pack_sensitivity);
    crypto_hash.updateBytes(&hasher, "request-fingerprint", &receipt.request_fingerprint);
    crypto_hash.updateBytes(&hasher, "query-fingerprint", &receipt.query_fingerprint);
    crypto_hash.updateBytes(&hasher, "pack-digest", &receipt.pack_digest);
    return crypto_hash.finalize(&hasher);
}

fn recordSemantic(
    ledger: ?*event_ledger.Ledger,
    subject: principal.PrincipalId,
    task_id: u64,
    allowed: bool,
    local_model: bool,
    encrypted_index: bool,
    redacted_snippets: bool,
    query_bytes: usize,
    tick: u64,
    detail: []const u8,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSemanticMemory(subject, task_id, allowed, local_model, encrypted_index, redacted_snippets, query_bytes, tick, detail);
    }
}

fn recordSemanticReceipt(
    ledger: ?*event_ledger.Ledger,
    receipt_id: u64,
    request: QueryRequest,
    allowed: bool,
    tick: u64,
    detail: []const u8,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSemanticMemoryReceipt(
            request.subject,
            request.task_id,
            request.workspace_id,
            receipt_id,
            allowed,
            request.local_model,
            request.encrypted_index,
            request.redacted_snippets,
            tick,
            detail,
        );
    }
}

test "personal context service leases local semantic memory with scoped audit" {
    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 910 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 911 };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 91 },
        .label = "personal context policy",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-policy",
        .seed = signing.seedFromByte(0x91),
    });
    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = Service.init();
    var ledger = event_ledger.Ledger.init();

    const lease = try service.issueLease(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .workspace_id = 42,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context lease",
    }, &ledger);

    const first_query = try service.query(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 16,
        .now_ticks = 11,
        .detail = "private local retrieval",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 48), first_query.bytes_remaining);

    var metered_service = Service.init();
    var metered_ledger = event_ledger.Ledger.init();
    const metered_lease = try metered_service.issueLease(&policies, subjects, .{
        .subject = app,
        .task_id = 709,
        .workspace_id = 42,
        .max_query_bytes = 8,
        .expires_at_ticks = 100,
        .now_ticks = 11,
        .detail = "private metered text lease",
    }, &metered_ledger);
    const metered_request = QueryRequest{
        .subject = app,
        .task_id = 709,
        .lease_id = metered_lease.id,
        .workspace_id = 42,
        .query_bytes = 1,
        .query = "context",
        .now_ticks = 12,
        .detail = "private metered text query",
    };
    const metered_query = try metered_service.query(&policies, subjects, metered_request, &metered_ledger);
    try std.testing.expectEqual(@as(usize, 7), meteredQueryBytes(metered_request));
    try std.testing.expectEqual(@as(usize, 7), metered_query.bytes_used);
    try std.testing.expectEqual(@as(usize, 1), metered_query.bytes_remaining);

    var semantic_index = indexing_service.Service.init();
    try semantic_index.upsertClassified(42, 1001, 1, "Context Notes", "private personal context roadmap", .private_user_data);
    try semantic_index.upsertClassified(43, 1002, 1, "Other Context", "private personal context roadmap", .private_user_data);
    var results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    const retrieval = try service.retrieve(&semantic_index, &policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 0,
        .query = "context",
        .now_ticks = 12,
        .detail = "private indexed context retrieval",
    }, &results_buffer, &ledger);
    try std.testing.expectEqual(@as(usize, 1), retrieval.results.len);
    try std.testing.expectEqual(@as(u64, 1001), retrieval.results[0].object_id);
    try std.testing.expectEqual(semantic_index.generation, retrieval.accounting.index_generation);
    try std.testing.expectEqual(semantic_index.generation, retrieval.results[0].index_generation);
    try std.testing.expectEqual(@as(usize, 23), retrieval.accounting.bytes_used);
    try std.testing.expectEqual(@as(usize, 41), retrieval.accounting.bytes_remaining);
    try std.testing.expectEqual(@as(u16, 1), retrieval.results[0].title_hits);
    try std.testing.expectEqual(@as(u16, 1), retrieval.results[0].body_hits);

    var pack_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var packs_buffer: [indexing_service.MAX_RESULTS]ContextPack = undefined;
    const pack_request = QueryRequest{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 0,
        .query = "context",
        .now_ticks = 13,
        .detail = "private packed context retrieval",
    };
    const packs = try service.retrievePacks(&semantic_index, &policies, subjects, pack_request, &pack_results_buffer, &packs_buffer, &ledger);
    try std.testing.expectEqual(@as(usize, 1), packs.packs.len);
    try std.testing.expectEqual(@as(u64, 1001), packs.packs[0].object_id);
    try std.testing.expectEqual(semantic_index.generation, packs.accounting.index_generation);
    try std.testing.expectEqual(semantic_index.generation, packs.packs[0].index_generation);
    try std.testing.expectEqual(@as(u16, 1), packs.packs[0].title_hits);
    try std.testing.expectEqual(@as(u16, 1), packs.packs[0].body_hits);
    try std.testing.expectEqual(manifest.DataSensitivity.private_user_data, packs.packs[0].sensitivity);
    try std.testing.expect(packs.packs[0].title_fingerprint != 0);
    try std.testing.expect((packs.packs[0].flags & PACK_FLAG_REDACTED) != 0);
    try std.testing.expect((packs.packs[0].flags & PACK_FLAG_LOCAL_MODEL) != 0);
    try std.testing.expect((packs.packs[0].flags & PACK_FLAG_ENCRYPTED_INDEX) != 0);
    try std.testing.expect(!@hasField(ContextPack, "title"));
    try std.testing.expect(!@hasField(ContextPack, "body"));
    try std.testing.expectEqual(@as(usize, 30), packs.accounting.bytes_used);
    try std.testing.expectEqual(@as(usize, 34), packs.accounting.bytes_remaining);
    try std.testing.expect(packs.receipt.complete());
    try std.testing.expect(packs.receipt.receipt_id != 0);
    try std.testing.expectEqual(semantic_index.generation, packs.receipt.index_generation);
    try std.testing.expectEqual(privacyFlagsFromRequest(pack_request), packs.receipt.privacy_mode_flags);
    try std.testing.expectEqual(manifest.DataSensitivity.private_user_data, packs.receipt.max_pack_sensitivity);
    try std.testing.expect(!std.mem.eql(u8, &packs.receipt.request_fingerprint, &crypto_hash.zero_digest));
    try std.testing.expect(verifyPackReceipt(packs.receipt, pack_request, packs.accounting, packs.packs));
    try std.testing.expect(verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 99));
    try std.testing.expect(verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 99));
    try std.testing.expectEqual(@as(u32, 0), packs.receipt.lease_revocation_generation);
    try std.testing.expect(try service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 99, &ledger, "private receipt consumption"));
    try std.testing.expect(!verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 99));
    try std.testing.expect(!(try service.consumePackReceipt(&policies, subjects, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 99, &ledger, "private receipt replay")));
    try std.testing.expect(!verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 100));
    try std.testing.expect(!verifyPackReceiptAt(packs.receipt, pack_request, packs.accounting, packs.packs, 12));
    var tampered_receipt = packs.receipt;
    tampered_receipt.receipt_id += 1;
    try std.testing.expect(!verifyPackReceipt(tampered_receipt, pack_request, packs.accounting, packs.packs));
    try std.testing.expect(!(try service.consumePackReceipt(&policies, subjects, tampered_receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 99, &ledger, "private receipt tamper")));
    var malformed_receipt = packs.receipt;
    malformed_receipt.receipt_id = 0;
    try std.testing.expect(!(try service.consumePackReceipt(&policies, subjects, malformed_receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 99, &ledger, "private malformed receipt")));
    var tampered_request = pack_request;
    tampered_request.query = "roadmap";
    try std.testing.expect(!verifyPackReceipt(packs.receipt, tampered_request, packs.accounting, packs.packs));
    var shifted_issue_request = pack_request;
    shifted_issue_request.now_ticks += 1;
    try std.testing.expect(!verifyPackReceipt(packs.receipt, shifted_issue_request, packs.accounting, packs.packs));
    var tampered_accounting = packs.accounting;
    tampered_accounting.index_generation += 1;
    try std.testing.expect(!verifyPackReceipt(packs.receipt, pack_request, tampered_accounting, packs.packs));
    var downgraded_request = pack_request;
    downgraded_request.local_model = false;
    try std.testing.expect(!verifyPackReceipt(packs.receipt, downgraded_request, packs.accounting, packs.packs));
    var tampered_packs = packs_buffer;
    tampered_packs[0].score += 1;
    try std.testing.expect(!verifyPackReceipt(packs.receipt, pack_request, packs.accounting, tampered_packs[0..packs.packs.len]));
    tampered_packs = packs_buffer;
    tampered_packs[0].index_generation += 1;
    var forged_receipt = packs.receipt;
    forged_receipt.pack_digest = digestPacks(tampered_packs[0..packs.packs.len]);
    forged_receipt.receipt_digest = digestReceiptFields(forged_receipt);
    try std.testing.expect(!verifyPackReceipt(forged_receipt, pack_request, packs.accounting, tampered_packs[0..packs.packs.len]));
    tampered_packs = packs_buffer;
    tampered_packs[0].workspace_id += 1;
    forged_receipt = packs.receipt;
    forged_receipt.pack_digest = digestPacks(tampered_packs[0..packs.packs.len]);
    forged_receipt.receipt_digest = digestReceiptFields(forged_receipt);
    try std.testing.expect(!verifyPackReceipt(forged_receipt, pack_request, packs.accounting, tampered_packs[0..packs.packs.len]));
    tampered_packs = packs_buffer;
    tampered_packs[0].flags = 0;
    forged_receipt = packs.receipt;
    forged_receipt.pack_digest = digestPacks(tampered_packs[0..packs.packs.len]);
    forged_receipt.receipt_digest = digestReceiptFields(forged_receipt);
    try std.testing.expect(!verifyPackReceipt(forged_receipt, pack_request, packs.accounting, tampered_packs[0..packs.packs.len]));
    tampered_packs = packs_buffer;
    tampered_packs[0].sensitivity = .secret_user_data;
    forged_receipt = packs.receipt;
    forged_receipt.max_pack_sensitivity = .secret_user_data;
    forged_receipt.pack_digest = digestPacks(tampered_packs[0..packs.packs.len]);
    forged_receipt.receipt_digest = digestReceiptFields(forged_receipt);
    try std.testing.expect(verifyPackReceipt(forged_receipt, pack_request, packs.accounting, tampered_packs[0..packs.packs.len]));
    try std.testing.expect(!verifyPackReceiptForLiveLease(&service, forged_receipt, pack_request, packs.accounting, tampered_packs[0..packs.packs.len], semantic_index.generation, 99));

    try std.testing.expectError(error.WorkspaceScopeMismatch, service.query(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 43,
        .query_bytes = 8,
        .now_ticks = 14,
        .detail = "private wrong workspace",
    }, &ledger));

    try std.testing.expectError(error.SourceMismatch, service.query(&policies, subjects, .{
        .subject = .{ .kind = .app, .serial = 912 },
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 8,
        .now_ticks = 14,
        .detail = "private wrong app",
    }, &ledger));

    try std.testing.expectError(error.LeasePrivacyMismatch, service.query(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 8,
        .local_model = false,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 15,
        .detail = "private remote retrieval attempt",
    }, &ledger));

    try std.testing.expectError(error.QueryBudgetExceeded, service.query(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 80,
        .now_ticks = 16,
        .detail = "private budget overflow",
    }, &ledger));

    try service.revoke(.{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .now_ticks = 17,
        .detail = "private context revoke",
    }, &ledger);
    try std.testing.expect(!verifyPackReceiptForLiveLease(&service, packs.receipt, pack_request, packs.accounting, packs.packs, semantic_index.generation, 18));

    try std.testing.expectError(error.LeaseRevoked, service.query(&policies, subjects, .{
        .subject = app,
        .task_id = 700,
        .lease_id = lease.id,
        .workspace_id = 42,
        .query_bytes = 8,
        .now_ticks = 18,
        .detail = "private revoked retrieval",
    }, &ledger));

    const short = try service.issueLease(&policies, subjects, .{
        .subject = app,
        .task_id = 701,
        .workspace_id = 42,
        .max_query_bytes = 32,
        .expires_at_ticks = 20,
        .now_ticks = 19,
        .detail = "private expiring lease",
    }, &ledger);
    try std.testing.expectError(error.LeaseExpired, service.query(&policies, subjects, .{
        .subject = app,
        .task_id = 701,
        .lease_id = short.id,
        .workspace_id = 42,
        .query_bytes = 8,
        .now_ticks = 20,
        .detail = "private expired retrieval",
    }, &ledger));

    var full_service = Service.init();
    for (0..MAX_CONTEXT_LEASES) |index| {
        _ = try full_service.issueLease(&policies, subjects, .{
            .subject = app,
            .task_id = 800 + @as(u64, @intCast(index)),
            .workspace_id = 42,
            .max_query_bytes = 8,
            .expires_at_ticks = 100,
            .now_ticks = 10,
        }, null);
    }
    try std.testing.expectError(error.LeaseTableFull, full_service.issueLease(&policies, subjects, .{
        .subject = app,
        .task_id = 900,
        .workspace_id = 42,
        .max_query_bytes = 8,
        .expires_at_ticks = 100,
        .now_ticks = 10,
    }, null));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 16), summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 9), summary.semantic_memory_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.semantic_memory_remote_denials);
    try std.testing.expectEqual(@as(usize, 4), summary.semantic_memory_receipt_events);
    try std.testing.expectEqual(@as(usize, 3), summary.semantic_memory_receipt_denials);
    try std.testing.expect(summary.protected_details_redacted >= summary.semantic_memory_events);

    var buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private personal context lease") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private local retrieval") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private indexed context retrieval") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private packed context retrieval") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private receipt replay") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private receipt tamper") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private malformed receipt") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "related=") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=semantic_memory") != null);

    var drift_policies = policy_object.Directory.init();
    _ = try drift_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 92 },
        .label = "personal context drift allow",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-drift-allow",
        .seed = signing.seedFromByte(0x92),
    });
    var drift_service = Service.init();
    var drift_ledger = event_ledger.Ledger.init();
    const drift_lease = try drift_service.issueLease(&drift_policies, subjects, .{
        .subject = app,
        .task_id = 702,
        .workspace_id = 52,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 21,
        .detail = "private policy drift lease",
    }, &drift_ledger);
    var drift_index = indexing_service.Service.init();
    try drift_index.upsertClassified(52, 2001, 1, "Policy Drift", "private receipt policy drift", .private_user_data);
    var drift_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var drift_packs_buffer: [indexing_service.MAX_RESULTS]ContextPack = undefined;
    const drift_request = QueryRequest{
        .subject = app,
        .task_id = 702,
        .lease_id = drift_lease.id,
        .workspace_id = 52,
        .query_bytes = 0,
        .query = "policy",
        .now_ticks = 22,
        .detail = "private policy-bound pack",
    };
    const drift_packs = try drift_service.retrievePacks(&drift_index, &drift_policies, subjects, drift_request, &drift_results_buffer, &drift_packs_buffer, &drift_ledger);
    _ = try drift_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 93 },
        .label = "personal context drift deny",
        .semantic_memory_allowed = false,
    }, signing.SignerIdentity{
        .label = "personal-context-drift-deny",
        .seed = signing.seedFromByte(0x93),
    });
    try std.testing.expect(!(try drift_service.consumePackReceipt(&drift_policies, subjects, drift_packs.receipt, drift_request, drift_packs.accounting, drift_packs.packs, drift_index.generation, 23, &drift_ledger, "private receipt policy drift")));
    const drift_summary = drift_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 3), drift_summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), drift_summary.semantic_memory_denials);
    try std.testing.expectEqual(@as(usize, 1), drift_summary.semantic_memory_receipt_events);
    try std.testing.expectEqual(@as(usize, 1), drift_summary.semantic_memory_receipt_denials);

    var loose_policies = policy_object.Directory.init();
    _ = try loose_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 94 },
        .label = "personal context loose policy",
        .semantic_memory_allowed = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-loose-policy",
        .seed = signing.seedFromByte(0x94),
    });
    var loose_service = Service.init();
    var loose_ledger = event_ledger.Ledger.init();
    const loose_lease = try loose_service.issueLease(&loose_policies, subjects, .{
        .subject = app,
        .task_id = 703,
        .workspace_id = 62,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .local_model = true,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 24,
        .detail = "private loose lease",
    }, &loose_ledger);
    try std.testing.expectError(error.LeasePrivacyMismatch, loose_service.query(&loose_policies, subjects, .{
        .subject = app,
        .task_id = 703,
        .lease_id = loose_lease.id,
        .workspace_id = 62,
        .query_bytes = 8,
        .local_model = false,
        .encrypted_index = true,
        .redacted_snippets = true,
        .now_ticks = 25,
        .detail = "private loose downgrade",
    }, &loose_ledger));
    const loose_summary = loose_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), loose_summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), loose_summary.semantic_memory_denials);
    try std.testing.expectEqual(@as(usize, 1), loose_summary.semantic_memory_remote_denials);

    var secret_cap_policies = policy_object.Directory.init();
    _ = try secret_cap_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 96 },
        .label = "personal context sensitivity cap policy",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-sensitivity-cap-policy",
        .seed = signing.seedFromByte(0x96),
    });
    var secret_cap_service = Service.init();
    var secret_cap_ledger = event_ledger.Ledger.init();
    var secret_cap_index = indexing_service.Service.init();
    try secret_cap_index.upsertClassified(82, 4001, 1, "Secret Context", "private secret context", .secret_user_data);
    const secret_cap_lease = try secret_cap_service.issueLease(&secret_cap_policies, subjects, .{
        .subject = app,
        .task_id = 705,
        .workspace_id = 82,
        .sensitivity = .private_user_data,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 28,
        .detail = "private sensitivity cap lease",
    }, &secret_cap_ledger);
    var secret_cap_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var secret_cap_packs_buffer: [indexing_service.MAX_RESULTS]ContextPack = undefined;
    try std.testing.expectError(error.LeaseSensitivityMismatch, secret_cap_service.retrievePacks(&secret_cap_index, &secret_cap_policies, subjects, .{
        .subject = app,
        .task_id = 705,
        .lease_id = secret_cap_lease.id,
        .workspace_id = 82,
        .query_bytes = 0,
        .query = "secret",
        .now_ticks = 29,
        .detail = "private sensitivity cap retrieval",
    }, &secret_cap_results_buffer, &secret_cap_packs_buffer, &secret_cap_ledger));
    const secret_cap_summary = secret_cap_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), secret_cap_summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), secret_cap_summary.semantic_memory_denials);

    var stale_policies = policy_object.Directory.init();
    _ = try stale_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 97 },
        .label = "personal context stale index policy",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-stale-index-policy",
        .seed = signing.seedFromByte(0x97),
    });
    var stale_service = Service.init();
    var stale_ledger = event_ledger.Ledger.init();
    var stale_index = indexing_service.Service.init();
    try stale_index.upsertClassified(92, 5001, 1, "Stable Context", "private stable context", .private_user_data);
    const stale_lease = try stale_service.issueLease(&stale_policies, subjects, .{
        .subject = app,
        .task_id = 706,
        .workspace_id = 92,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 30,
        .detail = "private stale index lease",
    }, &stale_ledger);
    var stale_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var stale_packs_buffer: [indexing_service.MAX_RESULTS]ContextPack = undefined;
    const stale_request = QueryRequest{
        .subject = app,
        .task_id = 706,
        .lease_id = stale_lease.id,
        .workspace_id = 92,
        .query_bytes = 0,
        .query = "stable",
        .now_ticks = 31,
        .detail = "private stale index pack",
    };
    const stale_packs = try stale_service.retrievePacks(&stale_index, &stale_policies, subjects, stale_request, &stale_results_buffer, &stale_packs_buffer, &stale_ledger);
    const issued_index_generation = stale_index.generation;
    try stale_index.upsertClassified(92, 5002, 1, "New Context", "private new context", .private_user_data);
    try std.testing.expect(stale_index.generation != issued_index_generation);
    try std.testing.expect(verifyPackReceiptForLiveLease(&stale_service, stale_packs.receipt, stale_request, stale_packs.accounting, stale_packs.packs, issued_index_generation, 32));
    try std.testing.expect(!verifyPackReceiptForLiveLease(&stale_service, stale_packs.receipt, stale_request, stale_packs.accounting, stale_packs.packs, stale_index.generation, 32));
    try std.testing.expect(!(try stale_service.consumePackReceipt(&stale_policies, subjects, stale_packs.receipt, stale_request, stale_packs.accounting, stale_packs.packs, stale_index.generation, 32, &stale_ledger, "private stale index receipt")));
    const stale_summary = stale_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 3), stale_summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), stale_summary.semantic_memory_receipt_events);
    try std.testing.expectEqual(@as(usize, 1), stale_summary.semantic_memory_receipt_denials);

    var accounting_policies = policy_object.Directory.init();
    _ = try accounting_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 98 },
        .label = "personal context accounting snapshot policy",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-accounting-snapshot-policy",
        .seed = signing.seedFromByte(0x98),
    });
    var accounting_service = Service.init();
    var accounting_ledger = event_ledger.Ledger.init();
    var accounting_index = indexing_service.Service.init();
    try accounting_index.upsertClassified(102, 6001, 1, "Stable Context", "private stable context", .private_user_data);
    const accounting_lease = try accounting_service.issueLease(&accounting_policies, subjects, .{
        .subject = app,
        .task_id = 707,
        .workspace_id = 102,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 33,
        .detail = "private accounting snapshot lease",
    }, &accounting_ledger);
    var accounting_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var accounting_packs_buffer: [indexing_service.MAX_RESULTS]ContextPack = undefined;
    const accounting_request = QueryRequest{
        .subject = app,
        .task_id = 707,
        .lease_id = accounting_lease.id,
        .workspace_id = 102,
        .query_bytes = 0,
        .query = "stable",
        .now_ticks = 34,
        .detail = "private accounting snapshot pack",
    };
    const accounting_packs = try accounting_service.retrievePacks(&accounting_index, &accounting_policies, subjects, accounting_request, &accounting_results_buffer, &accounting_packs_buffer, &accounting_ledger);
    _ = try accounting_service.query(&accounting_policies, subjects, .{
        .subject = app,
        .task_id = 707,
        .lease_id = accounting_lease.id,
        .workspace_id = 102,
        .query_bytes = 8,
        .now_ticks = 35,
        .detail = "private accounting snapshot drift",
    }, &accounting_ledger);
    try std.testing.expect(verifyPackReceipt(accounting_packs.receipt, accounting_request, accounting_packs.accounting, accounting_packs.packs));
    try std.testing.expect(!verifyPackReceiptForLiveLease(&accounting_service, accounting_packs.receipt, accounting_request, accounting_packs.accounting, accounting_packs.packs, accounting_index.generation, 36));
    try std.testing.expect(!(try accounting_service.consumePackReceipt(&accounting_policies, subjects, accounting_packs.receipt, accounting_request, accounting_packs.accounting, accounting_packs.packs, accounting_index.generation, 36, &accounting_ledger, "private stale accounting receipt")));
    const accounting_summary = accounting_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 4), accounting_summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), accounting_summary.semantic_memory_receipt_events);
    try std.testing.expectEqual(@as(usize, 1), accounting_summary.semantic_memory_receipt_denials);

    var empty_policies = policy_object.Directory.init();
    _ = try empty_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 95 },
        .label = "personal context empty policy",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 32,
    }, signing.SignerIdentity{
        .label = "personal-context-empty-policy",
        .seed = signing.seedFromByte(0x95),
    });
    var empty_service = Service.init();
    var empty_ledger = event_ledger.Ledger.init();
    var empty_index = indexing_service.Service.init();
    try empty_index.upsertClassified(72, 3001, 1, "Present Context", "private present context only", .private_user_data);
    const empty_lease = try empty_service.issueLease(&empty_policies, subjects, .{
        .subject = app,
        .task_id = 704,
        .workspace_id = 72,
        .max_query_bytes = 32,
        .expires_at_ticks = 100,
        .now_ticks = 26,
        .detail = "private empty context lease",
    }, &empty_ledger);
    var empty_results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    var empty_packs_buffer: [indexing_service.MAX_RESULTS]ContextPack = undefined;
    const empty_request = QueryRequest{
        .subject = app,
        .task_id = 704,
        .lease_id = empty_lease.id,
        .workspace_id = 72,
        .query_bytes = 0,
        .query = "absent",
        .now_ticks = 27,
        .detail = "private empty context pack",
    };
    const empty_packs = try empty_service.retrievePacks(&empty_index, &empty_policies, subjects, empty_request, &empty_results_buffer, &empty_packs_buffer, &empty_ledger);
    try std.testing.expectEqual(@as(usize, 0), empty_packs.packs.len);
    try std.testing.expectEqual(@as(u16, 0), empty_packs.receipt.pack_count);
    try std.testing.expectEqual(empty_index.generation, empty_packs.accounting.index_generation);
    try std.testing.expectEqual(empty_index.generation, empty_packs.receipt.index_generation);
    try std.testing.expect(empty_packs.receipt.complete());
    try std.testing.expectEqual(manifest.DataSensitivity.public_data, empty_packs.receipt.max_pack_sensitivity);
    try std.testing.expect(!std.mem.eql(u8, &empty_packs.receipt.request_fingerprint, &crypto_hash.zero_digest));
    try std.testing.expect(!std.mem.eql(u8, &empty_packs.receipt.pack_digest, &crypto_hash.zero_digest));
    try std.testing.expect(verifyPackReceipt(empty_packs.receipt, empty_request, empty_packs.accounting, empty_packs.packs));
    try std.testing.expect(verifyPackReceiptAt(empty_packs.receipt, empty_request, empty_packs.accounting, empty_packs.packs, 28));
    try std.testing.expect(try empty_service.consumePackReceipt(&empty_policies, subjects, empty_packs.receipt, empty_request, empty_packs.accounting, empty_packs.packs, empty_index.generation, 28, &empty_ledger, "private empty receipt consumption"));
    try std.testing.expect(!(try empty_service.consumePackReceipt(&empty_policies, subjects, empty_packs.receipt, empty_request, empty_packs.accounting, empty_packs.packs, empty_index.generation, 28, &empty_ledger, "private empty receipt replay")));
    const empty_summary = empty_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 4), empty_summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 1), empty_summary.semantic_memory_denials);
    try std.testing.expectEqual(@as(usize, 2), empty_summary.semantic_memory_receipt_events);
    try std.testing.expectEqual(@as(usize, 1), empty_summary.semantic_memory_receipt_denials);
}

test "personal context lease ids wrap without publishing id zero" {
    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 920 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 921 };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 92 },
        .label = "personal context wrap policy",
        .semantic_memory_allowed = true,
        .require_local_semantic_model = true,
        .require_encrypted_semantic_index = true,
        .require_redacted_semantic_snippets = true,
        .max_semantic_query_bytes = 64,
    }, signing.SignerIdentity{
        .label = "personal-context-wrap-policy",
        .seed = signing.seedFromByte(0x96),
    });

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = Service.init();
    service.next_lease_id = std.math.maxInt(u64);

    const first = try service.issueLease(&policies, subjects, .{
        .subject = app,
        .task_id = 720,
        .workspace_id = 42,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 10,
        .detail = "private personal context lease",
    }, null);
    try std.testing.expectEqual(std.math.maxInt(u64), first.id);
    try std.testing.expectEqual(@as(u64, 1), service.next_lease_id);
    try std.testing.expect(service.find(0) == null);

    const second = try service.issueLease(&policies, subjects, .{
        .subject = app,
        .task_id = 721,
        .workspace_id = 43,
        .max_query_bytes = 64,
        .expires_at_ticks = 100,
        .now_ticks = 11,
        .detail = "private personal context lease",
    }, null);
    try std.testing.expectEqual(@as(u64, 1), second.id);
    try std.testing.expectEqual(@as(u64, 2), service.next_lease_id);
    try std.testing.expectEqual(@as(usize, 2), service.slots.countInUse());
}
