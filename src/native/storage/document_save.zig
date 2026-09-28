const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const ids = @import("../core/ids.zig");
const object_store = @import("object_store.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("storage_service.zig");
const document_signer = @import("document_signer.zig");

pub const Request = RequestFor(document_signer.Signer);
pub const VerificationRequest = RequestFor(signing.SignerIdentity);

fn RequestFor(comptime Signer: type) type {
    return struct {
        workspace_id: u64,
        path: []const u8,
        expected_version_id: u64,
        payload: []const u8,
        signer: Signer,
        tick: u64,
    };
}

pub const Receipt = struct {
    object_id: u64,
    previous_version_id: u64,
    version_id: u64,
    checkpoint_generation: u64,
};

const Pending = struct {
    workspace_id: u64,
    object_id: u64,
    base_version_id: u64,
    previous_version_id: u64,
    version_id: u64,
    path_digest: crypto_hash.Digest,
    request_digest: crypto_hash.Digest,
};

// One open editor's save state. The storage service and editor serialize calls.
// A failed device flush leaves the draft unacknowledged and retains its version
// for retry; repeated Ctrl+Enter must not consume more version slots. This state
// is advisory, never authority: callers still need a scoped storage service port.
pub const Session = struct {
    pending: ?Pending = null,

    pub fn save(self: *Session, storage: *storage_service.Service, request: Request) !Receipt {
        return self.saveImpl(storage, request);
    }

    // Public software keys belong only to host fixtures and verification
    // workloads. Production callers cannot pass them to the normal save API.
    pub fn saveForVerification(self: *Session, storage: *storage_service.Service, request: VerificationRequest) !Receipt {
        if (comptime @import("builtin").os.tag == .freestanding) {
            if (comptime !@import("../../kernel/config.zig").includesVerificationEvidence())
                return error.SealedSigningKeyRequired;
        }
        return self.saveImpl(storage, request);
    }

    fn saveImpl(self: *Session, storage: *storage_service.Service, request: anytype) !Receipt {
        const uses_vault = @TypeOf(request.signer) == document_signer.Signer;
        if (uses_vault) try request.signer.validate(request.tick);
        try storage.requireDurableBoundary();
        const workspace_id = ids.workspace(request.workspace_id);
        const entry = try storage.resolve(workspace_id, request.path);
        if (entry.object_type != .document) return error.NotDocument;
        const object_id = entry.object_id.raw();
        var expected_version = request.expected_version_id;
        const path_digest = pathDigest(request.path);
        const request_digest = try requestDigest(request);

        if (self.pending) |pending| {
            if (pending.workspace_id != request.workspace_id or pending.object_id != object_id or
                !std.mem.eql(u8, &pending.path_digest, &path_digest)) return error.PendingDocumentSave;
            if (entry.version_id.raw() != pending.version_id or expected_version != pending.base_version_id) return error.DocumentChanged;
            const generation = try storage.checkpointDurable();
            // Keep the token until the entire requested save succeeds, including
            // when the user continues editing after a previous flush failure.
            if (std.mem.eql(u8, &pending.request_digest, &request_digest)) {
                self.pending = null;
                return receipt(pending, generation);
            }
            expected_version = pending.version_id;
        }

        if (expected_version == 0 or entry.version_id.raw() != expected_version) return error.DocumentChanged;
        const opened = storage.version(expected_version) orelse return error.ObjectMissing;
        if (opened.object_id.raw() != object_id) return error.DocumentChanged;
        // A workspace can intentionally pin an older immutable version. The
        // conflict token is that workspace's pointer, while the object store
        // serializes all versions in one append-only history. Appending to its
        // current head does not move any other workspace's pointer.
        const parent = storage.latestVersion(entry.object_id) orelse return error.ObjectMissing;
        const metadata = if (uses_vault)
            try request.signer.signMetadata(request.path, request.payload, request.tick)
        else
            try object_store.signMetadata(request.signer, request.path, "text/markdown", .document, request.payload, request.tick);

        {
            // The object bytes and workspace pointer belong to one checkpoint.
            // No automatic checkpoint may expose a new object before its path.
            storage.beginCheckpointBatch();
            defer storage.endCheckpointBatch();
            try storage.beginTransaction(workspace_id);
            errdefer storage.abortTransaction(workspace_id) catch {};
            // Reserve the path's staging slot before consuming an immutable
            // version slot. Replacing this staged entry requires no allocation.
            try storage.stagePut(workspace_id, request.path, entry.object_id, entry.version_id, .document);
            const edited = try storage.putVersion(.{
                .preferred_object_id = entry.object_id,
                .object_type = .document,
                .payload = request.payload,
                .metadata = metadata,
                .parent_version_id = parent.id,
            });
            try storage.stagePut(workspace_id, request.path, edited.object_id, edited.version_id, .document);
            _ = try storage.commit(workspace_id, request.tick);
            self.pending = .{
                .workspace_id = request.workspace_id,
                .object_id = object_id,
                .base_version_id = request.expected_version_id,
                .previous_version_id = expected_version,
                .version_id = edited.version_id.raw(),
                .path_digest = path_digest,
                .request_digest = request_digest,
            };
        }
        const generation = try storage.checkpointDurable();
        const result = receipt(self.pending.?, generation);
        self.pending = null;
        return result;
    }
};

fn receipt(pending: Pending, generation: u64) Receipt {
    return .{
        .object_id = pending.object_id,
        .previous_version_id = pending.previous_version_id,
        .version_id = pending.version_id,
        .checkpoint_generation = generation,
    };
}

fn pathDigest(path: []const u8) crypto_hash.Digest {
    var hash = crypto_hash.init();
    crypto_hash.updateBytes(&hash, "document-save-path", path);
    return crypto_hash.finalize(&hash);
}

fn requestDigest(request: anytype) !crypto_hash.Digest {
    var hash = crypto_hash.init();
    crypto_hash.updateBytes(&hash, "payload", request.payload);
    if (@TypeOf(request.signer) == document_signer.Signer) {
        crypto_hash.updateBytes(&hash, "signer-sealed-key", &request.signer.sealed_digest);
    } else {
        crypto_hash.updateBytes(&hash, "signer-label", request.signer.label);
        const public_key = try signing.publicKey(request.signer);
        crypto_hash.updateBytes(&hash, "signer-public-key", &public_key);
    }
    return crypto_hash.finalize(&hash);
}
