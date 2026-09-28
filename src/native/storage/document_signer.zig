const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const principal = @import("../core/principal.zig");
const policy = @import("../policy/policy_object.zig");
const vault = @import("../services/secret_vault_service.zig");
const secrets = @import("../platform/secure_secret_store.zig");
const ledger = @import("../platform/event_ledger.zig");
const objects = @import("object_store.zig");

// Session-owned, stable for the lifetime of every dependent document channel.
// Requests carry a lease and ciphertext binding, never a seed or raw key.
pub const Authority = struct {
    service: *vault.Service,
    policies: *const policy.Directory,
    subjects: policy.SubjectSet,
    owner: principal.PrincipalId,
    holder: principal.PrincipalId,
    task_id: u64,
    audit: ?*ledger.Ledger = null,
};

pub const Signer = struct {
    authority: ?*const Authority = null,
    handle_id: u64 = 0,
    sealed_digest: crypto_hash.Digest = @splat(0),

    pub fn bind(authority: *const Authority, handle_id: u64, now_ticks: u64) !Signer {
        var signer = Signer{ .authority = authority, .handle_id = handle_id };
        signer.sealed_digest = (try signer.secret(now_ticks)).sealed_digest;
        return signer;
    }

    fn request(self: Signer, now_ticks: u64) vault.SigningAuthority {
        const authority = self.authority.?;
        return .{ .holder = authority.holder, .task_id = authority.task_id, .handle_id = self.handle_id, .now_ticks = now_ticks };
    }

    fn secret(self: Signer, now_ticks: u64) !*const secrets.SecretRecord {
        const authority = self.authority orelse return error.SigningAuthorityUnavailable;
        if (authority.holder.kind != .service or authority.task_id == 0) return error.InvalidSigningAuthority;
        const handle = try authority.service.requireSigningHandle(authority.policies, authority.subjects, self.request(now_ticks));
        const record = authority.service.store.describeSecret(handle.secret_id) orelse return error.SecretNotFound;
        if (!record.owner.eql(authority.owner)) return error.SecretOwnerMismatch;
        if (!record.hardware_backed or !record.hardware_provider_used or !record.sealed_digest_present or
            record.exportable or record.resident_material or record.sealedBlob() == null) return error.SealedSigningKeyRequired;
        return record;
    }

    pub fn validate(self: Signer, now_ticks: u64) !void {
        const record = try self.secret(now_ticks);
        if (!std.mem.eql(u8, &record.sealed_digest, &self.sealed_digest)) return error.SigningKeyChanged;
    }

    pub fn validateService(self: Signer, holder: principal.PrincipalId, task_id: u64, now_ticks: u64) !void {
        const authority = self.authority orelse return error.SigningAuthorityUnavailable;
        if (!authority.holder.eql(holder) or authority.task_id != task_id) return error.HandleHolderMismatch;
        try self.validate(now_ticks);
    }

    pub fn signMetadata(self: Signer, path: []const u8, payload: []const u8, now_ticks: u64) !objects.SignedMetadata {
        try self.validate(now_ticks);
        const authority = self.authority.?;
        var metadata = try objects.SignedMetadata.init(path, "text/markdown", .{}, now_ticks);
        var buffer: [objects.MAX_METADATA_MESSAGE_BYTES]u8 = undefined;
        const message = try metadata.signingMessage(&buffer, .document, payload);
        metadata.signature = try authority.service.signMessage(authority.policies, authority.subjects, self.request(now_ticks), message, authority.audit);
        if (!metadata.verifyFor(.document, payload)) return error.InvalidDocumentSignature;
        return metadata;
    }
};

comptime {
    if (@sizeOf(Signer) > 48 or objects.MAX_METADATA_MESSAGE_BYTES > secrets.MAX_SIGNING_MESSAGE_BYTES)
        @compileError("document signer exceeds its bounded lease or message capacity");
}

test "document signing lease preserves canonical metadata and binds its sealed key" {
    const Fixture = @import("../../tests/fixtures/document_signer.zig").Fixture;
    const signing = @import("../core/signing.zig");
    var fixture = Fixture{};
    const identity = signing.SignerIdentity{ .label = "document key", .seed = @splat(0x37) };
    const signer = try fixture.init(.{ .kind = .user, .serial = 1 }, .{ .kind = .service, .serial = 2 }, 3, identity);
    const metadata = try signer.signMetadata("notes.md", "draft", 10);
    const software = try objects.signMetadata(identity, "notes.md", "text/markdown", .document, "draft", 10);
    try std.testing.expectEqualSlices(u8, software.signature.valueSlice(), metadata.signature.valueSlice());
    try std.testing.expect(metadata.verifyFor(.document, "draft"));
    try std.testing.expect(!metadata.verifyFor(.document, "other"));
    const handle = fixture.service.findHandle(signer.handle_id).?;
    const secret = fixture.service.store.describeSecret(handle.secret_id).?;
    try std.testing.expect(!secret.resident_material and !secret.exportable);
    const excessive = [_]u8{0} ** (secrets.MAX_SIGNING_MESSAGE_BYTES + 1);
    try std.testing.expectError(error.InvalidSigningMessage, fixture.service.signMessage(&fixture.policies, fixture.authority.subjects, signer.request(10), &excessive, null));
    try std.testing.expectError(error.InvalidSigningMessage, fixture.service.signMessage(&fixture.policies, fixture.authority.subjects, signer.request(10), "", null));
    var wrong = signer;
    wrong.sealed_digest[0] ^= 1;
    try std.testing.expectError(error.SigningKeyChanged, wrong.signMetadata("notes.md", "draft", 11));
    fixture.authority.owner.serial += 1;
    try std.testing.expectError(error.SecretOwnerMismatch, signer.signMetadata("notes.md", "draft", 11));
    fixture.authority.owner.serial -= 1;
    fixture.authority.task_id += 1;
    try std.testing.expectError(error.HandleHolderMismatch, signer.signMetadata("notes.md", "draft", 11));
    fixture.authority.task_id -= 1;
    handle.expires_at_ticks = 11;
    try std.testing.expectError(error.HandleExpired, signer.signMetadata("notes.md", "draft", 11));
    handle.expires_at_ticks = 100;
    handle.revoked = true;
    try std.testing.expectError(error.HandleRevoked, signer.signMetadata("notes.md", "draft", 11));
}
