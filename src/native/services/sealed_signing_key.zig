//! A service-owned lease for a non-exportable sealed signing key.
const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const principal = @import("../core/principal.zig");
const policy = @import("../policy/policy_object.zig");
const vault = @import("secret_vault_service.zig");
const secrets = @import("../platform/secure_secret_store.zig");
const ledger = @import("../platform/event_ledger.zig");
const signing = @import("../core/signing.zig");
const manifest = @import("../policy/manifest.zig");

pub const Error = vault.Error || error{ SigningAuthorityUnavailable, InvalidSigningAuthority, SealedSigningKeyRequired, SigningKeyChanged };

// Session-owned, stable for the lifetime of every dependent storage operation.
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

pub const Key = struct {
    authority: ?*const Authority = null,
    handle_id: u64 = 0,
    sealed_digest: crypto_hash.Digest = @splat(0),

    pub fn bind(authority: *const Authority, handle_id: u64, now_ticks: u64) Error!Key {
        var signer = Key{ .authority = authority, .handle_id = handle_id };
        signer.sealed_digest = (try signer.secret(now_ticks)).sealed_digest;
        return signer;
    }

    fn request(self: Key, now_ticks: u64) vault.SigningAuthority {
        const authority = self.authority.?;
        return .{ .holder = authority.holder, .task_id = authority.task_id, .handle_id = self.handle_id, .now_ticks = now_ticks };
    }

    fn secret(self: Key, now_ticks: u64) Error!*const secrets.SecretRecord {
        const authority = self.authority orelse return error.SigningAuthorityUnavailable;
        if (authority.holder.kind != .service or authority.task_id == 0) return error.InvalidSigningAuthority;
        const handle = try authority.service.requireSigningHandle(authority.policies, authority.subjects, self.request(now_ticks));
        const record = authority.service.store.describeSecret(handle.secret_id) orelse return error.SecretNotFound;
        if (!record.owner.eql(authority.owner)) return error.SecretOwnerMismatch;
        if (!record.hardware_backed or !record.hardware_provider_used or !record.sealed_digest_present or
            record.exportable or record.resident_material or record.sealedBlob() == null) return error.SealedSigningKeyRequired;
        return record;
    }

    pub fn validate(self: Key, now_ticks: u64) Error!void {
        const record = try self.secret(now_ticks);
        if (!std.mem.eql(u8, &record.sealed_digest, &self.sealed_digest)) return error.SigningKeyChanged;
    }

    pub fn validateService(self: Key, holder: principal.PrincipalId, task_id: u64, now_ticks: u64) Error!void {
        const authority = self.authority orelse return error.SigningAuthorityUnavailable;
        if (!authority.holder.eql(holder) or authority.task_id != task_id) return error.HandleHolderMismatch;
        try self.validate(now_ticks);
    }

    pub fn label(self: Key, now_ticks: u64) Error![]const u8 {
        try self.validate(now_ticks);
        return (try self.secret(now_ticks)).labelSlice();
    }

    pub fn signMessage(self: Key, message: []const u8, now_ticks: u64) Error!manifest.Signature {
        try self.validate(now_ticks);
        const authority = self.authority.?;
        const signature = try authority.service.signMessage(authority.policies, authority.subjects, self.request(now_ticks), message, authority.audit);
        if (!signing.verify(signature, message)) return error.InvalidSigningKey;
        return signature;
    }

    pub fn publicKey(self: Key, now_ticks: u64) Error!signing.PublicKey {
        return (try self.signMessage("zigos.sealed-key.public.v1", now_ticks)).public_key;
    }
};

comptime {
    if (@sizeOf(Key) > 48) @compileError("sealed signing lease exceeds its bounded state");
}
