//! Immutable enrollment policy, signed by the sealed user root and carried by
//! the independently pinned provisioning bundle. No policy key is self-trusted.
const std = @import("std");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const policy = @import("../policy/policy_object.zig");
const manifest = @import("../policy/manifest.zig");
const sealed = @import("sealed_signing_key.zig");
const wire = @import("../platform/tpm2_wire.zig");

pub const BYTES = 8 + 8 + signing.PUBLIC_KEY_BYTES + signing.SIGNATURE_BYTES;

pub const Record = struct {
    max_session_ticks: u64,
    signature: manifest.Signature,

    fn request(self: *const Record, owner: principal.PrincipalId) !policy.CreateRequest {
        if (owner.kind != .user or owner.serial == 0 or self.max_session_ticks == 0) return error.InvalidIdentityPolicy;
        return .{
            .scope = .user,
            .subject_id = owner.serial,
            .issuer = owner,
            .label = "Enrolled identity policy v1",
            .require_hardware_backed_session = true,
            .max_session_unlock_age_ticks = self.max_session_ticks,
            .credential_assertions_allowed = true,
            .deny_credential_password_fallback = true,
            .require_phishing_resistant_credential = true,
            .require_hardware_backed_credential = true,
            .require_local_credential_unlock = true,
            .max_credential_unlock_age_ticks = self.max_session_ticks,
            .secret_vault_allowed = true,
            .require_hardware_backed_secrets = true,
            .deny_secret_raw_export = true,
            .max_secret_handle_lease_ticks = self.max_session_ticks,
        };
    }

    pub fn issue(owner: principal.PrincipalId, max_session_ticks: u64, key: sealed.Key, now: u64) !Record {
        const authority = key.authority orelse return error.SigningAuthorityUnavailable;
        if (!authority.owner.eql(owner)) return error.InvalidIdentityPolicy;
        var result = Record{ .max_session_ticks = max_session_ticks, .signature = .{} };
        result.signature = try key.signMessage(&(try policy.requestDigest(try result.request(owner))), now);
        result.signature.signer = "";
        return result;
    }

    pub fn verify(self: *const Record, owner: principal.PrincipalId, root_key: signing.PublicKey) !void {
        try policy.verifyRequest(try self.request(owner), self.signature, root_key);
    }

    pub fn attach(self: *const Record, directory: *policy.Directory, owner: principal.PrincipalId, root_key: signing.PublicKey) !void {
        _ = try directory.attachInitialAuthenticated(try self.request(owner), self.signature, root_key);
    }

    pub fn encode(self: *const Record) ![BYTES]u8 {
        if (self.max_session_ticks == 0 or self.signature.format != .ed25519 or !self.signature.isComplete()) return error.InvalidIdentityPolicy;
        var bytes: [BYTES]u8 = undefined;
        var w = wire.Writer{ .bytes = &bytes };
        try w.put("ZGIDPL01");
        try w.int(u64, self.max_session_ticks);
        try w.put(self.signature.publicKeySlice());
        try w.put(self.signature.valueSlice());
        return bytes;
    }

    pub fn decode(bytes: []const u8) !Record {
        var r = wire.Reader{ .bytes = bytes };
        if (!std.mem.eql(u8, try r.take(8), "ZGIDPL01")) return error.InvalidIdentityPolicy;
        const max_session_ticks = try r.int(u64);
        const result = Record{ .max_session_ticks = max_session_ticks, .signature = .{
            .public_key = (try r.take(signing.PUBLIC_KEY_BYTES))[0..signing.PUBLIC_KEY_BYTES].*,
            .value = (try r.take(signing.SIGNATURE_BYTES))[0..signing.SIGNATURE_BYTES].*,
            .public_key_len = signing.PUBLIC_KEY_BYTES,
            .value_len = signing.SIGNATURE_BYTES,
        } };
        try r.end();
        if (max_session_ticks == 0) return error.InvalidIdentityPolicy;
        return result;
    }
};

test "identity policy authenticates owner root and every encoded byte before attachment" {
    const owner = principal.PrincipalId{ .kind = .user, .serial = 7 };
    var fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const signer = try fixture.init(owner, .{ .kind = .service, .serial = 1 }, 1, .{ .label = "policy fixture", .seed = @splat(11) });
    const record = try Record.issue(owner, 100, signer.key, 1);
    const root = record.signature.public_key;
    try std.testing.expectError(error.SigningAuthorityUnavailable, Record.issue(owner, 100, .{}, 1));
    try std.testing.expectError(error.InvalidIdentityPolicy, Record.issue(owner, 0, signer.key, 1));
    try std.testing.expectError(error.InvalidIdentityPolicy, Record.issue(.{ .kind = .user, .serial = 8 }, 100, signer.key, 1));
    const encoded = try record.encode();
    const decoded = try Record.decode(&encoded);
    try decoded.verify(owner, root);
    try std.testing.expectEqualDeep(record, decoded);
    for (0..encoded.len) |index| {
        var changed = encoded;
        changed[index] ^= 1;
        if (Record.decode(&changed)) |forged| {
            var directory = policy.Directory.init();
            if (forged.attach(&directory, owner, root)) |_| return error.AcceptedForgedPolicy else |_| {}
            try std.testing.expectEqual(@as(usize, 0), directory.policies.countInUse());
        } else |_| {}
    }
    for (0..encoded.len) |length| {
        if (Record.decode(encoded[0..length])) |_| return error.AcceptedTruncatedPolicy else |_| {}
    }
    var extended: [BYTES + 1]u8 = @splat(0);
    @memcpy(extended[0..BYTES], &encoded);
    try std.testing.expectError(error.InvalidResponse, Record.decode(&extended));
    try std.testing.expectError(error.UntrustedPolicy, decoded.verify(owner, @splat(0)));
    try std.testing.expectError(error.UntrustedPolicy, decoded.verify(.{ .kind = .user, .serial = 8 }, root));
    var directory = policy.Directory.init();
    try decoded.attach(&directory, owner, root);
    try std.testing.expectError(error.PolicyAlreadyAttached, decoded.attach(&directory, owner, root));
    try std.testing.expectEqual(@as(usize, 1), directory.policies.countInUse());
    try std.testing.expect(directory.verify(1));
    const subjects = policy.SubjectSet{ .user_id = owner.serial };
    try std.testing.expect(directory.sessionLifetimeDecision(subjects, 100).allowed);
    try std.testing.expect(!directory.sessionLifetimeDecision(subjects, 101).allowed);
    try std.testing.expect(!directory.sessionTrustDecision(subjects, .{}).allowed);
    try std.testing.expect(directory.sessionTrustDecision(subjects, .{ .hardware_backed_credential = true }).allowed);
    try std.testing.expect(!directory.secretVaultDecision(subjects, .{ .operation = .lend, .hardware_backed = true, .lease_ticks = 101 }).allowed);
    try std.testing.expect(!directory.secretVaultDecision(subjects, .{ .operation = .export_raw, .hardware_backed = true, .raw_export = true }).allowed);
    try std.testing.expect(!directory.secretVaultDecision(subjects, .{ .operation = .import, .hardware_backed = false }).allowed);
    const assertion = policy.CredentialAssertionRequest{ .phishing_resistant = true, .hardware_backed = true, .local_unlock_verified = true, .unlock_age_ticks = 100 };
    try std.testing.expect(directory.credentialAssertionDecision(subjects, assertion).allowed);
    for (0..5) |case| {
        var denied = assertion;
        switch (case) {
            0 => denied.password_fallback = true,
            1 => denied.phishing_resistant = false,
            2 => denied.hardware_backed = false,
            3 => denied.local_unlock_verified = false,
            4 => denied.unlock_age_ticks = 101,
            else => return error.InvalidTestCase,
        }
        try std.testing.expect(!directory.credentialAssertionDecision(subjects, denied).allowed);
    }
    directory.activeForScope(.user, owner.serial).?.max_session_unlock_age_ticks += 1;
    try std.testing.expect(!directory.sessionLifetimeDecision(subjects, 1).allowed);
}
