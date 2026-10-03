const std = @import("std");
const principal = @import("../core/principal.zig");
const objects = @import("object_store.zig");
const secrets = @import("../platform/secure_secret_store.zig");
const sealed = @import("../services/sealed_signing_key.zig");
pub const Authority = sealed.Authority;

pub const Signer = struct {
    key: sealed.Key = .{},

    pub fn bind(authority: *const Authority, handle_id: u64, now_ticks: u64) !Signer {
        return .{ .key = try sealed.Key.bind(authority, handle_id, now_ticks) };
    }

    pub fn validate(self: Signer, now_ticks: u64) !void {
        try self.key.validate(now_ticks);
    }

    pub fn validateService(self: Signer, holder: principal.PrincipalId, task_id: u64, now_ticks: u64) !void {
        try self.key.validateService(holder, task_id, now_ticks);
    }

    pub fn signMetadata(self: Signer, path: []const u8, payload: []const u8, now_ticks: u64) !objects.SignedMetadata {
        return self.signObjectMetadata(path, "text/markdown", .document, payload, now_ticks);
    }

    pub fn signObjectMetadata(self: Signer, label: []const u8, content_type: []const u8, object_type: objects.ObjectType, payload: []const u8, now_ticks: u64) !objects.SignedMetadata {
        var metadata = try objects.SignedMetadata.init(label, content_type, .{}, now_ticks);
        var buffer: [objects.MAX_METADATA_MESSAGE_BYTES]u8 = undefined;
        const message = try metadata.signingMessage(&buffer, object_type, payload);
        metadata.signature = try self.key.signMessage(message, now_ticks);
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
    const handle = fixture.service.findHandle(signer.key.handle_id).?;
    const secret = fixture.service.store.describeSecret(handle.secret_id).?;
    try std.testing.expect(!secret.resident_material and !secret.exportable);
    const excessive = @as([secrets.MAX_SIGNING_MESSAGE_BYTES + 1]u8, @splat(0));
    try std.testing.expectError(error.InvalidSigningMessage, fixture.service.signMessage(&fixture.policies, fixture.authority.subjects, .{ .holder = fixture.authority.holder, .task_id = fixture.authority.task_id, .handle_id = signer.key.handle_id, .now_ticks = 10 }, &excessive, null));
    try std.testing.expectError(error.InvalidSigningMessage, fixture.service.signMessage(&fixture.policies, fixture.authority.subjects, .{ .holder = fixture.authority.holder, .task_id = fixture.authority.task_id, .handle_id = signer.key.handle_id, .now_ticks = 10 }, "", null));
    var wrong = signer;
    wrong.key.sealed_digest[0] ^= 1;
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
