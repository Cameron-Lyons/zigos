//! Compiled only into the verification service-client image. Real applications
//! choose their relying-party challenge and use identity_client directly.
const std = @import("std");
const sdk = @import("identity_client.zig");

pub fn challenge(binding: sdk.protocol.Binding) [32]u8 {
    var bytes: [24]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], binding.endpoint_capability_id, .little);
    std.mem.writeInt(u64, bytes[8..16], binding.service_endpoint_id, .little);
    std.mem.writeInt(u64, bytes[16..24], binding.credential_id, .little);
    var digest: [32]u8 = undefined;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    // Domain separation also gives the production loaded-byte role gate a
    // positive control for this verification-only userspace workload.
    hash.update("zigos.identity.client-proof.v1");
    hash.update(&bytes);
    hash.final(&digest);
    return digest;
}

pub fn receipt(bytes: []const u8) u64 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.mem.readInt(u64, digest[0..8], .little);
}

pub const Probe = struct {
    client: sdk.Client = .{},
    observed: u64 = 0,
    pub fn step(self: *Probe, mailbox: anytype, transport: anytype) bool {
        const supplied = mailbox.identityBinding();
        if (!supplied.isValid()) return false;
        defer std.mem.writeInt(u64, mailbox.ui_text_digest[0..8], self.observed, .little);
        if (self.observed != supplied.endpoint_capability_id and !self.client.pending()) {
            const binding = sdk.protocol.Binding{ .endpoint_capability_id = supplied.endpoint_capability_id, .service_endpoint_id = supplied.service_endpoint_id, .credential_id = supplied.credential_id };
            self.observed = binding.endpoint_capability_id;
            mailbox.ui_commit_count = 0;
            mailbox.ui_interaction_hash = 0;
            self.client.begin(binding, binding.endpoint_capability_id, &challenge(binding)) catch {
                mailbox.ui_commit_count = 2;
                return true;
            };
        }
        const progress = self.client.step(transport);
        if (self.client.phase == .failed) {
            mailbox.ui_interaction_hash = @intFromEnum(self.client.failure.?);
            mailbox.ui_commit_count = 2;
        }
        if (self.client.result() != null) {
            mailbox.ui_interaction_hash = receipt(self.client.bytes[0..self.client.total]);
            mailbox.ui_commit_count = 1;
        }
        return progress;
    }
};
