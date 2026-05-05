const std = @import("std");
const manifest = @import("../policy/manifest.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const SignerIdentity = struct {
    label: []const u8,
    seed: [Ed25519.KeyPair.seed_length]u8,
};

pub fn publicKey(identity: SignerIdentity) ![Ed25519.PublicKey.encoded_length]u8 {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(identity.seed);
    return key_pair.public_key.toBytes();
}

pub fn sign(identity: SignerIdentity, message: []const u8) !manifest.Signature {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(identity.seed);
    const signature = try key_pair.sign(message, null);

    var result = manifest.Signature{
        .format = "ed25519",
        .signer = identity.label,
        .public_key_len = Ed25519.PublicKey.encoded_length,
        .value_len = Ed25519.Signature.encoded_length,
    };
    result.public_key = key_pair.public_key.toBytes();
    result.value = signature.toBytes();
    return result;
}

pub fn verify(signature: manifest.Signature, message: []const u8) bool {
    if (!signature.isComplete()) return false;

    const public_key = Ed25519.PublicKey.fromBytes(signature.public_key) catch return false;
    const raw_signature = Ed25519.Signature.fromBytes(signature.value);
    raw_signature.verify(message, public_key) catch return false;
    return true;
}

test "ed25519 signing produces verifiable native signatures" {
    const identity = SignerIdentity{
        .label = "zigos.test",
        .seed = [_]u8{0x11} ** Ed25519.KeyPair.seed_length,
    };
    const signature = try sign(identity, "storage-state");
    try std.testing.expect(signature.isComplete());
    try std.testing.expectEqualSlices(u8, &try publicKey(identity), signature.publicKeySlice());
    try std.testing.expect(verify(signature, "storage-state"));
    try std.testing.expect(!verify(signature, "sync-state"));
}
