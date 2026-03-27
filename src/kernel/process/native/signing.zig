const builtin = @import("builtin");
const std = @import("std");
const manifest = @import("manifest.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const SignerIdentity = struct {
    label: []const u8,
    seed: [Ed25519.KeyPair.seed_length]u8,
};

pub fn sign(identity: SignerIdentity, message: []const u8) !manifest.Signature {
    if (builtin.target.os.tag == .freestanding) {
        return bootstrapSign(identity, message);
    }

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
    if (builtin.target.os.tag == .freestanding) {
        return bootstrapVerify(signature, message);
    }

    const public_key = Ed25519.PublicKey.fromBytes(signature.public_key) catch return false;
    const raw_signature = Ed25519.Signature.fromBytes(signature.value);
    raw_signature.verify(message, public_key) catch return false;
    return true;
}

fn bootstrapSign(identity: SignerIdentity, message: []const u8) manifest.Signature {
    var result = manifest.Signature{
        .format = "ed25519",
        .signer = identity.label,
        .public_key_len = 32,
        .value_len = 64,
    };
    result.public_key = bootstrapDigest(4, &identity.seed, identity.label, "");
    result.value = bootstrapDigest(8, &result.public_key, identity.label, message);
    return result;
}

fn bootstrapVerify(signature: manifest.Signature, message: []const u8) bool {
    const expected = bootstrapDigest(8, &signature.public_key, signature.signer, message);
    return std.mem.eql(u8, &expected, &signature.value);
}

fn bootstrapDigest(
    comptime word_count: usize,
    seed_bytes: []const u8,
    signer: []const u8,
    message: []const u8,
) [word_count * @sizeOf(u64)]u8 {
    var digest = [_]u8{0} ** (word_count * @sizeOf(u64));
    const seeds = [_]u64{
        0xCBF29CE484222325,
        0x9E3779B185EBCA87,
        0xD6E8FEB86659FD93,
        0x94D049BB133111EB,
        0x2545F4914F6CDD1D,
        0x369DEA0F31A53F85,
        0x27BB2EE687B0B0FD,
        0xA0761D6478BD642F,
    };
    inline for (0..word_count) |index| {
        var hash = seeds[index];
        hash = hashBytes(hash, seed_bytes);
        hash = hashBytes(hash, signer);
        hash = hashBytes(hash, message);
        std.mem.writeInt(u64, digest[index * 8 ..][0..8], hash, .little);
    }
    return digest;
}

fn hashBytes(start: u64, bytes: []const u8) u64 {
    var hash = start;
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return hash;
}

test "ed25519 signing produces verifiable native signatures" {
    const identity = SignerIdentity{
        .label = "zigos.test",
        .seed = [_]u8{0x11} ** Ed25519.KeyPair.seed_length,
    };
    const signature = try sign(identity, "phase4");
    try std.testing.expect(signature.isComplete());
    try std.testing.expect(verify(signature, "phase4"));
    try std.testing.expect(!verify(signature, "phase5"));
}
