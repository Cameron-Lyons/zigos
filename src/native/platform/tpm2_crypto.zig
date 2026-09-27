const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const P256 = std.crypto.ecc.P256;

pub const Digest = [32]u8;
pub const Error = error{ InvalidPoint, EntropyUnavailable };

// TPM Library Part 1: KDFa and KDFe, restricted here to one SHA-256 block.
pub fn kdfa(key: []const u8, label: []const u8, newer: []const u8, older: []const u8) Digest {
    var mac = Hmac.init(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    mac.update(&.{ 0, 0, 0, 1 });
    mac.update(label);
    mac.update(&.{0});
    mac.update(newer);
    mac.update(older);
    mac.update(&.{ 0, 0, 1, 0 });
    var out: Digest = undefined;
    mac.final(&out);
    return out;
}

pub fn kdfe(z: *const Digest, ephemeral_x: *const Digest, parent_x: *const Digest) Digest {
    var hash = Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update(&.{ 0, 0, 0, 1 });
    hash.update(z);
    hash.update("SECRET\x00");
    hash.update(ephemeral_x);
    hash.update(parent_x);
    return hash.finalResult();
}

pub fn authHmac(key: []const u8, parameter_hash: *const Digest, newer: *const Digest, older: *const Digest, attributes: u8) Digest {
    var mac = Hmac.init(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    mac.update(parameter_hash);
    mac.update(newer);
    mac.update(older);
    mac.update(&.{attributes});
    var out: Digest = undefined;
    mac.final(&out);
    return out;
}

// CFB-128 uses AES encryption for both directions. TPM parameter sizes need not
// be block aligned. The final partial block never reads beyond the parameter.
pub fn cfb(bytes: []u8, key_iv: *const Digest, direction: enum { encrypt, decrypt }) void {
    var aes = std.crypto.core.aes.Aes128.initEnc(key_iv[0..16].*);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&aes));
    var feedback = key_iv[16..32].*;
    defer std.crypto.secureZero(u8, &feedback);
    var stream: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &stream);
    var offset: usize = 0;
    while (offset < bytes.len) : (offset += 16) {
        aes.encrypt(&stream, &feedback);
        const count = @min(16, bytes.len - offset);
        for (0..count) |index| {
            const original = bytes[offset + index];
            bytes[offset + index] ^= stream[index];
            feedback[index] = if (direction == .encrypt) bytes[offset + index] else original;
        }
    }
}

pub const Salt = struct {
    secret: Digest,
    x: Digest,
    y: Digest,

    pub fn wipe(self: *Salt) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

// The entropy source is supplied by the kernel, never std.Io or an implicit host
// RNG. Rejection sampling is bounded; scalar multiplication uses the secret API.
pub fn makeSalt(entropy: anytype, parent_x: Digest, parent_y: Digest) !Salt {
    const parent = P256.fromSerializedAffineCoordinates(parent_x, parent_y, .big) catch return error.InvalidPoint;
    parent.rejectIdentity() catch return error.InvalidPoint;
    var scalar: Digest = undefined;
    defer std.crypto.secureZero(u8, &scalar);
    for (0..16) |_| {
        try entropy.random(&scalar);
        P256.scalar.rejectNonCanonical(scalar, .big) catch continue;
        if (std.mem.allEqual(u8, &scalar, 0)) continue;
        const ephemeral = (P256.basePoint.mul(scalar, .big) catch continue).affineCoordinates();
        var shared_point = parent.mul(scalar, .big) catch return error.InvalidPoint;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&shared_point));
        var shared = shared_point.affineCoordinates();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&shared));
        var z = shared.x.toBytes(.big);
        defer std.crypto.secureZero(u8, &z);
        const x = ephemeral.x.toBytes(.big);
        return .{ .secret = kdfe(&z, &x, &parent_x), .x = x, .y = ephemeral.y.toBytes(.big) };
    }
    return error.EntropyUnavailable;
}

test "TPM AES CFB matches NIST SP 800-38A F.3.13 including partial blocks" {
    const key_iv = std.fmt.hexToBytes;
    var material: Digest = undefined;
    _ = try key_iv(&material, "2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f");
    var plaintext: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    var ciphertext: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ciphertext, "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
    for (0..65) |length| {
        var actual = plaintext;
        cfb(actual[0..length], &material, .encrypt);
        try std.testing.expectEqualSlices(u8, ciphertext[0..length], actual[0..length]);
        try std.testing.expectEqualSlices(u8, plaintext[length..], actual[length..]);
        cfb(actual[0..length], &material, .decrypt);
        try std.testing.expectEqualSlices(u8, &plaintext, &actual);
    }
}

test "TPM salt validates the peer and bounds entropy rejection" {
    const Source = struct {
        calls: usize = 0,
        pub fn random(self: *@This(), out: []u8) !void {
            self.calls += 1;
            @memset(out, 0);
        }
    };
    var source = Source{};
    const parent = P256.basePoint.affineCoordinates();
    try std.testing.expectError(error.InvalidPoint, makeSalt(&source, @splat(0), @splat(0)));
    try std.testing.expectEqual(@as(usize, 0), source.calls);
    try std.testing.expectError(error.EntropyUnavailable, makeSalt(&source, parent.x.toBytes(.big), parent.y.toBytes(.big)));
    try std.testing.expectEqual(@as(usize, 16), source.calls);
}

test "TPM KDFs match independent SHA256 and HMAC known answers" {
    var key: Digest = undefined;
    var newer: Digest = undefined;
    var older: Digest = undefined;
    for (0..32) |i| {
        key[i] = @intCast(i);
        newer[i] = @intCast(i + 32);
        older[i] = @intCast(i + 64);
    }
    var expected: Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0e910bfdca487340700b56f80f725785fc10ae9b0fc45c7bd79d2dc606187153");
    try std.testing.expectEqual(expected, kdfa(&key, "ATH", &newer, &older));
    _ = try std.fmt.hexToBytes(&expected, "62cf85ca3599cd915a71a6330c3885f986918e12037ba2e39578f72686417cdb");
    try std.testing.expectEqual(expected, kdfe(&key, &newer, &older));
}
