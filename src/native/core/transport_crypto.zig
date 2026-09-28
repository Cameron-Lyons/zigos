//! Bounded authenticated transport encryption using the pinned Zig primitives.
//! XChaCha20-Poly1305 permits fresh random 192-bit nonces for each packet.
//! https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
const std = @import("std");
const builtin = @import("builtin");
const hash = @import("crypto_hash.zig");
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
pub const Key = [Aead.key_length]u8;
pub const AUTH_BYTES = Aead.nonce_length + Aead.tag_length;
pub const Authentication = [AUTH_BYTES]u8;
pub const MAX_BYTES = 256;
pub const Error = error{ EntropyUnavailable, AuthenticationFailed, InvalidLength };

const Random = struct {
    fn fill(_: Random, out: []u8) Error!void {
        if (builtin.target.os.tag == .freestanding) {
            @import("../../kernel/platform/secure_random.zig").fill(out) catch return error.EntropyUnavailable;
        } else {
            const io = if (builtin.is_test) std.testing.io else std.Io.Threaded.global_single_threaded.io();
            io.randomSecure(out) catch return error.EntropyUnavailable;
        }
    }
};

// Public metadata is a KDF context, never the secret input. These keys are local
// session secrets; sharing them with a remote peer requires an authenticated
// key-establishment protocol, which this primitive does not claim to provide.
pub fn freshKey(context: hash.Digest) Error!Key {
    var secret: Key = undefined;
    defer std.crypto.secureZero(u8, &secret);
    try (Random{}).fill(&secret);
    return std.crypto.kdf.hkdf.HkdfSha256.extract(&context, &secret);
}

pub fn seal(out: []u8, plaintext: []const u8, key: Key, context: []const u8) Error!Authentication {
    return sealUsing(Random{}, out, plaintext, key, context);
}

fn sealUsing(random: anytype, out: []u8, plaintext: []const u8, key: Key, context: []const u8) Error!Authentication {
    if (out.len != plaintext.len or out.len > MAX_BYTES) return error.InvalidLength;
    errdefer std.crypto.secureZero(u8, out);
    var auth: Authentication = undefined;
    errdefer std.crypto.secureZero(u8, &auth);
    try random.fill(auth[0..Aead.nonce_length]);
    Aead.encrypt(out, auth[Aead.nonce_length..], plaintext, context, auth[0..Aead.nonce_length].*, key);
    return auth;
}

pub fn open(out: []u8, ciphertext: []const u8, auth: Authentication, key: Key, context: []const u8) Error!void {
    if (out.len != ciphertext.len or out.len > MAX_BYTES) return error.InvalidLength;
    errdefer std.crypto.secureZero(u8, out);
    Aead.decrypt(out, ciphertext, auth[Aead.nonce_length..].*, context, auth[0..Aead.nonce_length].*, key) catch return error.AuthenticationFailed;
}

// Authenticate the complete native wire header, including sequence and task
// routing, under a separate MAC key derived from the session secret.
pub fn wireMac(key: Key, bytes: []const u8) hash.Digest {
    var mac_key: Key = undefined;
    defer std.crypto.secureZero(u8, &mac_key);
    Hmac.create(&mac_key, "zigos.native-sync.wire.v4", &key);
    var result: hash.Digest = undefined;
    Hmac.create(&result, bytes, &mac_key);
    return result;
}

pub fn verifyWireMac(key: Key, bytes: []const u8, expected: hash.Digest) bool {
    const actual = wireMac(key, bytes);
    return std.crypto.timing_safe.eql(hash.Digest, actual, expected);
}

test "transport AEAD matches the pinned XChaCha vector and erases rejected plaintext" {
    const Fixed = struct {
        fn fill(_: @This(), out: []u8) Error!void {
            @memset(out, 42);
        }
    };
    const message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var ciphertext: [message.len]u8 = undefined;
    const key: Key = @splat(69);
    const auth = try sealUsing(Fixed{}, &ciphertext, message, key, "Additional data");
    const expected = "994d2dd32333f48e53650c02c7a2abb8e018b0836d7175aec779f52e961780768f815c58f1aa52d211498db89b9216763f569c9433a6bbfcefb4d4a49387a4c5207fbb3b5a92b5941294df30588c6740d39dc16fa1f0e634f7246cf7cdcb978e44347d89381b7a74eb7084f754b90bde9aaf5a94b8f2a85efd0b50692ae2d425e234";
    var sealed: [message.len + 16]u8 = undefined;
    @memcpy(sealed[0..message.len], &ciphertext);
    @memcpy(sealed[message.len..], auth[24..]);
    try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(sealed, .lower));
    var output: [message.len]u8 = undefined;
    try open(&output, &ciphertext, auth, key, "Additional data");
    try std.testing.expectEqualStrings(message, &output);
    for (0..AUTH_BYTES) |index| {
        var changed = auth;
        changed[index] ^= 1;
        @memset(&output, 0xa5);
        try std.testing.expectError(error.AuthenticationFailed, open(&output, &ciphertext, changed, key, "Additional data"));
        try std.testing.expect(std.mem.allEqual(u8, &output, 0));
    }
    try std.testing.expectError(error.AuthenticationFailed, open(&output, &ciphertext, auth, key, "wrong context"));
    try std.testing.expect(std.mem.allEqual(u8, &output, 0));
    ciphertext[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, open(&output, &ciphertext, auth, key, "Additional data"));
}

test "transport AEAD uses fresh secrets and nonces and fails closed without entropy" {
    const context: hash.Digest = @splat(7);
    const first = try freshKey(context);
    const second = try freshKey(context);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    const message: [64]u8 = @splat(0);
    const auth_a = try seal(&a, &message, first, &context);
    const auth_b = try seal(&b, &message, first, &context);
    try std.testing.expect(!std.mem.eql(u8, auth_a[0..24], auth_b[0..24]));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    try std.testing.expectError(error.AuthenticationFailed, open(&b, &a, auth_a, second, &context));
    const Broken = struct {
        fn fill(_: @This(), out: []u8) Error!void {
            @memset(out, 0xa5);
            return error.EntropyUnavailable;
        }
    };
    @memset(&a, 0xa5);
    try std.testing.expectError(error.EntropyUnavailable, sealUsing(Broken{}, &a, &message, first, &context));
    try std.testing.expect(std.mem.allEqual(u8, &a, 0));
    const mac = wireMac(first, "header and ciphertext");
    try std.testing.expect(verifyWireMac(first, "header and ciphertext", mac));
    try std.testing.expect(!verifyWireMac(first, "other routing", mac));
}
