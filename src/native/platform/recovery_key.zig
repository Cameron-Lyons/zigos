//! A random 256-bit recovery key, encoded as 56 base-32 symbols including a
//! domain-separated 24-bit typo checksum. These strings are secrets: only the
//! trusted input/export owner may retain them; never log or put them in a view.
const std = @import("std");
pub const Key = [32]u8;
const base32 = @import("recovery_code.zig");
const Codec = base32.Codec(32, "zigos:recovery-key:v1\x00");
pub const CODE_BYTES = Codec.CODE_BYTES;
pub const DISPLAY_BYTES = Codec.DISPLAY_BYTES;
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn generate(entropy: anytype, out: *Key) !void {
    std.crypto.secureZero(u8, out);
    errdefer std.crypto.secureZero(u8, out);
    try entropy.random(out);
    try validate(out);
}

// Input normalization happens at the trusted keyboard boundary. The decoder
// accepts only the compact uppercase representation, with no ambiguous aliases.
pub const symbol = base32.symbol;

pub fn encode(key: *const Key, out: *[CODE_BYTES]u8) !void {
    std.crypto.secureZero(u8, out);
    try validate(key);
    Codec.encode(key, out);
}

pub fn format(key: *const Key, out: *[DISPLAY_BYTES]u8) !void {
    std.crypto.secureZero(u8, out);
    var compact: [CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &compact);
    try encode(key, &compact);
    Codec.format(&compact, out);
}

pub fn decode(value: []const u8, out: *Key) !void {
    std.crypto.secureZero(u8, out);
    errdefer std.crypto.secureZero(u8, out);
    try Codec.decode(value, out);
    try validate(out);
}

fn validate(key: *const Key) !void {
    if (std.mem.allEqual(u8, key, 0)) return error.InvalidRecoveryKey;
}

test "recovery key code roundtrips all key bytes and rejects altered or noncanonical codes" {
    var key: Key = undefined;
    defer std.crypto.secureZero(u8, &key);
    var code: [CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    var out: Key = undefined;
    defer std.crypto.secureZero(u8, &out);
    for (1..256) |byte| {
        @memset(&key, @intCast(byte));
        try encode(&key, &code);
        try decode(&code, &out);
        try std.testing.expectEqual(key, out);
    }
    for (&key, 0..) |*byte, i| byte.* = @intCast(i);
    try encode(&key, &code);
    try std.testing.expectEqualStrings("000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFYVD0F", &code);
    try decode(&code, &out);
    try std.testing.expectEqual(key, out);
    for (0..CODE_BYTES) |i| {
        const original = code[i];
        for (alphabet) |replacement| {
            if (replacement == original) continue;
            code[i] = replacement;
            try std.testing.expectError(error.InvalidRecoveryCode, decode(&code, &out));
            try std.testing.expectEqual(@as(Key, @splat(0)), out);
        }
        code[i] = original;
    }
    for (0..CODE_BYTES) |length| try std.testing.expectError(error.InvalidRecoveryCode, decode(code[0..length], &out));
    var display: [DISPLAY_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &display);
    try format(&key, &display);
    for (0..CODE_BYTES / 4) |group| {
        if (group != 0) try std.testing.expectEqual(@as(u8, '-'), display[group * 5 - 1]);
        try std.testing.expectEqualSlices(u8, code[group * 4 ..][0..4], display[group * 5 ..][0..4]);
    }
    try std.testing.expectError(error.InvalidRecoveryCode, decode(&display, &out));
    for ("ILOUilou- \x00") |bad| {
        code[0] = bad;
        try std.testing.expectError(error.InvalidRecoveryCode, decode(&code, &out));
        try std.testing.expectEqual(@as(Key, @splat(0)), out);
    }
}

test "recovery key generation erases partial entropy failure and rejects a zero key" {
    const Entropy = struct {
        fail: bool = false,
        byte: u8 = 7,
        pub fn random(self: *@This(), out: []u8) !void {
            @memset(out, self.byte);
            if (self.fail) return error.NoEntropy;
        }
    };
    var entropy = Entropy{};
    var key: Key = undefined;
    defer std.crypto.secureZero(u8, &key);
    try generate(&entropy, &key);
    try std.testing.expectEqual(@as(Key, @splat(7)), key);
    entropy.fail = true;
    try std.testing.expectError(error.NoEntropy, generate(&entropy, &key));
    try std.testing.expectEqual(@as(Key, @splat(0)), key);
    entropy = .{ .byte = 0 };
    try std.testing.expectError(error.InvalidRecoveryKey, generate(&entropy, &key));
    var code: [CODE_BYTES]u8 = @splat(0xaa);
    try std.testing.expectError(error.InvalidRecoveryKey, encode(&key, &code));
    try std.testing.expect(std.mem.allEqual(u8, &code, 0));
}
