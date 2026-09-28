//! A random 256-bit recovery key, encoded as 56 base-32 symbols including a
//! domain-separated 24-bit typo checksum. These strings are secrets: only the
//! trusted input/export owner may retain them; never log or put them in a view.
const std = @import("std");
pub const Key = [32]u8;
pub const CODE_BYTES = 56;
pub const DISPLAY_BYTES = CODE_BYTES + CODE_BYTES / 4 - 1;
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RAW_BYTES = 35;

pub fn generate(entropy: anytype, out: *Key) !void {
    std.crypto.secureZero(u8, out);
    errdefer std.crypto.secureZero(u8, out);
    try entropy.random(out);
    try validate(out);
}

// Input normalization happens at the trusted keyboard boundary. The decoder
// accepts only the compact uppercase representation, with no ambiguous aliases.
pub fn symbol(byte: u8) ?u8 {
    const index = std.mem.indexOfScalar(u8, alphabet, byte) orelse return null;
    return @intCast(index);
}

pub fn encode(key: *const Key, out: *[CODE_BYTES]u8) !void {
    std.crypto.secureZero(u8, out);
    try validate(key);
    var raw: [RAW_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    @memcpy(raw[0..32], key);
    @memcpy(raw[32..], &checksum(key));
    for (0..RAW_BYTES / 5) |group| {
        var bits: u64 = 0;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&bits));
        for (raw[group * 5 ..][0..5]) |byte| bits = (bits << 8) | byte;
        for (0..8) |i| out[group * 8 + i] = alphabet[(bits >> @as(u6, @intCast(35 - i * 5))) & 31];
    }
}

pub fn format(key: *const Key, out: *[DISPLAY_BYTES]u8) !void {
    std.crypto.secureZero(u8, out);
    var compact: [CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &compact);
    try encode(key, &compact);
    for (0..CODE_BYTES / 4) |group| {
        if (group != 0) out[group * 5 - 1] = '-';
        @memcpy(out[group * 5 ..][0..4], compact[group * 4 ..][0..4]);
    }
}

pub fn decode(code: []const u8, out: *Key) !void {
    std.crypto.secureZero(u8, out);
    errdefer std.crypto.secureZero(u8, out);
    if (code.len != CODE_BYTES) return error.InvalidRecoveryCode;
    var raw: [RAW_BYTES]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &raw);
    for (0..CODE_BYTES / 8) |group| {
        var bits: u64 = 0;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&bits));
        for (code[group * 8 ..][0..8]) |byte| bits = (bits << 5) | (symbol(byte) orelse return error.InvalidRecoveryCode);
        for (0..5) |i| raw[group * 5 + i] = @truncate(bits >> @as(u6, @intCast(32 - i * 8)));
    }
    if (!std.crypto.timing_safe.eql([3]u8, raw[32..35].*, checksum(raw[0..32]))) return error.InvalidRecoveryCode;
    try validate(raw[0..32]);
    out.* = raw[0..32].*;
}

fn validate(key: *const Key) !void {
    if (std.mem.allEqual(u8, key, 0)) return error.InvalidRecoveryKey;
}

fn checksum(key: *const Key) [3]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update("zigos:recovery-key:v1\x00");
    hash.update(key);
    var digest = hash.finalResult();
    defer std.crypto.secureZero(u8, &digest);
    return digest[0..3].*;
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
