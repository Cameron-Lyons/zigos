//! Read-only TPM2 PCR_Read with an exact SHA-256 PCR selection.
const std = @import("std");
pub const INDEX = 11;
pub const SHA256: u16 = 0x000b;
pub const Digest = [32]u8;
pub const RESPONSE_BYTES = 62;
pub const Error = error{ InvalidPcrResponse, TpmPcrReadFailed };

pub fn command(comptime index: u5) [20]u8 {
    if (index > 23) @compileError("invalid static PCR selection");
    var result = [_]u8{ 0x80, 1, 0, 0, 0, 20, 0, 0, 1, 0x7e, 0, 0, 0, 1, 0, SHA256, 3, 0, 0, 0 };
    result[17 + index / 8] = @as(u8, 1) << @as(u3, @intCast(index % 8));
    return result;
}

pub fn parse(comptime index: u5, bytes: []const u8) Error!Digest {
    if (bytes.len < 10 or std.mem.readInt(u16, bytes[0..2], .big) != 0x8001 or
        std.mem.readInt(u32, bytes[2..6], .big) != bytes.len) return error.InvalidPcrResponse;
    if (std.mem.readInt(u32, bytes[6..10], .big) != 0) return error.TpmPcrReadFailed;
    // Counter, exactly one selection, exactly the requested SHA-256 PCR, and
    // exactly one 32-byte digest. Never accept a substituted or partial bank.
    const request = command(index);
    if (bytes.len != RESPONSE_BYTES or std.mem.readInt(u32, bytes[14..18], .big) != 1 or
        !std.mem.eql(u8, bytes[18..24], request[14..20]) or
        std.mem.readInt(u32, bytes[24..28], .big) != 1 or std.mem.readInt(u16, bytes[28..30], .big) != 32)
        return error.InvalidPcrResponse;
    return bytes[30..62].*;
}

pub fn extend(previous: Digest, digest: Digest) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&previous);
    hash.update(&digest);
    return hash.finalResult();
}

test "PCR read rejects substituted banks, extra selections and malformed replies" {
    var bytes: [RESPONSE_BYTES]u8 = @splat(0);
    @memcpy(bytes[0..10], &[_]u8{ 0x80, 1, 0, 0, 0, RESPONSE_BYTES, 0, 0, 0, 0 });
    bytes[17] = 1;
    @memcpy(bytes[18..30], &[_]u8{ 0, SHA256, 3, 0, 8, 0, 0, 0, 0, 1, 0, 32 });
    @memset(bytes[30..], 0x47);
    try std.testing.expectEqual(@as(Digest, @splat(0x47)), try parse(INDEX, &bytes));
    try std.testing.expectError(error.InvalidPcrResponse, parse(5, &bytes));
    for (0..RESPONSE_BYTES) |length| {
        if (parse(INDEX, bytes[0..length])) |_| return error.AcceptedTruncatedPcr else |_| {}
    }
    for ([_]usize{ 0, 1, 2, 5, 6, 9, 14, 17, 18, 19, 20, 21, 22, 23, 24, 27, 28, 29 }) |offset| {
        var changed = bytes;
        changed[offset] ^= 1;
        if (parse(INDEX, &changed)) |_| return error.AcceptedMalformedPcr else |_| {}
    }
    const extra = bytes ++ [_]u8{0};
    try std.testing.expectError(error.InvalidPcrResponse, parse(INDEX, &extra));
    const requested = command(5);
    @memcpy(bytes[18..24], requested[14..20]);
    try std.testing.expectEqual(@as(Digest, @splat(0x47)), try parse(5, &bytes));
    try std.testing.expectError(error.InvalidPcrResponse, parse(INDEX, &bytes));
}
