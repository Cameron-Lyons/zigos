//! Canonical base-32 text for private recovery material. The checksum detects
//! typing mistakes; authority always comes from the decoded key or pinned data.
const std = @import("std");
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn symbol(byte: u8) ?u8 {
    const index = std.mem.indexOfScalar(u8, alphabet, byte) orelse return null;
    return @intCast(index);
}

pub fn Codec(comptime payload_bytes: usize, comptime domain: []const u8) type {
    return struct {
        const RAW_BYTES = payload_bytes + 3;
        pub const CODE_BYTES = RAW_BYTES / 5 * 8;
        pub const DISPLAY_BYTES = CODE_BYTES + CODE_BYTES / 4 - 1;
        comptime {
            if (payload_bytes == 0 or RAW_BYTES % 5 != 0) @compileError("recovery payload must fill base-32 groups");
        }

        pub fn encode(payload: *const [payload_bytes]u8, out: *[CODE_BYTES]u8) void {
            var raw: [RAW_BYTES]u8 = undefined;
            defer std.crypto.secureZero(u8, &raw);
            @memcpy(raw[0..payload_bytes], payload);
            @memcpy(raw[payload_bytes..], &checksum(payload));
            for (0..RAW_BYTES / 5) |group| {
                var bits: u64 = 0;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&bits));
                for (raw[group * 5 ..][0..5]) |byte| bits = (bits << 8) | byte;
                for (0..8) |i| out[group * 8 + i] = alphabet[(bits >> @as(u6, @intCast(35 - i * 5))) & 31];
            }
        }

        pub fn format(code: *const [CODE_BYTES]u8, out: *[DISPLAY_BYTES]u8) void {
            for (0..CODE_BYTES / 4) |group| {
                if (group != 0) out[group * 5 - 1] = '-';
                @memcpy(out[group * 5 ..][0..4], code[group * 4 ..][0..4]);
            }
        }

        pub fn decode(code: []const u8, out: *[payload_bytes]u8) !void {
            std.crypto.secureZero(u8, out);
            if (code.len != CODE_BYTES) return error.InvalidRecoveryCode;
            var raw: [RAW_BYTES]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &raw);
            for (0..CODE_BYTES / 8) |group| {
                var bits: u64 = 0;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&bits));
                for (code[group * 8 ..][0..8]) |byte| bits = (bits << 5) | (symbol(byte) orelse return error.InvalidRecoveryCode);
                for (0..5) |i| raw[group * 5 + i] = @truncate(bits >> @as(u6, @intCast(32 - i * 8)));
            }
            if (!std.crypto.timing_safe.eql([3]u8, raw[payload_bytes..].*, checksum(raw[0..payload_bytes]))) return error.InvalidRecoveryCode;
            out.* = raw[0..payload_bytes].*;
        }

        fn checksum(payload: *const [payload_bytes]u8) [3]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
            hash.update(domain);
            hash.update(payload);
            var digest = hash.finalResult();
            defer std.crypto.secureZero(u8, &digest);
            return digest[0..3].*;
        }
    };
}
