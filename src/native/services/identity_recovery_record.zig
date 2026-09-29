//! Privately retained setup/recovery record. The enrollment pin travels with
//! the random recovery key, so restoring it does not trust a hash on the disk.
//! Only a native export/input owner may display or retain this secret record.
const std = @import("std");
const provisioning = @import("identity_provisioning.zig");
const tpm = @import("../platform/tpm2_sealing.zig");
const code = @import("../platform/recovery_code.zig");
const Codec = code.Codec(77, "zigos:identity-recovery-record:v1\x00");
pub const CODE_BYTES = Codec.CODE_BYTES;
pub const DISPLAY_BYTES = Codec.DISPLAY_BYTES;
pub const symbol = code.symbol;

pub const Record = struct {
    trusted: provisioning.Pin = .{ .object_id = 0, .digest = @splat(0) },
    key: tpm.Key = @splat(0),

    pub fn erase(self: *Record) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn validate(self: *const Record) !void {
        if (self.trusted.object_id == 0 or std.mem.allEqual(u8, &self.trusted.digest, 0) or std.mem.allEqual(u8, &self.key, 0)) return error.InvalidRecoveryRecord;
    }

    pub fn encode(self: *const Record, out: *[CODE_BYTES]u8) !void {
        std.crypto.secureZero(u8, out);
        try self.validate();
        var payload: [77]u8 = undefined;
        defer std.crypto.secureZero(u8, &payload);
        @memcpy(payload[0..5], "ZGRC1");
        std.mem.writeInt(u64, payload[5..13], self.trusted.object_id, .big);
        @memcpy(payload[13..45], &self.trusted.digest);
        @memcpy(payload[45..77], &self.key);
        Codec.encode(&payload, out);
    }

    pub fn format(self: *const Record, out: *[DISPLAY_BYTES]u8) !void {
        std.crypto.secureZero(u8, out);
        var compact: [CODE_BYTES]u8 = undefined;
        defer std.crypto.secureZero(u8, &compact);
        try self.encode(&compact);
        Codec.format(&compact, out);
    }

    pub fn decode(value: []const u8, out: *Record) !void {
        out.erase();
        errdefer out.erase();
        var payload: [77]u8 = undefined;
        defer std.crypto.secureZero(u8, &payload);
        try Codec.decode(value, &payload);
        if (!std.mem.eql(u8, payload[0..5], "ZGRC1")) return error.InvalidRecoveryRecord;
        out.* = .{ .trusted = .{ .object_id = std.mem.readInt(u64, payload[5..13], .big), .digest = payload[13..45].* }, .key = payload[45..77].* };
        try out.validate();
    }
};

test "identity recovery record retains an independent pin and erases invalid input" {
    var record = Record{ .trusted = .{ .object_id = 0x0102_0304_0506_0708, .digest = @splat(8) }, .key = @splat(9) };
    defer record.erase();
    var encoded: [CODE_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    var decoded = Record{};
    defer decoded.erase();
    try record.encode(&encoded);
    try Record.decode(&encoded, &decoded);
    try std.testing.expectEqualDeep(record, decoded);
    for (0..CODE_BYTES) |i| {
        const previous = encoded[i];
        encoded[i] = if (previous == '0') '1' else '0';
        try std.testing.expectError(error.InvalidRecoveryCode, Record.decode(&encoded, &decoded));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&decoded), 0));
        encoded[i] = previous;
        try std.testing.expectError(error.InvalidRecoveryCode, Record.decode(encoded[0..i], &decoded));
    }
    var grouped: [DISPLAY_BYTES]u8 = undefined;
    defer std.crypto.secureZero(u8, &grouped);
    try record.format(&grouped);
    try std.testing.expectError(error.InvalidRecoveryCode, Record.decode(&grouped, &decoded));
    record.trusted.digest = @splat(0);
    try std.testing.expectError(error.InvalidRecoveryRecord, record.encode(&encoded));
    try std.testing.expect(std.mem.allEqual(u8, &encoded, 0));
}
