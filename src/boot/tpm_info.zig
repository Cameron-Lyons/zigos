const std = @import("std");
const image = @import("image_info.zig");
pub const log = @import("tcg_event_log.zig");
pub const TAG: u32 = 0x5a475450;
pub const PAYLOAD_BYTES = 56;

// The copied log ends at the loader's measurement, before ExitBootServices.
// No final-log or attestation claim can be inferred from this handoff alone.
pub const Info = struct {
    log_address: u64,
    log_bytes: u32,
    pcr11: log.pcr.Digest,

    pub fn encode(self: Info, out: *[PAYLOAD_BYTES]u8) void {
        @memset(out, 0);
        std.mem.writeInt(u32, out[0..4], 1, .little);
        std.mem.writeInt(u32, out[4..8], 1, .little); // pre-ExitBootServices scope
        std.mem.writeInt(u64, out[8..16], self.log_address, .little);
        std.mem.writeInt(u32, out[16..20], self.log_bytes, .little);
        @memcpy(out[24..56], &self.pcr11);
    }

    pub fn decode(bytes: []const u8) error{InvalidTpmInfo}!Info {
        if (bytes.len != PAYLOAD_BYTES or std.mem.readInt(u32, bytes[0..4], .little) != 1 or
            std.mem.readInt(u32, bytes[4..8], .little) != 1 or !std.mem.allEqual(u8, bytes[20..24], 0)) return error.InvalidTpmInfo;
        const address = std.mem.readInt(u64, bytes[8..16], .little);
        const size = std.mem.readInt(u32, bytes[16..20], .little);
        if (size == 0 or size > log.MAX_BYTES or address < 0x100000 or address % 4096 != 0 or
            address > image.IDENTITY_LIMIT - size or std.mem.allEqual(u8, bytes[24..56], 0)) return error.InvalidTpmInfo;
        return .{ .log_address = address, .log_bytes = size, .pcr11 = bytes[24..56].* };
    }
};

test "TPM boot handoff bounds the copied log and rejects unsupported capture scopes" {
    const info = Info{ .log_address = 0x4000000, .log_bytes = 4096, .pcr11 = @splat(7) };
    var bytes: [PAYLOAD_BYTES]u8 = undefined;
    info.encode(&bytes);
    try std.testing.expectEqualDeep(info, try Info.decode(&bytes));
    for ([_]usize{ 0, 4, 20, 23 }) |offset| {
        var invalid = bytes;
        invalid[offset] = 2;
        try std.testing.expectError(error.InvalidTpmInfo, Info.decode(&invalid));
    }
    for ([_]u64{ 0, 0x100001, image.IDENTITY_LIMIT, std.math.maxInt(u64) }) |address| {
        var invalid = bytes;
        std.mem.writeInt(u64, invalid[8..16], address, .little);
        try std.testing.expectError(error.InvalidTpmInfo, Info.decode(&invalid));
    }
    for ([_]u32{ 0, log.MAX_BYTES + 1, std.math.maxInt(u32) }) |size| {
        var invalid = bytes;
        std.mem.writeInt(u32, invalid[16..20], size, .little);
        try std.testing.expectError(error.InvalidTpmInfo, Info.decode(&invalid));
    }
}
