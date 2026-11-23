const std = @import("std");
const image = @import("image_info.zig");
pub const log = @import("tcg_event_log.zig");

// The loader's copy of the TCG2 log, reconciled through successful
// ExitBootServices. The kernel verifies PCR 5 and PCR 11; this is not remote
// attestation.
pub const Info = extern struct {
    log_address: u64,
    log_bytes: u32,
    final_events: u32,
    pcr11: log.pcr.Digest,

    pub fn validate(self: Info) error{InvalidTpmInfo}!void {
        if (self.log_bytes == 0 or self.log_bytes > log.MAX_BYTES or self.log_address < 0x100000 or self.log_address % 4096 != 0 or
            self.final_events < 2 or self.final_events > log.MAX_FINAL_EVENTS or
            self.log_address > image.IDENTITY_LIMIT - self.log_bytes or std.mem.allEqual(u8, &self.pcr11, 0)) return error.InvalidTpmInfo;
    }
};

test "EFI TPM log handoff rejects malformed copied log receipts" {
    const info = Info{ .log_address = 0x4000000, .log_bytes = 4096, .final_events = 2, .pcr11 = @splat(7) };
    try info.validate();
    for ([_]u64{ 0, 0x100001, image.IDENTITY_LIMIT, std.math.maxInt(u64) }) |address| {
        var invalid = info;
        invalid.log_address = address;
        try std.testing.expectError(error.InvalidTpmInfo, invalid.validate());
    }
    for ([_]u32{ 0, log.MAX_BYTES + 1, std.math.maxInt(u32) }) |size| {
        var invalid = info;
        invalid.log_bytes = size;
        try std.testing.expectError(error.InvalidTpmInfo, invalid.validate());
    }
    for ([_]u32{ 0, 1, log.MAX_FINAL_EVENTS + 1, std.math.maxInt(u32) }) |count| {
        var invalid = info;
        invalid.final_events = count;
        try std.testing.expectError(error.InvalidTpmInfo, invalid.validate());
    }
    var unmeasured = info;
    unmeasured.pcr11 = @splat(0);
    try std.testing.expectError(error.InvalidTpmInfo, unmeasured.validate());
}
