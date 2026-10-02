const std = @import("std");
const endian = @import("bytes.zig");

// A local statement from the EFI image that actually loaded the kernel. This
// is not a TPM quote, a release signer identity, or an anti-rollback counter.
pub const TAG: u32 = 0x5a474249;
pub const PAYLOAD_BYTES: usize = 80;
pub const KERNEL_HEAP_BYTES: usize = 32 * 1024 * 1024;
pub const IDENTITY_LIMIT: usize = 1024 * 1024 * 1024;
pub const Info = struct {
    firmware_authenticated: bool,
    kernel_digest: [32]u8,
    cmdline_digest: [32]u8,
    heap_base: u64,

    pub fn measure(kernel: []const u8, cmdline: []const u8, authenticated: bool, heap_base: u64) Info {
        var info: Info = .{
            .firmware_authenticated = authenticated,
            .kernel_digest = undefined,
            .cmdline_digest = undefined,
            .heap_base = heap_base,
        };
        std.crypto.hash.sha2.Sha256.hash(kernel, &info.kernel_digest, .{});
        std.crypto.hash.sha2.Sha256.hash(cmdline, &info.cmdline_digest, .{});
        return info;
    }

    pub fn encode(self: Info, bytes: *[PAYLOAD_BYTES]u8) void {
        endian.writeU32Le(bytes[0..4], 1);
        endian.writeU32Le(bytes[4..8], @intFromBool(self.firmware_authenticated));
        @memcpy(bytes[8..40], &self.kernel_digest);
        @memcpy(bytes[40..72], &self.cmdline_digest);
        endian.writeU64Le(bytes[72..80], self.heap_base);
    }

    pub fn decode(bytes: []const u8) error{InvalidImageInfo}!Info {
        if (bytes.len != PAYLOAD_BYTES or endian.readU32Le(bytes[0..4]) != 1 or
            endian.readU32Le(bytes[4..8]) > 1 or std.mem.allEqual(u8, bytes[8..40], 0) or
            std.mem.allEqual(u8, bytes[40..72], 0)) return error.InvalidImageInfo;
        const heap_base = endian.readU64Le(bytes[72..80]);
        if (heap_base < 0x100000 or heap_base % 4096 != 0 or heap_base > IDENTITY_LIMIT - KERNEL_HEAP_BYTES)
            return error.InvalidImageInfo;
        return .{
            .firmware_authenticated = endian.readU32Le(bytes[4..8]) == 1,
            .kernel_digest = bytes[8..40].*,
            .cmdline_digest = bytes[40..72].*,
            .heap_base = heap_base,
        };
    }
};

pub fn authenticatedFirmwareState(secure_boot: ?u8, setup_mode: ?u8, audit_mode: ?u8) bool {
    // SecureBoot=1 promises active image validation and excludes audit mode
    // under UEFI section 3.3. Some firmware does not publish AuditMode; reject a
    // contradictory value when present. Read errors are rejected by the caller.
    return secure_boot != null and secure_boot.? == 1 and
        setup_mode != null and setup_mode.? == 0 and (audit_mode == null or audit_mode.? == 0);
}

test "EFI authentication requires complete enforcing firmware state" {
    try std.testing.expect(authenticatedFirmwareState(1, 0, 0));
    const values = [_]?u8{ null, 0, 1, 2, 255 };
    for (values) |secure| for (values) |setup| for (values) |audit| {
        try std.testing.expectEqual(secure == 1 and setup == 0 and (audit == null or audit == 0), authenticatedFirmwareState(secure, setup, audit));
    };
}

test "EFI image info binds exact payload and rejects malformed provenance" {
    const info = Info.measure("kernel", "options", false, 0x4000000);
    var encoded: [PAYLOAD_BYTES]u8 = undefined;
    info.encode(&encoded);
    try std.testing.expectEqualDeep(info, try Info.decode(&encoded));
    try std.testing.expect(!std.mem.eql(u8, &info.kernel_digest, &Info.measure("Kernel", "options", false, 0x4000000).kernel_digest));
    try std.testing.expect(!std.mem.eql(u8, &info.cmdline_digest, &Info.measure("kernel", "Options", false, 0x4000000).cmdline_digest));
    try std.testing.expectError(error.InvalidImageInfo, Info.decode(encoded[0 .. PAYLOAD_BYTES - 1]));
    for ([_]usize{ 0, 4, 7 }) |offset| {
        var invalid = encoded;
        invalid[offset] = 2;
        try std.testing.expectError(error.InvalidImageInfo, Info.decode(&invalid));
    }
    for ([_]usize{ 8, 40 }) |offset| {
        var invalid = encoded;
        @memset(invalid[offset..][0..32], 0);
        try std.testing.expectError(error.InvalidImageInfo, Info.decode(&invalid));
    }
    for ([_]u64{ 0, 0x100001, IDENTITY_LIMIT - KERNEL_HEAP_BYTES + 4096, std.math.maxInt(u64) }) |heap_base| {
        var invalid = encoded;
        endian.writeU64Le(invalid[72..80], heap_base);
        try std.testing.expectError(error.InvalidImageInfo, Info.decode(&invalid));
    }
}
