const std = @import("std");

// A local statement from the EFI image that actually loaded the kernel. This
// is not a TPM quote, a release signer identity, or an anti-rollback counter.
pub const KERNEL_HEAP_BYTES: usize = 32 * 1024 * 1024;
pub const IDENTITY_LIMIT: usize = 1024 * 1024 * 1024;
pub const Info = extern struct {
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

    pub fn validate(self: *const Info) error{InvalidImageInfo}!void {
        if (std.mem.allEqual(u8, &self.kernel_digest, 0) or std.mem.allEqual(u8, &self.cmdline_digest, 0) or
            self.heap_base < 0x100000 or self.heap_base % 4096 != 0 or self.heap_base > IDENTITY_LIMIT - KERNEL_HEAP_BYTES)
            return error.InvalidImageInfo;
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

test "EFI image info binds exact payload and rejects malformed heap placement" {
    const info = Info.measure("kernel", "options", false, 0x4000000);
    try info.validate();
    try std.testing.expect(!std.mem.eql(u8, &info.kernel_digest, &Info.measure("Kernel", "options", false, 0x4000000).kernel_digest));
    try std.testing.expect(!std.mem.eql(u8, &info.cmdline_digest, &Info.measure("kernel", "Options", false, 0x4000000).cmdline_digest));
    for ([_]u64{ 0, 0x100001, IDENTITY_LIMIT - KERNEL_HEAP_BYTES + 4096, std.math.maxInt(u64) }) |heap_base| {
        var invalid = info;
        invalid.heap_base = heap_base;
        try std.testing.expectError(error.InvalidImageInfo, invalid.validate());
    }
}
