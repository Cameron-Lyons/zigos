const sealing = @import("../../native/platform/secret_sealing.zig");

// Public deterministic software fixture for host tests, verification kernels,
// and microbenchmarks. This is not a hardware provider or a production fallback.
const key: [32]u8 = @splat(0x51);
pub fn provider() sealing.Provider {
    return .{ .operations = &.{ .seal = seal, .open = open } };
}

pub fn maximumEnvelopeProvider() sealing.Provider {
    return .{ .operations = &.{ .seal = sealMaximumEnvelope, .open = open } };
}

fn sealMaximumEnvelope(_: ?*anyopaque, binding: *const sealing.Binding, raw: []const u8, out: *sealing.Blob) sealing.Error!void {
    // Fill the wrapped-key capacity to exercise multi-page ciphertext catalogs.
    const wrapped = [_]u8{0x55} ** @import("../../native/platform/tpm2_sealing.zig").MAX_BLOB_BYTES;
    try sealing.encrypt(raw, &key, @splat(0x26), binding, &wrapped, out);
}
fn seal(_: ?*anyopaque, binding: *const sealing.Binding, raw: []const u8, out: *sealing.Blob) sealing.Error!void {
    try sealing.encrypt(raw, &key, @splat(0x26), binding, "verification-only", out);
}
fn open(_: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
    return (try sealing.Envelope.parse(blob)).open(&key, binding, out);
}

// Explicit stateful generation fixture. Its public deterministic seeds must
// never be used for a production identity; each instance belongs to one test.
pub const KeyGenerator = struct {
    calls: u8 = 0,
    result: enum { valid, fail, empty, oversized, malformed, wrong_size } = .valid,

    pub fn provider(self: *KeyGenerator) sealing.Provider {
        return .{ .context = self, .operations = &.{ .seal = seal, .open = open, .generateSigningKey = generate } };
    }

    fn generate(context: ?*anyopaque, binding: *const sealing.Binding, out: *sealing.Blob) sealing.Error!void {
        const self: *KeyGenerator = @ptrCast(@alignCast(context orelse return error.HardwareProviderUnavailable));
        self.calls += 1;
        switch (self.result) {
            .empty => return,
            .oversized => {
                out.len = sealing.MAX_BLOB_BYTES + 1;
                return;
            },
            .malformed => {
                out.len = 32;
                return;
            },
            else => {},
        }
        var seed: [32]u8 = @splat(self.calls);
        defer @import("std").crypto.secureZero(u8, &seed);
        try seal(null, binding, seed[0..if (self.result == .wrong_size) 31 else 32], out);
        if (self.result == .fail) return error.HardwareOperationFailed;
    }
};
