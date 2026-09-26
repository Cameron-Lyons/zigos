const sealing = @import("../../native/platform/secret_sealing.zig");

// Public deterministic software fixture for host tests, verification kernels,
// and microbenchmarks. This is not a hardware provider or a production fallback.
const key: [32]u8 = @splat(0x51);
pub fn provider() sealing.Provider {
    return .{ .sealFn = seal, .openFn = open };
}
fn seal(_: ?*anyopaque, binding: *const sealing.Binding, raw: []const u8, out: *sealing.Blob) sealing.Error!void {
    try sealing.encrypt(raw, &key, @splat(0x26), binding, "verification-only", out);
}
fn open(_: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
    return (try sealing.Envelope.parse(blob)).open(&key, binding, out);
}
