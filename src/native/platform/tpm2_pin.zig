const std = @import("std");
const tpm = @import("tpm2_sealing.zig");
const principal = @import("../core/principal.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const MIN_PIN_BYTES = 6;
pub const MAX_PIN_BYTES = 32;
pub const MAX_BYTES = 58 + tpm.MAX_BLOB_BYTES;
pub const DEFAULT_POLICY = tpm.DictionaryAttackPolicy{ .max_tries = 8, .recovery_seconds = 3600, .lockout_recovery_seconds = 86400 };

// A PIN protects a random 256-bit vault authorization inside the TPM, with no
// disk-stored PIN verifier. The caller must configure persistent DA protection
// and a strong, separately retained lockout authorization during enrollment.
// The capsule digest MUST come from trusted enrollment, not from this capsule
// or an unauthenticated disk header. This is a trusted-service primitive, not an
// app request boundary or an authenticator UI. Callers erase their PIN buffers.
pub const Capsule = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    salt: tpm.Key,
    sealed: tpm.Blob,

    pub fn enroll(client: *tpm.Client, io: anytype, owner: principal.PrincipalId, device: principal.PrincipalId, pin: []const u8, authorization: *const tpm.Key) !Capsule {
        try validatePin(pin);
        if (std.mem.allEqual(u8, authorization, 0)) return error.InvalidAuthorization;
        var result = Capsule{ .owner = owner, .device = device, .salt = undefined, .sealed = .{} };
        try validatePrincipals(owner, device);
        try io.random(&result.salt);
        if (std.mem.allEqual(u8, &result.salt, 0)) return error.EntropyUnavailable;
        var auth = try result.pinAuthorization(pin);
        defer std.crypto.secureZero(u8, &auth);
        try client.seal(io, authorization, &auth, &result.sealed);
        return result;
    }

    pub fn unlock(self: *const Capsule, client: *tpm.Client, io: anytype, trusted_digest: *const tpm.Key, pin: []const u8, out: *tpm.Key) !void {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        if (!std.crypto.timing_safe.eql(tpm.Key, try self.digest(), trusted_digest.*)) return error.UntrustedPinCapsule;
        var auth = try self.pinAuthorization(pin);
        defer std.crypto.secureZero(u8, &auth);
        client.unseal(io, self.sealed.slice(), &auth, out) catch |err| {
            if (err == error.TpmError) switch (client.last_tpm_error) {
                0x98e => return error.PinRejected, // TPM_RC_AUTH_FAIL, session 1
                0x921 => return error.PinLockedOut,
                else => {},
            };
            return err;
        };
        if (std.mem.allEqual(u8, out, 0)) return error.InvalidAuthorization;
    }

    pub fn encode(self: *const Capsule, out: *[MAX_BYTES]u8) ![]const u8 {
        try validatePrincipals(self.owner, self.device);
        if (std.mem.allEqual(u8, &self.salt, 0) or self.sealed.len == 0 or self.sealed.len > tpm.MAX_BLOB_BYTES) return error.InvalidPinCapsule;
        @memset(out, 0);
        @memcpy(out[0..8], "ZGPIN001");
        std.mem.writeInt(u64, out[8..16], self.owner.serial, .little);
        std.mem.writeInt(u64, out[16..24], self.device.serial, .little);
        @memcpy(out[24..56], &self.salt);
        std.mem.writeInt(u16, out[56..58], self.sealed.len, .little);
        @memcpy(out[58..][0..self.sealed.len], self.sealed.slice());
        return out[0 .. 58 + self.sealed.len];
    }

    pub fn digest(self: *const Capsule) !tpm.Key {
        var bytes: [MAX_BYTES]u8 = undefined;
        var result: tpm.Key = undefined;
        Sha256.hash(try self.encode(&bytes), &result, .{});
        return result;
    }

    pub fn decode(bytes: []const u8, trusted_digest: *const tpm.Key) !Capsule {
        if (bytes.len < 59 or bytes.len > MAX_BYTES or !std.mem.eql(u8, bytes[0..8], "ZGPIN001")) return error.InvalidPinCapsule;
        var actual: tpm.Key = undefined;
        Sha256.hash(bytes, &actual, .{});
        if (!std.crypto.timing_safe.eql(tpm.Key, actual, trusted_digest.*)) return error.UntrustedPinCapsule;
        const len = std.mem.readInt(u16, bytes[56..58], .little);
        if (len != bytes.len - 58) return error.InvalidPinCapsule;
        var result = Capsule{ .owner = .{ .kind = .user, .serial = std.mem.readInt(u64, bytes[8..16], .little) }, .device = .{ .kind = .device, .serial = std.mem.readInt(u64, bytes[16..24], .little) }, .salt = bytes[24..56].*, .sealed = .{ .len = len } };
        @memcpy(result.sealed.bytes[0..len], bytes[58..]);
        _ = try result.digest();
        return result;
    }

    fn pinAuthorization(self: *const Capsule, pin: []const u8) !tpm.Key {
        try validatePrincipals(self.owner, self.device);
        try validatePin(pin);
        if (std.mem.allEqual(u8, &self.salt, 0)) return error.InvalidPinCapsule;
        var hash = Sha256.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
        hash.update("zigos:device-pin:v1\x00");
        var binding: [16]u8 = undefined;
        std.mem.writeInt(u64, binding[0..8], self.owner.serial, .big);
        std.mem.writeInt(u64, binding[8..16], self.device.serial, .big);
        hash.update(&binding);
        hash.update(&self.salt);
        hash.update(&.{@intCast(pin.len)});
        hash.update(pin);
        return hash.finalResult();
    }
};

fn validatePrincipals(owner: principal.PrincipalId, device: principal.PrincipalId) !void {
    if (owner.kind != .user or owner.serial == 0 or device.kind != .device or device.serial == 0) return error.InvalidPinCapsule;
}

pub fn validatePin(pin: []const u8) !void {
    if (pin.len < MIN_PIN_BYTES or pin.len > MAX_PIN_BYTES) return error.InvalidPin;
    for (pin) |byte| if (byte < '0' or byte > '9') return error.InvalidPin;
}

test "TPM PIN capsule requires its independent pin and binds owner device salt and PIN" {
    const RejectIo = struct {
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedHardwareAccess;
        }
        pub fn execute(_: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            return error.UnexpectedHardwareAccess;
        }
    };
    var capsule = Capsule{ .owner = .{ .kind = .user, .serial = 3 }, .device = .{ .kind = .device, .serial = 4 }, .salt = @splat(5), .sealed = .{ .len = 3 } };
    @memcpy(capsule.sealed.bytes[0..3], "abc");
    const trusted = try capsule.digest();
    const auth = try capsule.pinAuthorization("528104");
    var bytes: [MAX_BYTES]u8 = undefined;
    const encoded = try capsule.encode(&bytes);
    try std.testing.expectEqualDeep(capsule, try Capsule.decode(encoded, &trusted));
    for (0..encoded.len) |len| try std.testing.expectError(if (len < 59) error.InvalidPinCapsule else error.UntrustedPinCapsule, Capsule.decode(encoded[0..len], &trusted));
    for ([_]usize{ 8, 16, 24, 56, 58 }) |offset| {
        var changed = bytes;
        changed[offset] ^= 1;
        try std.testing.expectError(error.UntrustedPinCapsule, Capsule.decode(changed[0..encoded.len], &trusted));
    }
    var changed = capsule;
    changed.owner.serial += 1;
    try std.testing.expect(!std.mem.eql(u8, &auth, &(try changed.pinAuthorization("528104"))));
    changed = capsule;
    changed.device.serial += 1;
    try std.testing.expect(!std.mem.eql(u8, &auth, &(try changed.pinAuthorization("528104"))));
    changed = capsule;
    changed.salt[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &auth, &(try changed.pinAuthorization("528104"))));
    try std.testing.expect(!std.mem.eql(u8, &auth, &(try capsule.pinAuthorization("528105"))));
    var client = tpm.Client{};
    var io = RejectIo{};
    var out: tpm.Key = @splat(0xaa);
    try std.testing.expectError(error.UntrustedPinCapsule, changed.unlock(&client, &io, &trusted, "528104", &out));
    try std.testing.expectEqual(@as(tpm.Key, @splat(0)), out);
    for ([_][]const u8{ "", "12345", "123 45", "12345\x00", "12345x", "123456789012345678901234567890123" }) |invalid| {
        out = @splat(0xaa);
        try std.testing.expectError(error.InvalidPin, capsule.unlock(&client, &io, &trusted, invalid, &out));
        try std.testing.expectEqual(@as(tpm.Key, @splat(0)), out);
    }
}
