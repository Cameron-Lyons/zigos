//! Administrator recovery material encrypted by an independently retained,
//! random 256-bit recovery key. Never derive that key from a PIN or password,
//! store it beside this package, or make it available to ordinary applications.
//! This recovers access on the enrolled TPM, not after that TPM is cleared or lost.
const std = @import("std");
const tpm = @import("../platform/tpm2_sealing.zig");
const enrollment = @import("identity_enrollment.zig");
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const HEADER_BYTES = 64;
pub const PACKAGE_BYTES = HEADER_BYTES + 96 + Aead.tag_length;

pub const Secrets = struct {
    owner: tpm.Key = @splat(0),
    lockout: tpm.Key = @splat(0),
    vault: tpm.Key = @splat(0),

    pub fn generate(entropy: anytype, out: *Secrets) !void {
        out.wipe();
        errdefer out.wipe();
        try entropy.random(&out.owner);
        try entropy.random(&out.lockout);
        try entropy.random(&out.vault);
        try out.validate();
    }

    pub fn wipe(self: *Secrets) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    fn validate(self: *const Secrets) !void {
        if (std.mem.allEqual(u8, &self.owner, 0) or std.mem.allEqual(u8, &self.lockout, 0) or std.mem.allEqual(u8, &self.vault, 0) or
            std.crypto.timing_safe.eql(tpm.Key, self.owner, self.lockout) or std.crypto.timing_safe.eql(tpm.Key, self.owner, self.vault) or
            std.crypto.timing_safe.eql(tpm.Key, self.lockout, self.vault)) return error.InvalidRecoverySecrets;
    }
};

pub const Package = struct {
    bytes: [PACKAGE_BYTES]u8 = @splat(0),

    // Durably export this ciphertext and retain the recovery key independently
    // before changing TPM authorization. A lost change reply may be committed.
    pub fn seal(record: *const enrollment.Record, secrets: *const Secrets, recovery_key: *const tpm.Key, entropy: anytype, out: *Package) !void {
        out.* = .{};
        errdefer out.* = .{};
        const binding = try record.digest();
        try secrets.validate();
        try validateRecoveryKey(recovery_key);
        if (std.crypto.timing_safe.eql(tpm.Key, recovery_key.*, secrets.owner) or std.crypto.timing_safe.eql(tpm.Key, recovery_key.*, secrets.lockout) or
            std.crypto.timing_safe.eql(tpm.Key, recovery_key.*, secrets.vault)) return error.InvalidRecoveryKey;
        var nonce: [Aead.nonce_length]u8 = undefined;
        try entropy.random(&nonce);
        if (std.mem.allEqual(u8, &nonce, 0)) return error.EntropyUnavailable;
        var plaintext: [96]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        @memcpy(plaintext[0..32], &secrets.owner);
        @memcpy(plaintext[32..64], &secrets.lockout);
        @memcpy(plaintext[64..96], &secrets.vault);
        @memcpy(out.bytes[0..8], "ZGIDRC01");
        @memcpy(out.bytes[8..40], &binding);
        @memcpy(out.bytes[40..64], &nonce);
        Aead.encrypt(out.bytes[HEADER_BYTES..][0..96], out.bytes[HEADER_BYTES + 96 ..][0..Aead.tag_length], &plaintext, out.bytes[0..HEADER_BYTES], nonce, recovery_key.*);
    }

    // The expected binding comes from authenticated enrollment, not the header.
    // Failed output is always erased, including framing, binding and key errors.
    pub fn open(bytes: []const u8, trusted_binding: *const tpm.Key, recovery_key: *const tpm.Key, out: *Secrets) !void {
        out.wipe();
        errdefer out.wipe();
        try validateRecoveryKey(recovery_key);
        if (bytes.len != PACKAGE_BYTES or !std.mem.eql(u8, bytes[0..8], "ZGIDRC01")) return error.InvalidRecoveryPackage;
        if (std.mem.allEqual(u8, trusted_binding, 0) or !std.crypto.timing_safe.eql(tpm.Key, bytes[8..40].*, trusted_binding.*)) return error.RecoveryEnrollmentChanged;
        var plaintext: [96]u8 = undefined;
        defer std.crypto.secureZero(u8, &plaintext);
        Aead.decrypt(&plaintext, bytes[HEADER_BYTES..][0..96], bytes[HEADER_BYTES + 96 ..][0..Aead.tag_length].*, bytes[0..HEADER_BYTES], bytes[40..64].*, recovery_key.*) catch return error.RecoveryAuthenticationFailed;
        out.owner = plaintext[0..32].*;
        out.lockout = plaintext[32..64].*;
        out.vault = plaintext[64..96].*;
        try out.validate();
    }
};

fn validateRecoveryKey(key: *const tpm.Key) !void {
    if (std.mem.allEqual(u8, key, 0)) return error.InvalidRecoveryKey;
}

test "identity recovery authenticates every byte and erases rejected secrets" {
    const Entropy = struct {
        next: u8 = 1,
        pub fn random(self: *@This(), out: []u8) !void {
            @memset(out, self.next);
            self.next += 1;
        }
    };
    const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    const binding = try record.digest();
    const key: tpm.Key = @splat(8);
    var entropy = Entropy{};
    var secrets = Secrets{};
    defer secrets.wipe();
    try Secrets.generate(&entropy, &secrets);
    var package = Package{};
    try Package.seal(&record, &secrets, &key, &entropy, &package);
    var out = Secrets{};
    defer out.wipe();
    try Package.open(&package.bytes, &binding, &key, &out);
    try std.testing.expectEqualDeep(secrets, out);
    for ([_]tpm.Key{ secrets.owner, secrets.lockout, secrets.vault, key }) |secret| try std.testing.expect(std.mem.indexOf(u8, &package.bytes, &secret) == null);
    for (0..PACKAGE_BYTES) |i| {
        var changed = package;
        changed.bytes[i] ^= 1;
        out = secrets;
        if (Package.open(&changed.bytes, &binding, &key, &out)) |_| return error.AcceptedCorruptRecovery else |_| {}
        try std.testing.expectEqualDeep(Secrets{}, out);
    }
    for (0..PACKAGE_BYTES) |length| {
        out = secrets;
        try std.testing.expectError(error.InvalidRecoveryPackage, Package.open(package.bytes[0..length], &binding, &key, &out));
        try std.testing.expectEqualDeep(Secrets{}, out);
    }
    const oversized = package.bytes ++ [_]u8{0};
    try std.testing.expectError(error.InvalidRecoveryPackage, Package.open(&oversized, &binding, &key, &out));
    try std.testing.expectEqualDeep(Secrets{}, out);
    const wrong_key: tpm.Key = @splat(9);
    out = secrets;
    try std.testing.expectError(error.RecoveryAuthenticationFailed, Package.open(&package.bytes, &binding, &wrong_key, &out));
    try std.testing.expectEqualDeep(Secrets{}, out);
    const zero_key: tpm.Key = @splat(0);
    out = secrets;
    try std.testing.expectError(error.InvalidRecoveryKey, Package.open(&package.bytes, &binding, &zero_key, &out));
    try std.testing.expectEqualDeep(Secrets{}, out);
    var changed = record;
    changed.enrollment.anchor_index += 1;
    try std.testing.expectError(error.RecoveryEnrollmentChanged, Package.open(&package.bytes, &(try changed.digest()), &key, &out));
    var second = Package{};
    try Package.seal(&record, &secrets, &key, &entropy, &second);
    try std.testing.expect(!std.mem.eql(u8, &package.bytes, &second.bytes));
}

test "identity recovery refuses failed entropy and reused administrator secrets" {
    const Entropy = struct {
        calls: u8 = 0,
        fail_at: u8 = 0,
        repeated: bool = false,
        zero: bool = false,
        pub fn random(self: *@This(), out: []u8) !void {
            self.calls += 1;
            @memset(out, if (self.zero) 0 else if (self.repeated) 1 else self.calls);
            if (self.calls == self.fail_at) return error.NoEntropy;
        }
    };
    var secrets = Secrets{};
    defer secrets.wipe();
    for (1..4) |step| {
        var entropy = Entropy{ .fail_at = @intCast(step) };
        try std.testing.expectError(error.NoEntropy, Secrets.generate(&entropy, &secrets));
        try std.testing.expectEqualDeep(Secrets{}, secrets);
    }
    var entropy = Entropy{ .repeated = true };
    try std.testing.expectError(error.InvalidRecoverySecrets, Secrets.generate(&entropy, &secrets));
    try std.testing.expectEqualDeep(Secrets{}, secrets);
    entropy = .{ .zero = true };
    try std.testing.expectError(error.InvalidRecoverySecrets, Secrets.generate(&entropy, &secrets));
    try std.testing.expectEqualDeep(Secrets{}, secrets);
    entropy = .{};
    try Secrets.generate(&entropy, &secrets);
    const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
    var package = Package{};
    const key: tpm.Key = @splat(8);
    entropy.fail_at = 4;
    try std.testing.expectError(error.NoEntropy, Package.seal(&record, &secrets, &key, &entropy, &package));
    try std.testing.expectEqualDeep(Package{}, package);
    try std.testing.expectError(error.InvalidRecoveryKey, Package.seal(&record, &secrets, &secrets.owner, &entropy, &package));
    try std.testing.expectEqualDeep(Package{}, package);
    entropy = .{ .zero = true };
    try std.testing.expectError(error.EntropyUnavailable, Package.seal(&record, &secrets, &key, &entropy, &package));
    try std.testing.expectEqualDeep(Package{}, package);
}
