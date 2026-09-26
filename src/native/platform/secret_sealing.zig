const std = @import("std");
const tpm = @import("tpm2_sealing.zig");
const wire = @import("tpm2_wire.zig");
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const MAX_VALUE_BYTES = 96;
pub const MAX_BLOB_BYTES = 6 + tpm.MAX_BLOB_BYTES + Aead.nonce_length + Aead.tag_length + MAX_VALUE_BYTES;
pub const Binding = [32]u8;
pub const Value = [MAX_VALUE_BYTES]u8;
pub const Error = error{ HardwareProviderUnavailable, HardwareOperationFailed, InvalidSealedSecret, InvalidAuthorization, SecretTooLarge };
pub const Blob = struct {
    bytes: [MAX_BLOB_BYTES]u8 = @splat(0),
    len: u16 = 0,

    pub fn slice(self: *const Blob) []const u8 {
        std.debug.assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }
};

// The owner keeps the context alive and serializes calls until detaching it.
// There is deliberately no default sealing implementation or digest fallback.
pub const Provider = struct {
    pub const Operations = struct {
        seal: *const fn (?*anyopaque, *const Binding, []const u8, *Blob) Error!void,
        open: *const fn (?*anyopaque, *const Binding, []const u8, *Value) Error!usize,
        generateSigningKey: ?*const fn (?*anyopaque, *const Binding, *Blob) Error!void = null,
    };

    context: ?*anyopaque = null,
    operations: ?*const Operations = null,

    pub fn seal(self: Provider, binding: *const Binding, raw: []const u8, out: *Blob) Error!void {
        out.* = .{};
        errdefer out.* = .{};
        if (raw.len > MAX_VALUE_BYTES) return error.SecretTooLarge;
        const ops = self.operations orelse return error.HardwareProviderUnavailable;
        try ops.seal(self.context, binding, raw, out);
        if (out.len == 0 or out.len > out.bytes.len) return error.InvalidSealedSecret;
    }

    // Only the backend sees the new Ed25519 seed. Callers receive ciphertext;
    // there is no import, software, or deterministic generation fallback.
    pub fn generateSigningKey(self: Provider, binding: *const Binding, out: *Blob) Error!void {
        out.* = .{};
        errdefer out.* = .{};
        const ops = self.operations orelse return error.HardwareProviderUnavailable;
        const generate = ops.generateSigningKey orelse return error.HardwareProviderUnavailable;
        try generate(self.context, binding, out);
        if (out.len == 0 or out.len > out.bytes.len) return error.InvalidSealedSecret;
        const envelope = try Envelope.parse(out.slice());
        if (envelope.ciphertext.len != std.crypto.sign.Ed25519.KeyPair.seed_length) return error.InvalidSealedSecret;
    }

    pub fn open(self: Provider, binding: *const Binding, blob: []const u8, out: *Value) Error!usize {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        if (blob.len == 0 or blob.len > MAX_BLOB_BYTES) return error.InvalidSealedSecret;
        const ops = self.operations orelse return error.HardwareProviderUnavailable;
        const len = try ops.open(self.context, binding, blob, out);
        if (len > out.len) return error.InvalidSealedSecret;
        std.crypto.secureZero(u8, out[len..]);
        return len;
    }
};

pub const Envelope = struct {
    wrapped_key: []const u8,
    nonce: [Aead.nonce_length]u8,
    tag: [Aead.tag_length]u8,
    ciphertext: []const u8,

    pub fn parse(blob: []const u8) Error!Envelope {
        return parseWire(blob) catch return error.InvalidSealedSecret;
    }

    fn parseWire(blob: []const u8) !Envelope {
        if (blob.len > MAX_BLOB_BYTES) return error.InvalidSealedSecret;
        var r = wire.Reader{ .bytes = blob };
        if (!std.mem.eql(u8, try r.take(4), "ZSV1")) return error.InvalidSealedSecret;
        const wrapped = try r.sized();
        if (wrapped.len == 0 or wrapped.len > tpm.MAX_BLOB_BYTES) return error.InvalidSealedSecret;
        const nonce = (try r.take(Aead.nonce_length))[0..Aead.nonce_length].*;
        const tag = (try r.take(Aead.tag_length))[0..Aead.tag_length].*;
        const ciphertext = blob[r.pos..];
        if (ciphertext.len > MAX_VALUE_BYTES) return error.InvalidSealedSecret;
        return .{ .wrapped_key = wrapped, .nonce = nonce, .tag = tag, .ciphertext = ciphertext };
    }

    pub fn open(self: Envelope, key: *const tpm.Key, binding: *const Binding, out: *Value) Error!usize {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        if (self.ciphertext.len > out.len) return error.InvalidSealedSecret;
        Aead.decrypt(out[0..self.ciphertext.len], self.ciphertext, self.tag, binding, self.nonce, key.*) catch
            return error.InvalidSealedSecret;
        return self.ciphertext.len;
    }
};

pub fn encrypt(raw: []const u8, key: *const tpm.Key, nonce: [Aead.nonce_length]u8, binding: *const Binding, wrapped: []const u8, out: *Blob) Error!void {
    out.* = .{};
    if (raw.len > MAX_VALUE_BYTES) return error.SecretTooLarge;
    if (wrapped.len == 0 or wrapped.len > tpm.MAX_BLOB_BYTES) return error.InvalidSealedSecret;
    // The checked maxima above make all writes fit this fixed-size envelope.
    var w = wire.Writer{ .bytes = &out.bytes };
    w.put("ZSV1") catch unreachable;
    w.sized(wrapped) catch unreachable;
    w.put(&nonce) catch unreachable;
    const tag_offset = w.pos;
    w.put(&(@as([Aead.tag_length]u8, @splat(0)))) catch unreachable;
    Aead.encrypt(out.bytes[w.pos..][0..raw.len], out.bytes[tag_offset..][0..Aead.tag_length], raw, binding, nonce, key.*);
    out.len = @intCast(w.pos + raw.len);
}

test "sealed envelopes authenticate binding ciphertext nonce and tag and erase failed output" {
    const key: tpm.Key = @splat(0x57);
    const binding: Binding = @splat(0x23);
    var raw: Value = undefined;
    for (&raw, 0..) |*byte, i| byte.* = @intCast(i);
    for (0..MAX_VALUE_BYTES + 1) |len| {
        var blob = Blob{};
        try encrypt(raw[0..len], &key, @splat(0x41), &binding, "wrapped", &blob);
        var out: Value = @splat(0xaa);
        const envelope = try Envelope.parse(blob.slice());
        try std.testing.expectEqual(len, try envelope.open(&key, &binding, &out));
        try std.testing.expectEqualSlices(u8, raw[0..len], out[0..len]);
        try std.testing.expect(std.mem.allEqual(u8, out[len..], 0));
        if (len != MAX_VALUE_BYTES) continue;
        var wrong_binding = binding;
        wrong_binding[0] ^= 1;
        try std.testing.expectError(error.InvalidSealedSecret, envelope.open(&key, &wrong_binding, &out));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0));
        for (13..blob.len) |i| {
            var damaged = blob;
            damaged.bytes[i] ^= 1;
            const parsed = try Envelope.parse(damaged.slice());
            out = @splat(0xaa);
            try std.testing.expectError(error.InvalidSealedSecret, parsed.open(&key, &binding, &out));
            try std.testing.expect(std.mem.allEqual(u8, &out, 0));
        }
    }
}

test "sealed envelopes reject framing overflow and incomplete authentication fields" {
    var blob = Blob{};
    try encrypt("secret", &(@as(tpm.Key, @splat(1))), @splat(2), &(@as(Binding, @splat(3))), "wrapped", &blob);
    for (0..53) |len| try std.testing.expectError(error.InvalidSealedSecret, Envelope.parse(blob.bytes[0..len]));
    blob.bytes[4] = 0xff;
    blob.bytes[5] = 0xff;
    try std.testing.expectError(error.InvalidSealedSecret, Envelope.parse(blob.slice()));
}

test "signing key generation rejects unavailable malformed and failed providers without output" {
    const fixture = @import("../../tests/fixtures/secret_provider.zig");
    var generator = fixture.KeyGenerator{};
    const binding: Binding = @splat(0x81);
    var blob = Blob{};
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Provider));
    for ([_]Provider{ .{}, fixture.provider() }) |unavailable| {
        blob.bytes = @splat(0xaa);
        blob.len = 32;
        try std.testing.expectError(error.HardwareProviderUnavailable, unavailable.generateSigningKey(&binding, &blob));
        try std.testing.expectEqualDeep(Blob{}, blob);
    }
    inline for (.{ .fail, .empty, .oversized, .malformed, .wrong_size }) |failure| {
        generator.result = failure;
        blob.bytes = @splat(0xaa);
        blob.len = 32;
        const expected = if (failure == .fail) error.HardwareOperationFailed else error.InvalidSealedSecret;
        try std.testing.expectError(expected, generator.provider().generateSigningKey(&binding, &blob));
        try std.testing.expectEqualDeep(Blob{}, blob);
    }
    generator.result = .valid;
    try generator.provider().generateSigningKey(&binding, &blob);
    try std.testing.expectEqual(@as(usize, 32), (try Envelope.parse(blob.slice())).ciphertext.len);
}
