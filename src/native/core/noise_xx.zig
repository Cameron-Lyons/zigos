//! Noise_XX_25519_ChaChaPoly_SHA256, revision 34. No negotiation or fallback.
//! https://noiseprotocol.org/noise.html
//! The application must authenticate remote_static before using split keys.
const std = @import("std");
const entropy = @import("transport_crypto.zig");
const Dh = std.crypto.dh.X25519;
const Hash = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
pub const PROTOCOL = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const MAX_PAYLOAD = 96;
pub const MAX_MESSAGE = 96 + MAX_PAYLOAD;
pub const Role = enum { initiator, responder };
pub const Error = entropy.Error || error{ InvalidState, InvalidPublicKey, NonceExhausted };

pub const Cipher = struct {
    key: [32]u8,
    nonce: u64 = 0,
    active: bool = true,

    pub fn seal(self: *Cipher, out: []u8, plaintext: []const u8, ad: []const u8) Error![]const u8 {
        errdefer std.crypto.secureZero(u8, out[0..@min(out.len, 256)]);
        if (!self.active) return error.InvalidState;
        if (self.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        if (plaintext.len > 240 or out.len < plaintext.len + 16) return error.InvalidLength;
        const result = out[0 .. plaintext.len + 16];
        Aead.encrypt(result[0..plaintext.len], result[plaintext.len..][0..16], plaintext, ad, nonceBytes(self.nonce), self.key);
        self.nonce += 1;
        return result;
    }

    pub fn open(self: *Cipher, out: []u8, ciphertext: []const u8, ad: []const u8) Error![]const u8 {
        const result = try self.openAt(out, ciphertext, ad, self.nonce);
        self.nonce += 1;
        return result;
    }

    // Noise section 11.4: the datagram owner must reject successfully received
    // nonce duplicates. Authentication failures must not advance that window.
    pub fn openAt(self: *const Cipher, out: []u8, ciphertext: []const u8, ad: []const u8, nonce: u64) Error![]const u8 {
        errdefer std.crypto.secureZero(u8, out[0..@min(out.len, 256)]);
        if (!self.active) return error.InvalidState;
        if (nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        if (ciphertext.len < 16 or ciphertext.len > 256 or out.len < ciphertext.len - 16) return error.InvalidLength;
        const length = ciphertext.len - 16;
        const result = out[0..length];
        Aead.decrypt(result, ciphertext[0..length], ciphertext[length..][0..16].*, ad, nonceBytes(nonce), self.key) catch return error.AuthenticationFailed;
        return result;
    }

    pub fn deinit(self: *Cipher) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const Split = struct {
    send: Cipher,
    receive: Cipher,
    hash: [32]u8,

    pub fn deinit(self: *Split) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const Handshake = struct {
    local_static: Dh.KeyPair,
    ephemeral: Dh.KeyPair,
    remote_static: [32]u8 = @splat(0),
    remote_ephemeral: [32]u8 = @splat(0),
    hash: [32]u8,
    chaining_key: [32]u8,
    cipher: Cipher = .{ .key = @splat(0), .active = false },
    role: Role,
    step: u8 = 0,
    active: bool = true,

    pub fn init(role: Role, prologue: []const u8) Error!Handshake {
        var local_static = try freshPair();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&local_static));
        var ephemeral = try freshPair();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&ephemeral));
        return initKeys(role, prologue, local_static, ephemeral);
    }

    // Deterministic key injection is private and used only by published vectors.
    fn initKeys(role: Role, prologue: []const u8, local_static: Dh.KeyPair, ephemeral: Dh.KeyPair) Handshake {
        var initial: [32]u8 = @splat(0);
        if (PROTOCOL.len <= initial.len) @memcpy(initial[0..PROTOCOL.len], PROTOCOL) else Hash.hash(PROTOCOL, &initial, .{});
        var self = Handshake{ .role = role, .local_static = local_static, .ephemeral = ephemeral, .hash = initial, .chaining_key = initial };
        self.mixHash(prologue);
        return self;
    }

    pub fn write(self: *Handshake, out: []u8, payload: []const u8) Error![]const u8 {
        errdefer self.deinit();
        errdefer std.crypto.secureZero(u8, out[0..@min(out.len, MAX_MESSAGE)]);
        if (!self.active or self.step >= 3 or (self.role == .initiator) != (self.step != 1)) return error.InvalidState;
        const overhead: usize = switch (self.step) {
            0 => 32,
            1 => 96,
            2 => 64,
            else => unreachable,
        };
        if (payload.len > MAX_PAYLOAD or out.len < overhead + payload.len) return error.InvalidLength;
        var offset: usize = 0;
        if (self.step < 2) {
            @memcpy(out[0..32], &self.ephemeral.public_key);
            self.mixHash(out[0..32]);
            offset = 32;
        }
        if (self.step == 1) try self.mixDh(self.ephemeral.secret_key, self.remote_ephemeral); // ee
        if (self.step != 0) {
            const encrypted = try self.encryptAndHash(out[offset..], &self.local_static.public_key);
            offset += encrypted.len;
            try self.mixDh(self.local_static.secret_key, self.remote_ephemeral); // es or se
        }
        const encrypted = try self.encryptAndHash(out[offset..], payload);
        self.step += 1;
        return out[0 .. offset + encrypted.len];
    }

    pub fn read(self: *Handshake, out: []u8, message: []const u8) Error![]const u8 {
        errdefer self.deinit();
        errdefer std.crypto.secureZero(u8, out[0..@min(out.len, MAX_PAYLOAD)]);
        if (!self.active or self.step >= 3 or (self.role == .initiator) != (self.step == 1)) return error.InvalidState;
        const overhead: usize = switch (self.step) {
            0 => 32,
            1 => 96,
            2 => 64,
            else => unreachable,
        };
        if (message.len < overhead or message.len > overhead + MAX_PAYLOAD or out.len < message.len - overhead) return error.InvalidLength;
        var offset: usize = 0;
        if (self.step < 2) {
            self.remote_ephemeral = message[0..32].*;
            self.mixHash(message[0..32]);
            offset = 32;
        }
        if (self.step == 1) try self.mixDh(self.ephemeral.secret_key, self.remote_ephemeral); // ee
        if (self.step != 0) {
            _ = try self.decryptAndHash(&self.remote_static, message[offset .. offset + 48]);
            offset += 48;
            try self.mixDh(self.ephemeral.secret_key, self.remote_static); // es or se
        }
        const payload = try self.decryptAndHash(out, message[offset..]);
        self.step += 1;
        return payload;
    }

    pub fn finish(self: *Handshake) Error!Split {
        errdefer self.deinit();
        if (!self.active or self.step != 3) return error.InvalidState;
        defer self.deinit();
        var keys = hkdf(self.chaining_key, "");
        defer std.crypto.secureZero(u8, &keys);
        const initiator = self.role == .initiator;
        return .{
            .send = .{ .key = if (initiator) keys[0..32].* else keys[32..64].* },
            .receive = .{ .key = if (initiator) keys[32..64].* else keys[0..32].* },
            .hash = self.hash,
        };
    }

    pub fn deinit(self: *Handshake) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    fn mixHash(self: *Handshake, bytes: []const u8) void {
        var hasher = Hash.init(.{});
        hasher.update(&self.hash);
        hasher.update(bytes);
        hasher.final(&self.hash);
    }

    fn mixDh(self: *Handshake, secret: [32]u8, public: [32]u8) Error!void {
        var shared = Dh.scalarmult(secret, public) catch return error.InvalidPublicKey;
        defer std.crypto.secureZero(u8, &shared);
        var keys = hkdf(self.chaining_key, &shared);
        defer std.crypto.secureZero(u8, &keys);
        self.chaining_key = keys[0..32].*;
        self.cipher = .{ .key = keys[32..64].* };
    }

    fn encryptAndHash(self: *Handshake, out: []u8, plaintext: []const u8) Error![]const u8 {
        const result = if (self.cipher.active) try self.cipher.seal(out, plaintext, &self.hash) else blk: {
            @memcpy(out[0..plaintext.len], plaintext);
            break :blk out[0..plaintext.len];
        };
        self.mixHash(result);
        return result;
    }

    fn decryptAndHash(self: *Handshake, out: []u8, ciphertext: []const u8) Error![]const u8 {
        const result = if (self.cipher.active) try self.cipher.open(out, ciphertext, &self.hash) else blk: {
            @memcpy(out[0..ciphertext.len], ciphertext);
            break :blk out[0..ciphertext.len];
        };
        self.mixHash(ciphertext);
        return result;
    }
};

fn freshPair() Error!Dh.KeyPair {
    var context: [32]u8 = undefined;
    Hash.hash("zigos.noise.xx.key", &context, .{});
    var seed = try entropy.freshKey(context);
    defer std.crypto.secureZero(u8, &seed);
    return Dh.KeyPair.generateDeterministic(seed) catch error.InvalidPublicKey;
}

fn hkdf(chaining_key: [32]u8, input: []const u8) [64]u8 {
    var prk = Hkdf.extract(&chaining_key, input);
    defer std.crypto.secureZero(u8, &prk);
    var result: [64]u8 = undefined;
    Hkdf.expand(&result, "", prk);
    return result;
}

fn nonceBytes(nonce: u64) [12]u8 {
    var result: [12]u8 = @splat(0);
    std.mem.writeInt(u64, result[4..12], nonce, .little);
    return result;
}

comptime {
    if (@sizeOf(Handshake) > 320 or @sizeOf(Split) > 128) @compileError("Noise state exceeds bounded channel budget");
}

// Interoperability fixture from noise-c (MIT), tests/vector/noise-c-basic.txt.
// https://github.com/rweather/noise-c/blob/master/tests/vector/noise-c-basic.txt
// Copyright (C) 2016 Southern Storm Software, Pty Ltd.
// License: ../../tests/fixtures/noise_c_LICENSE
fn fromHex(comptime value: []const u8) [value.len / 2]u8 {
    var bytes: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, value) catch unreachable;
    return bytes;
}

test "Noise XX matches noise-c handshake and bidirectional transport vectors" {
    var init = Handshake.initKeys(.initiator, &fromHex("50726f6c6f677565313233"), try Dh.KeyPair.generateDeterministic(fromHex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")), try Dh.KeyPair.generateDeterministic(fromHex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
    defer init.deinit();
    var resp = Handshake.initKeys(.responder, &fromHex("50726f6c6f677565313233"), try Dh.KeyPair.generateDeterministic(fromHex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")), try Dh.KeyPair.generateDeterministic(fromHex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")));
    defer resp.deinit();
    var buffer: [256]u8 = undefined;
    var output: [256]u8 = undefined;
    const message0 = try init.write(&buffer, &fromHex("4c756477696720766f6e204d69736573"));
    try std.testing.expectEqualSlices(u8, &fromHex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"), message0);
    try std.testing.expectEqualSlices(u8, &fromHex("4c756477696720766f6e204d69736573"), try resp.read(&output, message0));
    const message1 = try resp.write(&buffer, &fromHex("4d757272617920526f746862617264"));
    try std.testing.expectEqualSlices(u8, &fromHex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b94a6d8798832d5372f220f161d9c2df035528f8982ffe09be9b5c412f8a0db5d21351f20af1370d0bf8ef1a8c59a30e"), message1);
    try std.testing.expectEqualSlices(u8, &fromHex("4d757272617920526f746862617264"), try init.read(&output, message1));
    const message2 = try init.write(&buffer, &fromHex("462e20412e20486179656b"));
    try std.testing.expectEqualSlices(u8, &fromHex("c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a8589981dfbd651e6ff4724a781cc2aa6158c9fea0d4ec82a286427484c5b8c8123a7a6002b1de9f9775fc97"), message2);
    try std.testing.expectEqualSlices(u8, &fromHex("462e20412e20486179656b"), try resp.read(&output, message2));
    try std.testing.expectEqualSlices(u8, &fromHex("852a28d2146785c54bd8334f4e460c80d7fe4fd0cc5bc0abef2a24a3c4d44d5f"), &init.hash);
    try std.testing.expectEqualSlices(u8, &init.hash, &resp.hash);
    var initiator = try init.finish();
    defer initiator.deinit();
    var responder = try resp.finish();
    defer responder.deinit();
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&init), 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&resp), 0));
    const message3 = try responder.send.seal(&buffer, &fromHex("4361726c204d656e676572"), "");
    try std.testing.expectEqualSlices(u8, &fromHex("96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df"), message3);
    try std.testing.expectEqualSlices(u8, &fromHex("4361726c204d656e676572"), try initiator.receive.open(&output, message3, ""));
    const message4 = try initiator.send.seal(&buffer, &fromHex("4a65616e2d426170746973746520536179"), "");
    try std.testing.expectEqualSlices(u8, &fromHex("3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5"), message4);
    try std.testing.expectEqualSlices(u8, &fromHex("4a65616e2d426170746973746520536179"), try responder.receive.open(&output, message4, ""));
    const message5 = try responder.send.seal(&buffer, &fromHex("457567656e2042f6686d20766f6e2042617765726b"), "");
    try std.testing.expectEqualSlices(u8, &fromHex("eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3a58502ae3f"), message5);
    try std.testing.expectEqualSlices(u8, &fromHex("457567656e2042f6686d20766f6e2042617765726b"), try initiator.receive.open(&output, message5, ""));
}

test "Noise XX rejects low order public keys and destroys failed handshake state" {
    var responder = try Handshake.init(.responder, "invalid peer");
    defer responder.deinit();
    var output = [_]u8{0xa5} ** MAX_MESSAGE;
    _ = try responder.read(&output, &(@as([32]u8, @splat(0))));
    try std.testing.expectError(error.InvalidPublicKey, responder.write(&output, ""));
    try std.testing.expect(std.mem.allEqual(u8, &output, 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&responder), 0));
    var initiator = try Handshake.init(.initiator, "incomplete");
    try std.testing.expectError(error.InvalidState, initiator.finish());
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&initiator), 0));
}
