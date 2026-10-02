//! Public enrollment reference retained independently of disk in TPM NV.
//! An initial read supplies only a candidate. Authenticate it through the
//! enrolled parent before using its bundle for PIN or recovery entry.
const std = @import("std");
const wire = @import("tpm2_wire.zig");

pub const BYTES = 48;
// OWNERWRITE, AUTHREAD, WRITEALL, WRITEDEFINE, NO_DA. Reads are public;
// only separately retained owner authorization can write or lock this index.
pub const ATTRIBUTES: u32 = 0x0204_3002;
pub const WRITTEN: u32 = 0x2000_0000;
pub const LOCKED: u32 = 0x0000_0800;
pub const Pin = struct {
    object_id: u64,
    digest: [32]u8,

    pub fn encode(self: Pin) ![BYTES]u8 {
        if (self.object_id == 0 or std.mem.allEqual(u8, &self.digest, 0)) return error.InvalidBootPin;
        var bytes: [BYTES]u8 = undefined;
        @memcpy(bytes[0..8], "ZGIDBP01");
        std.mem.writeInt(u64, bytes[8..16], self.object_id, .big);
        @memcpy(bytes[16..], &self.digest);
        return bytes;
    }

    pub fn decode(bytes: []const u8) !Pin {
        if (bytes.len != BYTES or !std.mem.eql(u8, bytes[0..8], "ZGIDBP01")) return error.InvalidBootPin;
        const result = Pin{ .object_id = std.mem.readInt(u64, bytes[8..16], .big), .digest = bytes[16..48].* };
        _ = try result.encode();
        return result;
    }
};

pub fn validateIndex(index: u32) !void {
    if (index < 0x0180_0000 or index > 0x0180_ffff) return error.InvalidNvSpace;
}

pub fn commitment(index: u32, bytes: *const [BYTES]u8) [32]u8 {
    var encoded_index: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded_index, index, .big);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("zigos:identity-boot-pin:v1\x00");
    hash.update(&encoded_index);
    hash.update(bytes);
    return hash.finalResult();
}

pub const Public = struct {
    name: [34]u8,
    commitment: [32]u8,
    written: bool,
    locked: bool,

    pub fn requireComplete(self: Public) !void {
        if (!self.written or !self.locked) return error.BootPinIncomplete;
    }
};

pub fn parsePublic(bytes: []const u8, index: u32) !Public {
    try validateIndex(index);
    var r = wire.Reader{ .bytes = bytes };
    const public = try r.sized();
    var p = wire.Reader{ .bytes = public };
    if (try p.int(u32) != index or try p.int(u16) != 0x0b) return error.InvalidResponse;
    const attributes = try p.int(u32);
    if (attributes & ~(WRITTEN | LOCKED) != ATTRIBUTES) return error.InvalidResponse;
    const binding = try p.sized();
    if (binding.len != 32 or std.mem.allEqual(u8, binding, 0)) return error.InvalidResponse;
    if (try p.int(u16) != BYTES) return error.InvalidResponse;
    try p.end();
    var name: [34]u8 = undefined;
    name[0..2].* = .{ 0, 0x0b };
    std.crypto.hash.sha2.Sha256.hash(public, name[2..], .{});
    if (!std.mem.eql(u8, try r.sized(), &name)) return error.IntegrityFailure;
    try r.end();
    return .{ .name = name, .commitment = binding[0..32].*, .written = attributes & WRITTEN != 0, .locked = attributes & LOCKED != 0 };
}

test "TPM boot pin framing binds the index and rejects incomplete or weaker NV public areas" {
    const pin = Pin{ .object_id = 1001, .digest = @splat(9) };
    const bytes = try pin.encode();
    try std.testing.expectEqualDeep(pin, try Pin.decode(&bytes));
    for (0..bytes.len) |length| try std.testing.expectError(error.InvalidBootPin, Pin.decode(bytes[0..length]));
    const index = 0x0180_1345;
    const binding = commitment(index, &bytes);
    try std.testing.expect(!std.mem.eql(u8, &binding, &commitment(index + 1, &bytes)));
    for ([_]u32{ ATTRIBUTES, ATTRIBUTES | WRITTEN, ATTRIBUTES | LOCKED, ATTRIBUTES | WRITTEN | LOCKED }) |attributes| {
        var buffer: [84]u8 = undefined;
        var w = wire.Writer{ .bytes = &buffer };
        try w.int(u16, 46);
        try w.int(u32, index);
        try w.int(u16, 0x0b);
        try w.int(u32, attributes);
        try w.sized(&binding);
        try w.int(u16, BYTES);
        var name: [34]u8 = .{ 0, 0x0b } ++ @as([32]u8, @splat(0));
        std.crypto.hash.sha2.Sha256.hash(buffer[2..48], name[2..], .{});
        try w.sized(&name);
        const public = try parsePublic(&buffer, index);
        if (attributes & (WRITTEN | LOCKED) == WRITTEN | LOCKED) try public.requireComplete() else try std.testing.expectError(error.BootPinIncomplete, public.requireComplete());
        for (0..32) |bit| {
            const changed = attributes ^ (@as(u32, 1) << @as(u5, @intCast(bit)));
            std.mem.writeInt(u32, buffer[8..12], changed, .big);
            if (bit != 11 and bit != 29) try std.testing.expectError(error.InvalidResponse, parsePublic(&buffer, index));
        }
    }
}
