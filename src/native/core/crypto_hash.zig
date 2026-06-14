const std = @import("std");

pub const Hasher = std.crypto.hash.sha2.Sha256;
pub const digest_bytes: usize = 32;
pub const hex_digest_bytes: usize = digest_bytes * 2;
pub const Digest = [digest_bytes]u8;
pub const zero_digest: Digest = [_]u8{0} ** digest_bytes;

pub fn digestFromByte(byte: u8) Digest {
    return [_]u8{byte} ** digest_bytes;
}

pub fn init() Hasher {
    return Hasher.init(.{});
}

pub fn finalize(hasher: *Hasher) Digest {
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

pub fn updateBytes(hasher: *Hasher, tag: []const u8, bytes: []const u8) void {
    updateTag(hasher, tag);
    updateU64(hasher, @intCast(bytes.len));
    hasher.update(bytes);
}

pub fn updateBool(hasher: *Hasher, tag: []const u8, value: bool) void {
    updateTag(hasher, tag);
    hasher.update(&.{if (value) 1 else 0});
}

pub fn updateEnum(hasher: *Hasher, tag: []const u8, value: anytype) void {
    updateTag(hasher, tag);
    updateU64(hasher, @intCast(@intFromEnum(value)));
}

pub fn updateInt(hasher: *Hasher, tag: []const u8, value: anytype) void {
    updateTag(hasher, tag);
    updateU64(hasher, @intCast(value));
}

pub fn updateU64(hasher: *Hasher, value: u64) void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, value, .little);
    hasher.update(&buffer);
}

fn updateTag(hasher: *Hasher, tag: []const u8) void {
    updateU64(hasher, @intCast(tag.len));
    hasher.update(tag);
}
