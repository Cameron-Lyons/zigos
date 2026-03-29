const std = @import("std");

pub const Hasher = std.crypto.hash.sha2.Sha256;

pub fn init() Hasher {
    return Hasher.init(.{});
}

pub fn finalize(hasher: *Hasher) [32]u8 {
    var digest: [32]u8 = undefined;
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
