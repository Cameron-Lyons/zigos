//! Bounded TCG2 event-log prefix through the loader's boot measurement.
//! This snapshot precedes ExitBootServices. It is not a TPM quote or the final
//! firmware log; callers must compare its PCR 11 replay with the live TPM.
const std = @import("std");
const image_info = @import("image_info.zig");
pub const pcr = @import("tpm_pcr.zig");
pub const MAX_BYTES = 256 * 1024;
pub const MAX_ALGORITHMS = 8;
pub const EV_NO_ACTION = 3;
pub const EV_EVENT_TAG = 6;
pub const BOOT_EVENT_ID: u32 = 0x5a470001;
pub const DESCRIPTION_BYTES = 80;
pub const EVENT_BYTES = 18 + 8 + DESCRIPTION_BYTES;
pub const Error = error{ InvalidEventLog, UnsupportedEventLog, BootMeasurementMismatch };

pub fn description(info: image_info.Info) [DESCRIPTION_BYTES]u8 {
    var bytes: [DESCRIPTION_BYTES]u8 = @splat(0);
    @memcpy(bytes[0..8], "ZGBOOT01");
    std.mem.writeInt(u32, bytes[8..12], 1, .little);
    std.mem.writeInt(u32, bytes[12..16], @intFromBool(info.firmware_authenticated), .little);
    @memcpy(bytes[16..48], &info.kernel_digest);
    @memcpy(bytes[48..80], &info.cmdline_digest);
    return bytes;
}

pub fn event(info: image_info.Info) [EVENT_BYTES]u8 {
    var bytes: [EVENT_BYTES]u8 = @splat(0);
    std.mem.writeInt(u32, bytes[0..4], EVENT_BYTES, .little);
    std.mem.writeInt(u32, bytes[4..8], 14, .little); // packed EFI_TCG2_EVENT_HEADER
    std.mem.writeInt(u16, bytes[8..10], 1, .little);
    std.mem.writeInt(u32, bytes[10..14], pcr.INDEX, .little);
    std.mem.writeInt(u32, bytes[14..18], EV_EVENT_TAG, .little);
    std.mem.writeInt(u32, bytes[18..22], BOOT_EVENT_ID, .little);
    std.mem.writeInt(u32, bytes[22..26], DESCRIPTION_BYTES, .little);
    @memcpy(bytes[26..], &description(info));
    return bytes;
}

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (n > self.bytes.len - self.pos) return error.InvalidEventLog;
        const result = self.bytes[self.pos..][0..n];
        self.pos += n;
        return result;
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
};

const Algorithm = struct { id: u16, bytes: u16 };
pub const Entry = struct { index: u32, kind: u32, sha256: ?pcr.Digest, data: []const u8 };
pub const Iterator = struct {
    reader: Reader,
    algorithms: [MAX_ALGORITHMS]Algorithm = undefined,
    algorithm_count: usize = 0,

    pub fn init(bytes: []const u8) Error!Iterator {
        if (bytes.len > MAX_BYTES) return error.InvalidEventLog;
        var self = Iterator{ .reader = .{ .bytes = bytes } };
        // The first entry uses the legacy framing solely to describe TCG2
        // digest sizes. Legacy SHA-1-only event streams are not supported.
        if (try self.reader.int(u32) != 0 or try self.reader.int(u32) != EV_NO_ACTION or
            !std.mem.allEqual(u8, try self.reader.take(20), 0)) return error.InvalidEventLog;
        var spec = Reader{ .bytes = try self.reader.take(try self.reader.int(u32)) };
        if (!std.mem.eql(u8, try spec.take(16), "Spec ID Event03\x00")) return error.UnsupportedEventLog;
        _ = try spec.int(u32); // platform class
        const minor = try spec.int(u8);
        const major = try spec.int(u8);
        _ = try spec.int(u8); // errata
        const uintn = try spec.int(u8);
        if (major != 2 or minor != 0 or (uintn != 1 and uintn != 2)) return error.UnsupportedEventLog;
        self.algorithm_count = try spec.int(u32);
        if (self.algorithm_count == 0 or self.algorithm_count > MAX_ALGORITHMS) return error.InvalidEventLog;
        var sha256 = false;
        for (self.algorithms[0..self.algorithm_count], 0..) |*algorithm, index| {
            algorithm.* = .{ .id = try spec.int(u16), .bytes = try spec.int(u16) };
            if (algorithm.bytes == 0 or algorithm.bytes > 64) return error.UnsupportedEventLog;
            for (self.algorithms[0..index]) |prior| if (prior.id == algorithm.id) return error.InvalidEventLog;
            if (algorithm.id == pcr.SHA256) {
                if (algorithm.bytes != 32) return error.InvalidEventLog;
                sha256 = true;
            }
        }
        if (!sha256) return error.UnsupportedEventLog;
        _ = try spec.take(try spec.int(u8));
        if (spec.pos != spec.bytes.len) return error.InvalidEventLog;
        return self;
    }

    pub fn next(self: *Iterator) Error!?Entry {
        if (self.reader.pos == self.reader.bytes.len) return null;
        const index = try self.reader.int(u32);
        const kind = try self.reader.int(u32);
        const count = try self.reader.int(u32);
        if (index > 23 or count == 0 or count > self.algorithm_count) return error.InvalidEventLog;
        var seen: u8 = 0;
        var digest: ?pcr.Digest = null;
        for (0..count) |_| {
            const id = try self.reader.int(u16);
            const slot = for (self.algorithms[0..self.algorithm_count], 0..) |algorithm, slot| {
                if (algorithm.id == id) break slot;
            } else return error.InvalidEventLog;
            const bit = @as(u8, 1) << @as(u3, @intCast(slot));
            if (seen & bit != 0) return error.InvalidEventLog;
            seen |= bit;
            const bytes = try self.reader.take(self.algorithms[slot].bytes);
            if (id == pcr.SHA256) digest = bytes[0..32].*;
        }
        const data = try self.reader.take(try self.reader.int(u32));
        return .{ .index = index, .kind = kind, .sha256 = digest, .data = data };
    }
};

// Firmware returns the START of its last event, not the used byte count. Never
// include allocator padding, infer an end from zero bytes, or truncate events.
pub fn usedLength(bytes: []const u8, last_offset: usize) Error!usize {
    var iter = try Iterator.init(bytes);
    if (last_offset < iter.reader.pos or last_offset >= bytes.len) return error.InvalidEventLog;
    while (iter.reader.pos <= last_offset) {
        const start = iter.reader.pos;
        _ = try iter.next() orelse return error.InvalidEventLog;
        if (start == last_offset) return iter.reader.pos;
    }
    return error.InvalidEventLog;
}

pub fn replay(bytes: []const u8, info: image_info.Info) Error!pcr.Digest {
    var iter = try Iterator.init(bytes);
    var result: pcr.Digest = @splat(0);
    var found = false;
    const expected = event(info);
    const measured = description(info);
    var expected_digest: pcr.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&measured, &expected_digest, .{});
    while (try iter.next()) |entry| {
        if (entry.index != pcr.INDEX or entry.kind == EV_NO_ACTION) continue;
        const digest = entry.sha256 orelse return error.InvalidEventLog;
        // No later PCR 11 event may escape the descriptor carried to the kernel.
        if (found) return error.BootMeasurementMismatch;
        if (entry.kind == EV_EVENT_TAG and entry.data.len >= 4 and
            std.mem.readInt(u32, entry.data[0..4], .little) == BOOT_EVENT_ID)
        {
            if (!std.mem.eql(u8, entry.data, expected[18..]) or !std.mem.eql(u8, &digest, &expected_digest)) return error.BootMeasurementMismatch;
            found = true;
        }
        result = pcr.extend(result, digest);
    }
    if (!found) return error.BootMeasurementMismatch;
    return result;
}

fn fixture(info: image_info.Info, out: []u8) []const u8 {
    @memset(out, 0);
    std.mem.writeInt(u32, out[4..8], EV_NO_ACTION, .little);
    std.mem.writeInt(u32, out[28..32], 33, .little);
    @memcpy(out[32..48], "Spec ID Event03\x00");
    out[53] = 2;
    out[55] = 2;
    out[56] = 1;
    out[60] = pcr.SHA256;
    out[62] = 32;
    const offset = 65;
    std.mem.writeInt(u32, out[offset..][0..4], pcr.INDEX, .little);
    std.mem.writeInt(u32, out[offset + 4 ..][0..4], EV_EVENT_TAG, .little);
    out[offset + 8] = 1;
    out[offset + 12] = pcr.SHA256;
    std.crypto.hash.sha2.Sha256.hash(&description(info), out[offset + 14 ..][0..32], .{});
    const encoded = event(info);
    std.mem.writeInt(u32, out[offset + 46 ..][0..4], encoded.len - 18, .little);
    @memcpy(out[offset + 50 ..][0 .. encoded.len - 18], encoded[18..]);
    return out[0 .. offset + 50 + encoded.len - 18];
}

test "TCG2 replay binds kernel options and authentication while excluding heap placement" {
    const info = image_info.Info.measure("kernel", "cmdline", true, 0x4000000);
    var buffer: [512]u8 = undefined;
    const bytes = fixture(info, &buffer);
    const digest = try replay(bytes, info);
    var expected: pcr.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&description(info), &expected, .{});
    try std.testing.expectEqual(pcr.extend(@splat(0), expected), digest);
    try std.testing.expectEqual(bytes.len, try usedLength(&buffer, 65));
    var moved = info;
    moved.heap_base += 4096;
    try std.testing.expectEqual(digest, try replay(bytes, moved));
    for (0..3) |kind| {
        var changed = info;
        switch (kind) {
            0 => changed.kernel_digest[0] ^= 1,
            1 => changed.cmdline_digest[0] ^= 1,
            else => changed.firmware_authenticated = false,
        }
        try std.testing.expectError(error.BootMeasurementMismatch, replay(bytes, changed));
    }
}

test "TCG2 log rejects truncated framing, substituted digests and incorrect last-entry pointers" {
    const info = image_info.Info.measure("kernel", "cmdline", false, 0x4000000);
    var buffer: [512]u8 = undefined;
    const bytes = fixture(info, &buffer);
    for (0..bytes.len) |length| {
        if (replay(bytes[0..length], info)) |_| return error.AcceptedTruncatedEventLog else |_| {}
    }
    for ([_]usize{ 0, 31, 64, 66, bytes.len - 1, bytes.len, buffer.len }) |offset|
        try std.testing.expectError(error.InvalidEventLog, usedLength(&buffer, offset));
    for ([_]usize{ 0, 4, 8, 28, 32, 53, 55, 56, 60, 62, 64, 65, 69, 73, 77, 79, 110, 111, 115, 119, 123, 139, 171 }) |offset| {
        buffer[offset] ^= 0x80;
        if (replay(bytes, info)) |_| return error.AcceptedMalformedEventLog else |_| {}
        buffer[offset] ^= 0x80;
    }
    try std.testing.expectError(error.InvalidEventLog, replay(&buffer, info));
}

test "TCG2 replay includes earlier PCR extensions and refuses duplicate or later boot events" {
    const info = image_info.Info.measure("kernel", "cmdline", false, 0x4000000);
    var original: [512]u8 = undefined;
    const bytes = fixture(info, &original);
    var buffer: [512]u8 = @splat(0);
    @memcpy(buffer[0..65], bytes[0..65]);
    @memcpy(buffer[65..115], bytes[65..115]);
    std.mem.writeInt(u32, buffer[69..73], 5, .little); // EV_ACTION
    @memset(buffer[79..111], 0x5a);
    @memset(buffer[111..115], 0); // zero event data, digest is authoritative
    @memcpy(buffer[115..][0 .. bytes.len - 65], bytes[65..]);
    const prefixed = buffer[0 .. bytes.len + 50];
    var measured: pcr.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&description(info), &measured, .{});
    const expected = pcr.extend(pcr.extend(@splat(0), @splat(0x5a)), measured);
    try std.testing.expectEqual(expected, try replay(prefixed, info));
    // Other PCRs and EV_NO_ACTION do not extend PCR 11.
    std.mem.writeInt(u32, buffer[65..69], 7, .little);
    try std.testing.expectEqual(try replay(bytes, info), try replay(prefixed, info));
    std.mem.writeInt(u32, buffer[65..69], pcr.INDEX, .little);
    std.mem.writeInt(u32, buffer[69..73], EV_NO_ACTION, .little);
    try std.testing.expectEqual(try replay(bytes, info), try replay(prefixed, info));
    @memcpy(buffer[0..bytes.len], bytes);
    @memcpy(buffer[bytes.len..][0 .. bytes.len - 65], bytes[65..]);
    const duplicated = buffer[0 .. 2 * bytes.len - 65];
    try std.testing.expectError(error.BootMeasurementMismatch, replay(duplicated, info));
    std.mem.writeInt(u32, buffer[bytes.len + 4 ..][0..4], 5, .little);
    try std.testing.expectError(error.BootMeasurementMismatch, replay(duplicated, info));
}

test "TCG2 log handles multiple digest banks and rejects duplicate or unknown algorithms" {
    const info = image_info.Info.measure("kernel", "cmdline", false, 0x4000000);
    var original: [512]u8 = undefined;
    const bytes = fixture(info, &original);
    var buffer: [512]u8 = @splat(0);
    @memcpy(buffer[0..64], bytes[0..64]);
    buffer[28] = 37; // Spec ID payload with two algorithms
    buffer[56] = 2;
    buffer[64] = 4; // SHA-1 digest framing is retained for firmware bank traversal.
    buffer[66] = 20;
    @memcpy(buffer[69..115], bytes[65..111]);
    buffer[77] = 2; // two digests in this event
    buffer[115] = 4;
    @memset(buffer[117..137], 0x55);
    @memcpy(buffer[137..][0 .. bytes.len - 111], bytes[111..]);
    const multiple = buffer[0 .. bytes.len + 26];
    try std.testing.expectEqual(try replay(bytes, info), try replay(multiple, info));
    buffer[115] = pcr.SHA256;
    try std.testing.expectError(error.InvalidEventLog, replay(multiple, info));
    buffer[115] = 0xff;
    try std.testing.expectError(error.InvalidEventLog, replay(multiple, info));
    buffer[115] = 4;
    buffer[64] = pcr.SHA256;
    try std.testing.expectError(error.InvalidEventLog, replay(multiple, info));
}
