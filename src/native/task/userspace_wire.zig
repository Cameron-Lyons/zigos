const std = @import("std");

pub const CopyTextExactError = error{DestinationTooSmall};
pub const FNV1A_64_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
pub const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01B3;

pub fn copyTextExact(dest: []u8, src: []const u8) CopyTextExactError!usize {
    if (src.len > dest.len) return error.DestinationTooSmall;
    @memcpy(dest[0..src.len], src);
    return src.len;
}

pub fn Writer(comptime ErrorSet: type, comptime full_error: ErrorSet) type {
    return struct {
        buffer: []u8,
        offset: usize = 0,

        const Self = @This();

        pub fn writeByte(self: *Self, value: u8) ErrorSet!void {
            if (self.offset >= self.buffer.len) return full_error;
            self.buffer[self.offset] = value;
            self.offset += 1;
        }

        pub fn writeBytes(self: *Self, bytes: []const u8) ErrorSet!void {
            if (self.offset + bytes.len > self.buffer.len) return full_error;
            @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
            self.offset += bytes.len;
        }

        pub fn writeU16(self: *Self, value: u16) ErrorSet!void {
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, value, .little);
            try self.writeBytes(&bytes);
        }

        pub fn writeU32(self: *Self, value: u32) ErrorSet!void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, value, .little);
            try self.writeBytes(&bytes);
        }

        pub fn writeU64(self: *Self, value: u64) ErrorSet!void {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, value, .little);
            try self.writeBytes(&bytes);
        }
    };
}

pub fn Reader(comptime ErrorSet: type, comptime corrupt_error: ErrorSet) type {
    return struct {
        buffer: []const u8,
        offset: usize = 0,

        const Self = @This();

        pub fn readByte(self: *Self) ErrorSet!u8 {
            if (self.offset >= self.buffer.len) return corrupt_error;
            const value = self.buffer[self.offset];
            self.offset += 1;
            return value;
        }

        pub fn readBytes(self: *Self, dest: []u8) ErrorSet!void {
            if (self.offset + dest.len > self.buffer.len) return corrupt_error;
            @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
            self.offset += dest.len;
        }

        pub fn readSlice(self: *Self, len: usize) ErrorSet![]const u8 {
            if (self.offset + len > self.buffer.len) return corrupt_error;
            const slice = self.buffer[self.offset .. self.offset + len];
            self.offset += len;
            return slice;
        }

        pub fn readU16(self: *Self) ErrorSet!u16 {
            var bytes: [2]u8 = undefined;
            try self.readBytes(&bytes);
            return std.mem.readInt(u16, &bytes, .little);
        }

        pub fn readU32(self: *Self) ErrorSet!u32 {
            var bytes: [4]u8 = undefined;
            try self.readBytes(&bytes);
            return std.mem.readInt(u32, &bytes, .little);
        }

        pub fn readU64(self: *Self) ErrorSet!u64 {
            var bytes: [8]u8 = undefined;
            try self.readBytes(&bytes);
            return std.mem.readInt(u64, &bytes, .little);
        }
    };
}

pub fn fnv1a64(bytes: []const u8) u64 {
    return fnv1a64WithSeed(FNV1A_64_OFFSET_BASIS, bytes);
}

pub fn fnv1a64WithSeed(seed: u64, bytes: []const u8) u64 {
    var hash = seed;
    for (bytes) |byte| {
        hash = fnv1a64AppendByte(hash, byte);
    }
    return hash;
}

pub fn fnv1a64AppendByte(hash: u64, byte: u8) u64 {
    var next = hash;
    next ^= @as(u64, byte);
    next *%= FNV1A_64_PRIME;
    return next;
}

pub fn fnv1a64AppendU16LittleEndian(hash: u64, value: u16) u64 {
    return fnv1a64AppendIntegerLittleEndian(u16, hash, value);
}

pub fn fnv1a64AppendU32LittleEndian(hash: u64, value: u32) u64 {
    return fnv1a64AppendIntegerLittleEndian(u32, hash, value);
}

fn fnv1a64AppendIntegerLittleEndian(comptime T: type, hash: u64, value: T) u64 {
    var next = hash;
    var remaining = value;
    inline for (0..@sizeOf(T)) |_| {
        next = fnv1a64AppendByte(next, @as(u8, @truncate(remaining & 0xFF)));
        remaining >>= 8;
    }
    return next;
}

test "userspace wire cursor round-trips fixed and variable fields" {
    const Error = error{ Full, Corrupt };
    const TestWriter = Writer(Error, error.Full);
    const TestReader = Reader(Error, error.Corrupt);

    var buffer: [16]u8 = undefined;
    var writer = TestWriter{ .buffer = &buffer };
    try writer.writeByte(0xAB);
    try writer.writeU16(0x1234);
    try writer.writeU32(0x5678_9ABC);
    try writer.writeBytes("ok");

    var reader = TestReader{ .buffer = buffer[0..writer.offset] };
    try std.testing.expectEqual(@as(u8, 0xAB), try reader.readByte());
    try std.testing.expectEqual(@as(u16, 0x1234), try reader.readU16());
    try std.testing.expectEqual(@as(u32, 0x5678_9ABC), try reader.readU32());
    try std.testing.expectEqualStrings("ok", try reader.readSlice(2));
}

test "userspace wire exact copy and fnv integer helpers are explicit" {
    var buffer = [_]u8{0} ** 4;
    try std.testing.expectEqual(@as(usize, 4), try copyTextExact(&buffer, "zigo"));
    try std.testing.expectError(error.DestinationTooSmall, copyTextExact(buffer[0..3], "zigo"));

    const seeded = fnv1a64("seed");
    var manual = seeded;
    manual = fnv1a64AppendByte(manual, 0x78);
    manual = fnv1a64AppendByte(manual, 0x56);
    manual = fnv1a64AppendByte(manual, 0x34);
    manual = fnv1a64AppendByte(manual, 0x12);
    try std.testing.expectEqual(manual, fnv1a64AppendU32LittleEndian(seeded, 0x1234_5678));
}
