const std = @import("std");

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
