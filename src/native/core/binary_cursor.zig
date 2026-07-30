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
            if (bytes.len > self.buffer.len - self.offset) return full_error;
            @memcpy(self.buffer[self.offset .. self.offset + bytes.len], bytes);
            self.offset += bytes.len;
        }

        fn writeInt(self: *Self, comptime T: type, value: T) ErrorSet!void {
            var bytes: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &bytes, value, .little);
            try self.writeBytes(&bytes);
        }

        pub fn writeU16(self: *Self, value: u16) ErrorSet!void {
            try self.writeInt(u16, value);
        }

        pub fn writeU32(self: *Self, value: u32) ErrorSet!void {
            try self.writeInt(u32, value);
        }

        pub fn writeU64(self: *Self, value: u64) ErrorSet!void {
            try self.writeInt(u64, value);
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
            if (dest.len > self.buffer.len - self.offset) return corrupt_error;
            @memcpy(dest, self.buffer[self.offset .. self.offset + dest.len]);
            self.offset += dest.len;
        }

        pub fn readSlice(self: *Self, len: usize) ErrorSet![]const u8 {
            if (len > self.buffer.len - self.offset) return corrupt_error;
            const slice = self.buffer[self.offset .. self.offset + len];
            self.offset += len;
            return slice;
        }

        pub fn remaining(self: *const Self) usize {
            return self.buffer.len - self.offset;
        }

        pub fn eof(self: *const Self) bool {
            return self.remaining() == 0;
        }

        fn readInt(self: *Self, comptime T: type) ErrorSet!T {
            var bytes: [@sizeOf(T)]u8 = undefined;
            try self.readBytes(&bytes);
            return std.mem.readInt(T, &bytes, .little);
        }

        pub fn readU16(self: *Self) ErrorSet!u16 {
            return self.readInt(u16);
        }

        pub fn readU32(self: *Self) ErrorSet!u32 {
            return self.readInt(u32);
        }

        pub fn readU64(self: *Self) ErrorSet!u64 {
            return self.readInt(u64);
        }
    };
}
