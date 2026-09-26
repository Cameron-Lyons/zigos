const std = @import("std");

pub const Error = error{ InvalidResponse, MessageTooLarge };
pub const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    pub fn put(self: *Writer, value: []const u8) Error!void {
        if (value.len > self.bytes.len - self.pos) return error.MessageTooLarge;
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }
    pub fn int(self: *Writer, comptime T: type, value: T) Error!void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .big);
        try self.put(&encoded);
    }
    pub fn sized(self: *Writer, value: []const u8) Error!void {
        if (value.len > std.math.maxInt(u16)) return error.MessageTooLarge;
        try self.int(u16, @intCast(value.len));
        try self.put(value);
    }
    pub fn begin(self: *Writer, tag: u16, code: u32) Error!void {
        self.pos = 0;
        try self.int(u16, tag);
        try self.int(u32, 0);
        try self.int(u32, code);
    }
    pub fn finish(self: *Writer) []u8 {
        std.debug.assert(self.pos >= 10);
        std.mem.writeInt(u32, self.bytes[2..6], @intCast(self.pos), .big);
        return self.bytes[0..self.pos];
    }
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn take(self: *Reader, count: usize) Error![]const u8 {
        if (count > self.bytes.len - self.pos) return error.InvalidResponse;
        const out = self.bytes[self.pos..][0..count];
        self.pos += count;
        return out;
    }
    pub fn int(self: *Reader, comptime T: type) Error!T {
        const bytes = try self.take(@sizeOf(T));
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .big);
    }
    pub fn sized(self: *Reader) Error![]const u8 {
        return self.take(try self.int(u16));
    }
    pub fn end(self: *Reader) Error!void {
        if (self.pos != self.bytes.len) return error.InvalidResponse;
    }
};

test "TPM wire cursors bound lengths and reject incomplete and trailing fields" {
    var bytes: [12]u8 = undefined;
    var w = Writer{ .bytes = &bytes };
    try w.begin(0x8001, 0x17a);
    try w.sized("");
    try std.testing.expectError(error.MessageTooLarge, w.int(u8, 1));
    const message = w.finish();
    try std.testing.expectEqual(@as(u32, 12), std.mem.readInt(u32, message[2..6], .big));
    var r = Reader{ .bytes = message[10..] };
    try std.testing.expectEqualStrings("", try r.sized());
    try r.end();
    try std.testing.expectError(error.InvalidResponse, r.int(u8));
    r = .{ .bytes = &.{ 0xff, 0xff, 0 } };
    try std.testing.expectError(error.InvalidResponse, r.sized());
    r = .{ .bytes = &.{0} };
    try std.testing.expectError(error.InvalidResponse, r.end());
}
