const std = @import("std");

pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_FRAME_BYTES: usize = 88;
pub const CHUNK_BYTES: usize = MAX_FRAME_BYTES - 20;
const MAGIC: u32 = 0x504c435a;
const VERSION: u8 = 2;

pub const Status = enum(u16) { ok, denied, empty, invalid, unavailable, expired };
pub const Reply = struct { status: Status, total: u16 = 0, offset: u16 = 0, bytes: []const u8 = "" };
pub const Body = union(enum(u8)) {
    copy_begin: u16 = 1,
    copy_chunk: struct { offset: u16, bytes: []const u8 } = 2,
    copy_commit: void = 3,
    paste: void = 4,
    paste_read: u16 = 5,
    reply: Reply = 6,
};
pub const Frame = struct { gesture: u64, body: Body };
pub const Error = error{MalformedFrame};

// A transport fragment may begin/end inside a scalar. Validate the assembled
// document at commit and paste completion, before publishing any bytes.
fn validFragment(bytes: []const u8) bool {
    for (bytes) |byte| if ((byte < 0x20 and byte != '\n' and byte != '\r' and byte != '\t') or byte == 0x7f) return false;
    return true;
}

pub fn encode(out: *[MAX_FRAME_BYTES]u8, frame: Frame) Error![]const u8 {
    if (frame.gesture == 0) return error.MalformedFrame;
    @memset(out, 0);
    put(u32, out, MAGIC);
    out[4] = VERSION;
    out[5] = @backingInt(frame.body);
    put(u64, out[8..], frame.gesture);
    const length: usize = switch (frame.body) {
        .copy_begin => |length| blk: {
            if (length == 0 or length > MAX_TEXT_BYTES) return error.MalformedFrame;
            put(u16, out[16..], length);
            break :blk 18;
        },
        .copy_chunk => |chunk| blk: {
            if (chunk.bytes.len == 0 or chunk.bytes.len > CHUNK_BYTES or chunk.offset >= MAX_TEXT_BYTES or
                chunk.bytes.len > MAX_TEXT_BYTES - chunk.offset or !validFragment(chunk.bytes)) return error.MalformedFrame;
            put(u16, out[16..], chunk.offset);
            put(u16, out[18..], @intCast(chunk.bytes.len));
            @memcpy(out[20..][0..chunk.bytes.len], chunk.bytes);
            break :blk 20 + chunk.bytes.len;
        },
        .copy_commit, .paste => 16,
        .paste_read => |offset| blk: {
            if (offset == 0 or offset >= MAX_TEXT_BYTES) return error.MalformedFrame;
            put(u16, out[16..], offset);
            break :blk 18;
        },
        .reply => |reply| blk: {
            if (reply.total > MAX_TEXT_BYTES or reply.offset > reply.total or reply.bytes.len > CHUNK_BYTES or
                reply.bytes.len > reply.total - reply.offset or !validFragment(reply.bytes) or
                (reply.status != .ok and (reply.total != 0 or reply.offset != 0 or reply.bytes.len != 0))) return error.MalformedFrame;
            put(u16, out[6..], @backingInt(reply.status));
            put(u16, out[16..], reply.total);
            put(u16, out[18..], reply.offset);
            @memcpy(out[20..][0..reply.bytes.len], reply.bytes);
            break :blk 20 + reply.bytes.len;
        },
    };
    return out[0..length];
}

pub fn decode(bytes: []const u8) Error!Frame {
    if (bytes.len < 16 or bytes.len > MAX_FRAME_BYTES or get(u32, bytes) != MAGIC or bytes[4] != VERSION)
        return error.MalformedFrame;
    const tag = std.enums.fromInt(std.meta.Tag(Body), bytes[5]) orelse return error.MalformedFrame;
    if (tag != .reply and get(u16, bytes[6..]) != 0) return error.MalformedFrame;
    const body: Body = switch (tag) {
        .copy_begin => if (bytes.len == 18) .{ .copy_begin = get(u16, bytes[16..]) } else return error.MalformedFrame,
        .copy_chunk => blk: {
            if (bytes.len < 21 or get(u16, bytes[18..]) != bytes.len - 20) return error.MalformedFrame;
            break :blk .{ .copy_chunk = .{ .offset = get(u16, bytes[16..]), .bytes = bytes[20..] } };
        },
        .copy_commit => if (bytes.len == 16) .{ .copy_commit = {} } else return error.MalformedFrame,
        .paste => if (bytes.len == 16) .{ .paste = {} } else return error.MalformedFrame,
        .paste_read => if (bytes.len == 18) .{ .paste_read = get(u16, bytes[16..]) } else return error.MalformedFrame,
        .reply => blk: {
            if (bytes.len < 20) return error.MalformedFrame;
            break :blk .{ .reply = .{
                .status = std.enums.fromInt(Status, get(u16, bytes[6..])) orelse return error.MalformedFrame,
                .total = get(u16, bytes[16..]),
                .offset = get(u16, bytes[18..]),
                .bytes = bytes[20..],
            } };
        },
    };
    const frame = Frame{ .gesture = get(u64, bytes[8..]), .body = body };
    // One canonical representation; decoding also enforces all semantic bounds.
    var canonical: [MAX_FRAME_BYTES]u8 = undefined;
    const encoded = try encode(&canonical, frame);
    if (!std.mem.eql(u8, bytes, encoded)) return error.MalformedFrame;
    return frame;
}

fn put(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, out[0..@sizeOf(T)], value, .little);
}
fn get(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
}

test "clipboard protocol accepts only bounded canonical text frames" {
    const seeds = [_]Frame{
        .{ .gesture = 1, .body = .{ .copy_begin = 512 } },
        .{ .gesture = 2, .body = .{ .copy_chunk = .{ .offset = 4, .bytes = "hello\n" } } },
        .{ .gesture = 3, .body = .{ .copy_commit = {} } },
        .{ .gesture = 4, .body = .{ .paste = {} } },
        .{ .gesture = 5, .body = .{ .paste_read = 68 } },
        .{ .gesture = 6, .body = .{ .reply = .{ .status = .ok, .total = 5, .bytes = "hello" } } },
        .{ .gesture = 7, .body = .{ .reply = .{ .status = .denied } } },
    };
    for (seeds) |seed| {
        var buffer: [MAX_FRAME_BYTES]u8 = undefined;
        const encoded = try encode(&buffer, seed);
        _ = try decode(encoded);
        // Replies have variable payloads, so a shortened payload is a valid
        // frame; transfer state separately checks the required chunk size.
        for (0..@min(encoded.len, 16)) |length| try std.testing.expectError(error.MalformedFrame, decode(encoded[0..length]));
        for (0..encoded.len) |index| {
            for ([_]u8{ 1, 0x80, 0xff }) |mask| {
                var mutated = buffer;
                mutated[index] ^= mask;
                const frame = decode(mutated[0..encoded.len]) catch continue;
                var canonical: [MAX_FRAME_BYTES]u8 = undefined;
                try std.testing.expectEqualSlices(u8, mutated[0..encoded.len], try encode(&canonical, frame));
            }
        }
    }
    var buffer: [MAX_FRAME_BYTES]u8 = undefined;
    try std.testing.expectError(error.MalformedFrame, encode(&buffer, .{ .gesture = 1, .body = .{ .copy_begin = 513 } }));
    try std.testing.expectError(error.MalformedFrame, encode(&buffer, .{ .gesture = 1, .body = .{ .copy_chunk = .{ .offset = 511, .bytes = "ab" } } }));
    try std.testing.expectError(error.MalformedFrame, encode(&buffer, .{ .gesture = 1, .body = .{ .copy_chunk = .{ .offset = 0, .bytes = "\x1b" } } }));
}
