//! One assertion per native grant. A frame cannot choose its credential, user,
//! device, relying party, origin, unlock proof, lease or signing key.
const std = @import("std");

pub const MAX_FRAME_BYTES = 88;
pub const MAX_CHALLENGE_BYTES = 64;
pub const MAX_ASSERTION_BYTES = 384;
pub const CHUNK_BYTES = MAX_FRAME_BYTES - 20;
const MAGIC: u32 = 0x4449475a;
pub const Binding = struct { endpoint_capability_id: u64, service_endpoint_id: u64, credential_id: u64 };
pub const Status = enum(u16) { ok, denied, unavailable };
pub const Body = union(enum(u8)) {
    assert: []const u8 = 1,
    read: u16 = 2,
    finish: void = 3,
    reply: struct { status: Status, total: u16 = 0, offset: u16 = 0, bytes: []const u8 = "" } = 4,
};
pub const Frame = struct { request_id: u64, body: Body };
pub const Error = error{MalformedIdentityFrame};

pub fn encode(out: *[MAX_FRAME_BYTES]u8, frame: Frame) Error![]const u8 {
    if (frame.request_id == 0) return error.MalformedIdentityFrame;
    @memset(out, 0);
    put(u32, out, MAGIC);
    out[4] = 1;
    out[5] = @intFromEnum(frame.body);
    put(u64, out[8..], frame.request_id);
    const length: usize = switch (frame.body) {
        .assert => |challenge| blk: {
            if (challenge.len == 0 or challenge.len > MAX_CHALLENGE_BYTES) return error.MalformedIdentityFrame;
            @memcpy(out[16..][0..challenge.len], challenge);
            break :blk 16 + challenge.len;
        },
        .read => |offset| blk: {
            if (offset == 0 or offset >= MAX_ASSERTION_BYTES) return error.MalformedIdentityFrame;
            put(u16, out[16..], offset);
            break :blk 18;
        },
        .finish => 16,
        .reply => |reply| blk: {
            if (reply.total > MAX_ASSERTION_BYTES or reply.offset > reply.total or reply.bytes.len > CHUNK_BYTES or
                reply.bytes.len > reply.total - reply.offset or
                (reply.status == .ok and (reply.total == 0 or reply.bytes.len == 0)) or
                (reply.status != .ok and (reply.total != 0 or reply.offset != 0 or reply.bytes.len != 0))) return error.MalformedIdentityFrame;
            put(u16, out[6..], @intFromEnum(reply.status));
            put(u16, out[16..], reply.total);
            put(u16, out[18..], reply.offset);
            @memcpy(out[20..][0..reply.bytes.len], reply.bytes);
            break :blk 20 + reply.bytes.len;
        },
    };
    return out[0..length];
}

pub fn decode(bytes: []const u8) Error!Frame {
    if (bytes.len < 16 or bytes.len > MAX_FRAME_BYTES or get(u32, bytes) != MAGIC or bytes[4] != 1) return error.MalformedIdentityFrame;
    const tag = std.enums.fromInt(std.meta.Tag(Body), bytes[5]) orelse return error.MalformedIdentityFrame;
    if (tag != .reply and get(u16, bytes[6..]) != 0) return error.MalformedIdentityFrame;
    const body: Body = switch (tag) {
        .assert => .{ .assert = bytes[16..] },
        .read => if (bytes.len == 18) .{ .read = get(u16, bytes[16..]) } else return error.MalformedIdentityFrame,
        .finish => if (bytes.len == 16) .{ .finish = {} } else return error.MalformedIdentityFrame,
        .reply => if (bytes.len >= 20) .{ .reply = .{
            .status = std.enums.fromInt(Status, get(u16, bytes[6..])) orelse return error.MalformedIdentityFrame,
            .total = get(u16, bytes[16..]),
            .offset = get(u16, bytes[18..]),
            .bytes = bytes[20..],
        } } else return error.MalformedIdentityFrame,
    };
    const frame = Frame{ .request_id = get(u64, bytes[8..]), .body = body };
    var canonical: [MAX_FRAME_BYTES]u8 = undefined;
    if (!std.mem.eql(u8, bytes, try encode(&canonical, frame))) return error.MalformedIdentityFrame;
    return frame;
}

fn put(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, out[0..@sizeOf(T)], value, .little);
}
fn get(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
}

test "identity protocol frames never carry native authority and enforce exact bounds" {
    const frames = [_]Frame{
        .{ .request_id = 1, .body = .{ .assert = "challenge" } },
        .{ .request_id = 2, .body = .{ .read = 68 } },
        .{ .request_id = 3, .body = .finish },
        .{ .request_id = 4, .body = .{ .reply = .{ .status = .ok, .total = 100, .bytes = "signed bytes" } } },
        .{ .request_id = 5, .body = .{ .reply = .{ .status = .denied } } },
    };
    for (frames) |frame| {
        var bytes: [MAX_FRAME_BYTES]u8 = undefined;
        const encoded = try encode(&bytes, frame);
        var copy: [MAX_FRAME_BYTES]u8 = undefined;
        try std.testing.expectEqualSlices(u8, encoded, try encode(&copy, try decode(encoded)));
        for (0..16) |length| try std.testing.expectError(error.MalformedIdentityFrame, decode(encoded[0..length]));
        bytes[4] = 0;
        try std.testing.expectError(error.MalformedIdentityFrame, decode(encoded));
    }
    var out: [MAX_FRAME_BYTES]u8 = undefined;
    try std.testing.expectError(error.MalformedIdentityFrame, encode(&out, .{ .request_id = 0, .body = .finish }));
    try std.testing.expectError(error.MalformedIdentityFrame, encode(&out, .{ .request_id = 1, .body = .{ .assert = "" } }));
    try std.testing.expectError(error.MalformedIdentityFrame, encode(&out, .{ .request_id = 1, .body = .{ .assert = &(@as([65]u8, @splat(1))) } }));
    try std.testing.expectError(error.MalformedIdentityFrame, encode(&out, .{ .request_id = 1, .body = .{ .reply = .{ .status = .denied, .total = 1, .bytes = "x" } } }));
}
