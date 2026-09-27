const std = @import("std");

pub const MAX_FRAME_BYTES = 88;
pub const MAX_LABEL_BYTES = 60;
const MAGIC: u32 = 0x48434c5a;
pub const Status = enum(u8) { opened, cancelled, unavailable };
pub const Result = struct { status: Status, task_id: u64 = 0, window_id: u64 = 0 };
pub const Body = union(enum(u8)) {
    offer: struct { window_id: u64, label: []const u8 } = 1,
    open: void = 2,
    cancel: void = 3,
    result: Result = 4,
};
pub const Frame = struct { token: u64, body: Body };
pub const Error = error{MalformedFrame};

pub fn encode(out: *[MAX_FRAME_BYTES]u8, frame: Frame) Error![]const u8 {
    if (frame.token == 0) return error.MalformedFrame;
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], MAGIC, .little);
    out[4] = 1;
    out[5] = @intFromEnum(frame.body);
    std.mem.writeInt(u64, out[8..16], frame.token, .little);
    const length: usize = switch (frame.body) {
        .open, .cancel => 16,
        .offer => |offer| blk: {
            if (offer.window_id == 0 or !validLabel(offer.label)) return error.MalformedFrame;
            std.mem.writeInt(u64, out[16..24], offer.window_id, .little);
            out[24] = @intCast(offer.label.len);
            @memcpy(out[28..][0..offer.label.len], offer.label);
            break :blk 28 + offer.label.len;
        },
        .result => |result| blk: {
            if (!validResult(result)) return error.MalformedFrame;
            out[16] = @intFromEnum(result.status);
            std.mem.writeInt(u64, out[24..32], result.task_id, .little);
            std.mem.writeInt(u64, out[32..40], result.window_id, .little);
            break :blk 40;
        },
    };
    return out[0..length];
}

pub fn decode(bytes: []const u8) Error!Frame {
    if (bytes.len < 16 or bytes.len > MAX_FRAME_BYTES or
        std.mem.readInt(u32, bytes[0..4], .little) != MAGIC or bytes[4] != 1 or
        bytes[6] != 0 or bytes[7] != 0) return error.MalformedFrame;
    const token = std.mem.readInt(u64, bytes[8..16], .little);
    if (token == 0) return error.MalformedFrame;
    const tag = std.enums.fromInt(std.meta.Tag(Body), bytes[5]) orelse return error.MalformedFrame;
    const body: Body = switch (tag) {
        .open, .cancel => blk: {
            if (bytes.len != 16) return error.MalformedFrame;
            break :blk if (tag == .open) .open else .cancel;
        },
        .offer => blk: {
            if (bytes.len < 28 or bytes.len != 28 + @as(usize, bytes[24]) or
                !std.mem.allEqual(u8, bytes[25..28], 0)) return error.MalformedFrame;
            const window_id = std.mem.readInt(u64, bytes[16..24], .little);
            if (window_id == 0 or !validLabel(bytes[28..])) return error.MalformedFrame;
            break :blk .{ .offer = .{ .window_id = window_id, .label = bytes[28..] } };
        },
        .result => blk: {
            if (bytes.len != 40 or !std.mem.allEqual(u8, bytes[17..24], 0)) return error.MalformedFrame;
            const result = Result{
                .status = std.enums.fromInt(Status, bytes[16]) orelse return error.MalformedFrame,
                .task_id = std.mem.readInt(u64, bytes[24..32], .little),
                .window_id = std.mem.readInt(u64, bytes[32..40], .little),
            };
            if (!validResult(result)) return error.MalformedFrame;
            break :blk .{ .result = result };
        },
    };
    return .{ .token = token, .body = body };
}

fn validLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > MAX_LABEL_BYTES) return false;
    for (label) |byte| if (byte < 0x20 or byte > 0x7e) return false;
    return true;
}

fn validResult(result: Result) bool {
    return if (result.status == .opened) result.task_id != 0 and result.window_id != 0 else result.task_id == 0 and result.window_id == 0;
}

test "launcher protocol accepts only canonical bounded frames" {
    const frames = [_]Frame{
        .{ .token = 1, .body = .open },
        .{ .token = 2, .body = .cancel },
        .{ .token = 3, .body = .{ .offer = .{ .window_id = 4, .label = "Notes" } } },
        .{ .token = 4, .body = .{ .result = .{ .status = .opened, .task_id = 5, .window_id = 6 } } },
        .{ .token = 5, .body = .{ .result = .{ .status = .cancelled } } },
    };
    for (frames) |frame| {
        var bytes: [MAX_FRAME_BYTES]u8 = undefined;
        const encoded = try encode(&bytes, frame);
        const decoded = try decode(encoded);
        var canonical: [MAX_FRAME_BYTES]u8 = undefined;
        try std.testing.expectEqualSlices(u8, encoded, try encode(&canonical, decoded));
        for (0..encoded.len) |length| try std.testing.expectError(error.MalformedFrame, decode(encoded[0..length]));
        bytes[6] = 1;
        try std.testing.expectError(error.MalformedFrame, decode(encoded));
    }
    var bytes: [MAX_FRAME_BYTES]u8 = undefined;
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .token = 0, .body = .open }));
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .token = 1, .body = .{ .result = .{ .status = .cancelled, .task_id = 7 } } }));
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .token = 1, .body = .{ .offer = .{ .window_id = 1, .label = "bad\nlabel" } } }));
}

test "launcher protocol mutation decoding never accepts ambiguous bytes" {
    for ([_]Frame{
        .{ .token = 1, .body = .{ .offer = .{ .window_id = 2, .label = "Document" } } },
        .{ .token = 2, .body = .{ .result = .{ .status = .opened, .task_id = 3, .window_id = 4 } } },
    }) |frame| {
        var original: [MAX_FRAME_BYTES]u8 = undefined;
        const length = (try encode(&original, frame)).len;
        for (0..length) |offset| {
            for (0..256) |value| {
                var bytes = original;
                bytes[offset] = @intCast(value);
                const decoded = decode(bytes[0..length]) catch continue;
                var canonical: [MAX_FRAME_BYTES]u8 = undefined;
                try std.testing.expectEqualSlices(u8, bytes[0..length], try encode(&canonical, decoded));
            }
        }
    }
}
