const std = @import("std");

pub const MAX_FRAME_BYTES = 88;
pub const MAX_LABEL_BYTES = 96;
pub const PAGE_ENTRIES = 4;
pub const MAX_PAGE_TEXT_BYTES = PAGE_ENTRIES * MAX_LABEL_BYTES + PAGE_ENTRIES - 1;
pub const CHUNK_BYTES = 64;
const MAGIC: u32 = 0x48434c5a;
pub const Status = enum(u8) { opened, cancelled, unavailable };
pub const Result = struct { status: Status, task_id: u64 = 0, window_id: u64 = 0 };
pub const Page = struct { window_id: u64, text_length: u16, count: u8, previous: bool, next: bool };
pub const Body = union(enum(u8)) {
    page: Page = 1,
    text: struct { offset: u16, bytes: []const u8 } = 2,
    open: u8 = 3,
    move: bool = 4,
    cancel: void = 5,
    result: Result = 6,
};
pub const Frame = struct { token: u64, body: Body };
pub const Error = error{MalformedFrame};

pub fn encode(out: *[MAX_FRAME_BYTES]u8, frame: Frame) Error![]const u8 {
    if (frame.token == 0) return error.MalformedFrame;
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], MAGIC, .little);
    out[4] = 2;
    out[5] = @intFromEnum(frame.body);
    std.mem.writeInt(u64, out[8..16], frame.token, .little);
    const length: usize = switch (frame.body) {
        .cancel => 16,
        .open => |index| blk: {
            if (index >= PAGE_ENTRIES) return error.MalformedFrame;
            out[16] = index;
            break :blk 20;
        },
        .move => |forward| blk: {
            out[16] = @intFromBool(forward);
            break :blk 20;
        },
        .page => |page| blk: {
            if (!validPage(page)) return error.MalformedFrame;
            std.mem.writeInt(u64, out[16..24], page.window_id, .little);
            std.mem.writeInt(u16, out[24..26], page.text_length, .little);
            out[26] = page.count;
            out[27] = @as(u8, @intFromBool(page.previous)) | (@as(u8, @intFromBool(page.next)) << 1);
            break :blk 32;
        },
        .text => |chunk| blk: {
            if (!validChunk(chunk.offset, chunk.bytes.len)) return error.MalformedFrame;
            std.mem.writeInt(u16, out[16..18], chunk.offset, .little);
            out[18] = @intCast(chunk.bytes.len);
            @memcpy(out[24..][0..chunk.bytes.len], chunk.bytes);
            break :blk 24 + chunk.bytes.len;
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
        std.mem.readInt(u32, bytes[0..4], .little) != MAGIC or bytes[4] != 2 or
        bytes[6] != 0 or bytes[7] != 0) return error.MalformedFrame;
    const token = std.mem.readInt(u64, bytes[8..16], .little);
    if (token == 0) return error.MalformedFrame;
    const tag = std.enums.fromInt(std.meta.Tag(Body), bytes[5]) orelse return error.MalformedFrame;
    const body: Body = switch (tag) {
        .cancel => blk: {
            if (bytes.len != 16) return error.MalformedFrame;
            break :blk .cancel;
        },
        .open, .move => blk: {
            if (bytes.len != 20 or !std.mem.allEqual(u8, bytes[17..20], 0)) return error.MalformedFrame;
            if (tag == .open) {
                if (bytes[16] >= PAGE_ENTRIES) return error.MalformedFrame;
                break :blk .{ .open = bytes[16] };
            }
            if (bytes[16] > 1) return error.MalformedFrame;
            break :blk .{ .move = bytes[16] == 1 };
        },
        .page => blk: {
            if (bytes.len != 32 or bytes[27] > 3 or !std.mem.allEqual(u8, bytes[28..32], 0)) return error.MalformedFrame;
            const page = Page{
                .window_id = std.mem.readInt(u64, bytes[16..24], .little),
                .text_length = std.mem.readInt(u16, bytes[24..26], .little),
                .count = bytes[26],
                .previous = bytes[27] & 1 != 0,
                .next = bytes[27] & 2 != 0,
            };
            if (!validPage(page)) return error.MalformedFrame;
            break :blk .{ .page = page };
        },
        .text => blk: {
            if (bytes.len < 24 or bytes.len != 24 + @as(usize, bytes[18]) or !std.mem.allEqual(u8, bytes[19..24], 0)) return error.MalformedFrame;
            const offset = std.mem.readInt(u16, bytes[16..18], .little);
            if (!validChunk(offset, bytes.len - 24)) return error.MalformedFrame;
            break :blk .{ .text = .{ .offset = offset, .bytes = bytes[24..] } };
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

pub fn validLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > MAX_LABEL_BYTES) return false;
    const view = std.unicode.Utf8View.init(label) catch return false;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x20 or (cp >= 0x7f and cp <= 0x9f) or cp == 0x2028 or cp == 0x2029) return false;
    }
    return true;
}

pub fn validPageText(text: []const u8, count: u8) bool {
    if (count == 0) return text.len == 0;
    if (count > PAGE_ENTRIES or text.len > MAX_PAGE_TEXT_BYTES) return false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var seen: usize = 0;
    while (lines.next()) |line| {
        if (!validLabel(line)) return false;
        seen += 1;
    }
    return seen == count;
}

fn validPage(page: Page) bool {
    if (page.window_id == 0 or page.count > PAGE_ENTRIES) return false;
    return if (page.count == 0) page.text_length == 0 and !page.next else page.text_length >= @as(usize, page.count) * 2 - 1 and page.text_length <= @as(usize, page.count) * MAX_LABEL_BYTES + page.count - 1;
}

fn validChunk(offset: u16, length: usize) bool {
    return length != 0 and length <= CHUNK_BYTES and @as(usize, offset) + length <= MAX_PAGE_TEXT_BYTES;
}

fn validResult(result: Result) bool {
    return if (result.status == .opened) result.task_id != 0 and result.window_id != 0 else result.task_id == 0 and result.window_id == 0;
}

const test_frames = [_]Frame{
    .{ .token = 1, .body = .{ .open = 3 } },
    .{ .token = 2, .body = .cancel },
    .{ .token = 3, .body = .{ .page = .{ .window_id = 4, .text_length = 5, .count = 1, .previous = false, .next = true } } },
    .{ .token = 4, .body = .{ .text = .{ .offset = 0, .bytes = "Notes" } } },
    .{ .token = 5, .body = .{ .result = .{ .status = .opened, .task_id = 5, .window_id = 6 } } },
    .{ .token = 6, .body = .{ .result = .{ .status = .cancelled } } },
    .{ .token = 7, .body = .{ .move = true } },
};

test "launcher protocol accepts only canonical bounded frames" {
    for (test_frames) |frame| {
        var bytes: [MAX_FRAME_BYTES]u8 = undefined;
        const encoded = try encode(&bytes, frame);
        for (0..encoded.len) |length| try std.testing.expectError(error.MalformedFrame, decode(encoded[0..length]));
        for (0..encoded.len) |offset| {
            for (0..256) |value| {
                var mutated = bytes;
                mutated[offset] = @intCast(value);
                const decoded = decode(mutated[0..encoded.len]) catch continue;
                var canonical: [MAX_FRAME_BYTES]u8 = undefined;
                try std.testing.expectEqualSlices(u8, mutated[0..encoded.len], try encode(&canonical, decoded));
            }
        }
    }
    var bytes: [MAX_FRAME_BYTES]u8 = undefined;
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .token = 0, .body = .cancel }));
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .token = 1, .body = .{ .open = 4 } }));
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .token = 1, .body = .{ .text = .{ .offset = MAX_PAGE_TEXT_BYTES, .bytes = "a" } } }));
    try std.testing.expect(validPageText("Notes\n文書", 2));
    try std.testing.expect(validPageText("a" ** MAX_LABEL_BYTES, 1));
    try std.testing.expect(!validPageText("a\nb", 1));
    try std.testing.expect(!validPageText("a\n", 2));
    try std.testing.expect(!validPageText("a\r", 1));
    try std.testing.expect(!validPageText("\xff", 1));
}
