const std = @import("std");

pub const MAX_DOCUMENT_BYTES: usize = 512;
pub const MAX_FRAME_BYTES: usize = 96;
pub const CHUNK_BYTES: usize = MAX_FRAME_BYTES - 20;
pub const Digest = [32]u8;
const MAGIC: u32 = 0x434f445a;
const VERSION: u8 = 1;

pub const Status = enum(u16) {
    saved,
    invalid_request,
    busy,
    stale_request,
    request_conflict,
    incomplete,
    permission_denied,
    document_changed,
    durability_failed,
    storage_failed,
};

pub const Begin = struct {
    expected_version_id: u64,
    length: u16,
    digest: Digest,

    pub fn eql(self: Begin, other: Begin) bool {
        return self.expected_version_id == other.expected_version_id and
            self.length == other.length and std.mem.eql(u8, &self.digest, &other.digest);
    }
};

pub const Receipt = struct {
    status: Status,
    object_id: u64 = 0,
    previous_version_id: u64 = 0,
    version_id: u64 = 0,
    checkpoint_generation: u64 = 0,
};

pub const Body = union(enum(u8)) {
    begin: Begin = 1,
    chunk: struct { offset: u16, bytes: []const u8 } = 2,
    commit: void = 3,
    receipt: Receipt = 4,
};

pub const Frame = struct { request_id: u64, body: Body };
pub const Error = error{MalformedFrame};

pub fn digest(bytes: []const u8) Digest {
    var out: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}

pub fn encode(out: *[MAX_FRAME_BYTES]u8, frame: Frame) Error![]const u8 {
    if (frame.request_id == 0) return error.MalformedFrame;
    @memset(out, 0);
    put(u32, out[0..], MAGIC);
    out[4] = VERSION;
    out[5] = @intFromEnum(frame.body);
    put(u64, out[8..], frame.request_id);
    const length: usize = switch (frame.body) {
        .begin => |begin| blk: {
            if (begin.expected_version_id == 0 or begin.length > MAX_DOCUMENT_BYTES) return error.MalformedFrame;
            put(u64, out[16..], begin.expected_version_id);
            put(u16, out[24..], begin.length);
            @memcpy(out[26..58], &begin.digest);
            break :blk 58;
        },
        .chunk => |chunk| blk: {
            if (chunk.bytes.len == 0 or chunk.bytes.len > CHUNK_BYTES or
                chunk.offset > MAX_DOCUMENT_BYTES or chunk.bytes.len > MAX_DOCUMENT_BYTES - chunk.offset) return error.MalformedFrame;
            put(u16, out[16..], chunk.offset);
            put(u16, out[18..], @intCast(chunk.bytes.len));
            @memcpy(out[20..][0..chunk.bytes.len], chunk.bytes);
            break :blk 20 + chunk.bytes.len;
        },
        .commit => 16,
        .receipt => |receipt| blk: {
            if (!canonicalReceipt(receipt)) return error.MalformedFrame;
            put(u16, out[16..], @intFromEnum(receipt.status));
            put(u64, out[20..], receipt.object_id);
            put(u64, out[28..], receipt.previous_version_id);
            put(u64, out[36..], receipt.version_id);
            put(u64, out[44..], receipt.checkpoint_generation);
            break :blk 52;
        },
    };
    return out[0..length];
}

pub fn decode(bytes: []const u8) Error!Frame {
    if (bytes.len < 16 or bytes.len > MAX_FRAME_BYTES or
        get(u32, bytes) != MAGIC or bytes[4] != VERSION or get(u16, bytes[6..]) != 0) return error.MalformedFrame;
    const request_id = get(u64, bytes[8..]);
    if (request_id == 0) return error.MalformedFrame;
    const tag = std.enums.fromInt(std.meta.Tag(Body), bytes[5]) orelse return error.MalformedFrame;
    const body: Body = switch (tag) {
        .begin => blk: {
            if (bytes.len != 58) return error.MalformedFrame;
            const expected_version_id = get(u64, bytes[16..]);
            const length = get(u16, bytes[24..]);
            if (expected_version_id == 0 or length > MAX_DOCUMENT_BYTES) return error.MalformedFrame;
            break :blk .{ .begin = .{ .expected_version_id = expected_version_id, .length = length, .digest = bytes[26..58].* } };
        },
        .chunk => blk: {
            if (bytes.len < 21) return error.MalformedFrame;
            const offset = get(u16, bytes[16..]);
            const length = get(u16, bytes[18..]);
            if (length == 0 or length > CHUNK_BYTES or bytes.len != 20 + @as(usize, length) or
                offset > MAX_DOCUMENT_BYTES or length > MAX_DOCUMENT_BYTES - offset) return error.MalformedFrame;
            break :blk .{ .chunk = .{ .offset = offset, .bytes = bytes[20..] } };
        },
        .commit => blk: {
            if (bytes.len != 16) return error.MalformedFrame;
            break :blk .{ .commit = {} };
        },
        .receipt => blk: {
            if (bytes.len != 52 or get(u16, bytes[18..]) != 0) return error.MalformedFrame;
            const receipt = Receipt{
                .status = std.enums.fromInt(Status, get(u16, bytes[16..])) orelse return error.MalformedFrame,
                .object_id = get(u64, bytes[20..]),
                .previous_version_id = get(u64, bytes[28..]),
                .version_id = get(u64, bytes[36..]),
                .checkpoint_generation = get(u64, bytes[44..]),
            };
            if (!canonicalReceipt(receipt)) return error.MalformedFrame;
            break :blk .{ .receipt = receipt };
        },
    };
    return .{ .request_id = request_id, .body = body };
}

fn canonicalReceipt(receipt: Receipt) bool {
    if (receipt.status == .saved) return receipt.object_id != 0 and receipt.previous_version_id != 0 and
        receipt.version_id != 0 and receipt.version_id != receipt.previous_version_id and receipt.checkpoint_generation != 0;
    return receipt.object_id == 0 and receipt.previous_version_id == 0 and receipt.version_id == 0 and receipt.checkpoint_generation == 0;
}

fn put(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, out[0..@sizeOf(T)], value, .little);
}

fn get(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
}

test "document protocol rejects truncation padding and noncanonical receipts" {
    var bytes: [MAX_FRAME_BYTES]u8 = undefined;
    const encoded = try encode(&bytes, .{ .request_id = 7, .body = .{ .begin = .{
        .expected_version_id = 9,
        .length = 4,
        .digest = digest("text"),
    } } });
    const parsed = try decode(encoded);
    try std.testing.expectEqual(@as(u64, 9), parsed.body.begin.expected_version_id);
    for (0..encoded.len) |length| try std.testing.expectError(error.MalformedFrame, decode(encoded[0..length]));
    bytes[6] = 1;
    try std.testing.expectError(error.MalformedFrame, decode(encoded));
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .request_id = 7, .body = .{ .receipt = .{ .status = .saved } } }));
    try std.testing.expectError(error.MalformedFrame, encode(&bytes, .{ .request_id = 7, .body = .{ .receipt = .{ .status = .permission_denied, .version_id = 5 } } }));
}

test "document protocol mutation decoding roundtrips only canonical frames" {
    const seeds = [_]Frame{
        .{ .request_id = 1, .body = .{ .begin = .{ .expected_version_id = 5, .length = 4, .digest = digest("text") } } },
        .{ .request_id = 1, .body = .{ .chunk = .{ .offset = 0, .bytes = "text" } } },
        .{ .request_id = 1, .body = .{ .commit = {} } },
        .{ .request_id = 1, .body = .{ .receipt = .{ .status = .saved, .object_id = 4, .previous_version_id = 5, .version_id = 6, .checkpoint_generation = 3 } } },
        .{ .request_id = 1, .body = .{ .receipt = .{ .status = .permission_denied } } },
    };
    for (seeds) |seed| {
        var original: [MAX_FRAME_BYTES]u8 = undefined;
        const length = (try encode(&original, seed)).len;
        for (0..length) |prefix| try std.testing.expectError(error.MalformedFrame, decode(original[0..prefix]));
        for (0..length) |offset| {
            for ([_]u8{ 1, 0x80, 0xff }) |mask| {
                var mutated = original;
                mutated[offset] ^= mask;
                const parsed = decode(mutated[0..length]) catch continue;
                var canonical: [MAX_FRAME_BYTES]u8 = undefined;
                try std.testing.expectEqualSlices(u8, mutated[0..length], try encode(&canonical, parsed));
            }
        }
    }
}
