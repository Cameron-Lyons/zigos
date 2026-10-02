const std = @import("std");

pub const DATA_PLANE_USES_SEALED_RINGS = true;
pub const MAGIC: u32 = 0x5247_4950;
pub const SLOT_BYTES: usize = 128;
pub const PAYLOAD_BYTES: usize = 88;
pub const HEADER_BYTES: usize = 192;
pub const HEAD_OFFSET: usize = 64;
pub const TAIL_OFFSET: usize = 128;
pub const STORAGE_ALIGNMENT: usize = 64;

pub const Record = extern struct {
    sender_endpoint_id: u64 = 0,
    sender_task_id: u64 = 0,
    correlation_id: u64 = 0,
    attached_capability_id: u64 = 0,
    flags: u16 = 0,
    payload_len: u16 = 0,
    move_attached: u8 = 0,
    _pad: [3]u8 = .{ 0, 0, 0 },
    bytes: [PAYLOAD_BYTES]u8 = [_]u8{0} ** PAYLOAD_BYTES,
};

pub const Error = error{
    RingTooSmall,
    RingCorrupt,
    RingFull,
    RingEmpty,
    PayloadTooLarge,
};

const Preface = extern struct {
    magic: u32 = MAGIC,
    slot_count: u32,
    slot_bytes: u32 = SLOT_BYTES,
    _reserved: u32 = 0,
};

comptime {
    if (@sizeOf(Record) != SLOT_BYTES) @compileError("ipc ring slots must occupy one fixed record");
    if (HEAD_OFFSET + 64 != TAIL_OFFSET) @compileError("ipc ring indexes must sit on separate cache lines");
    if (HEADER_BYTES != TAIL_OFFSET + 64) @compileError("ipc ring slots must start on their own cache line");
}

pub fn minimumBytes(slot_count: u32) usize {
    return HEADER_BYTES + @as(usize, slot_count) * SLOT_BYTES;
}

pub fn init(buffer: []u8, capacity: u32) Error!*Preface {
    if (capacity < SLOT_BYTES or buffer.len < HEADER_BYTES) return error.RingTooSmall;
    // The wrapping sequence counters must map to the same slots on either
    // side of u32 rollover. Only power-of-two slot counts have that property.
    if (capacity % SLOT_BYTES != 0 or !std.math.isPowerOfTwo(capacity / SLOT_BYTES) or
        !aligned(buffer)) return error.RingCorrupt;
    const slot_count: u32 = @intCast(capacity / SLOT_BYTES);
    if (buffer.len < minimumBytes(slot_count)) return error.RingTooSmall;
    // Initialization requires exclusive ownership, including the header's
    // cache-line padding. Never expose bytes from an earlier allocation.
    @memset(buffer[0..minimumBytes(slot_count)], 0);
    const preface: *Preface = @ptrCast(@alignCast(buffer.ptr));
    preface.* = .{
        .magic = MAGIC,
        .slot_count = slot_count,
    };
    @atomicStore(u32, indexPtr(buffer, HEAD_OFFSET), 0, .release);
    @atomicStore(u32, indexPtr(buffer, TAIL_OFFSET), 0, .release);
    return preface;
}

// One producer and one consumer, or externally serialized endpoint operations.
// Header geometry stays immutable while the ring is live. An independent
// observer must synchronize with one side before calling queued().
pub fn queued(buffer: []u8) Error!u32 {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .acquire);
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .acquire);
    return occupancy(head, tail, preface.slot_count);
}

pub fn pushRecord(buffer: []u8, record: Record) Error!void {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    if (record.payload_len > PAYLOAD_BYTES) return error.PayloadTooLarge;
    if (!validRecord(record)) return error.RingCorrupt;
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .acquire);
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .monotonic);
    if (try occupancy(head, tail, preface.slot_count) == preface.slot_count) return error.RingFull;
    slotPtr(buffer, head & (preface.slot_count - 1)).* = record;
    @atomicStore(u32, indexPtr(buffer, HEAD_OFFSET), head +% 1, .release);
}

pub fn peekRecord(buffer: []u8) Error!Record {
    return (try readPending(buffer)).record;
}

pub fn popRecord(buffer: []u8) Error!Record {
    const pending = try readPending(buffer);
    @atomicStore(u32, indexPtr(buffer, TAIL_OFFSET), pending.tail +% 1, .release);
    return pending.record;
}

// Validate and snapshot once, and release the slot only after checking the
// destination. A short receive must preserve the message and its capability.
pub fn receive(buffer: []u8, out: []u8) Error!Record {
    const pending = try readPending(buffer);
    const record = pending.record;
    if (record.payload_len > out.len) return error.PayloadTooLarge;
    @memcpy(out[0..record.payload_len], record.bytes[0..record.payload_len]);
    @atomicStore(u32, indexPtr(buffer, TAIL_OFFSET), pending.tail +% 1, .release);
    return record;
}

const Pending = struct { tail: u32, record: Record };

inline fn readPending(buffer: []u8) Error!Pending {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .acquire);
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .monotonic);
    if (try occupancy(head, tail, preface.slot_count) == 0) return error.RingEmpty;
    const record = slotPtr(buffer, tail & (preface.slot_count - 1)).*;
    if (!validRecord(record)) return error.RingCorrupt;
    return .{ .tail = tail, .record = record };
}

pub fn push(buffer: []u8, bytes: []const u8) Error!void {
    if (bytes.len > PAYLOAD_BYTES) return error.PayloadTooLarge;
    var record = Record{ .payload_len = @intCast(bytes.len) };
    if (bytes.len != 0) @memcpy(record.bytes[0..bytes.len], bytes);
    return pushRecord(buffer, record);
}

pub fn pop(buffer: []u8, out: []u8) Error!usize {
    return (try receive(buffer, out)).payload_len;
}

fn prefaceOf(buffer: []u8) ?Preface {
    if (buffer.len < HEADER_BYTES or !aligned(buffer)) return null;
    const pointer: *const Preface = @ptrCast(@alignCast(buffer.ptr));
    const preface = pointer.*;
    if (preface.magic != MAGIC or !std.math.isPowerOfTwo(preface.slot_count) or
        preface.slot_bytes != SLOT_BYTES or preface._reserved != 0) return null;
    if (buffer.len < minimumBytes(preface.slot_count)) return null;
    return preface;
}

fn aligned(buffer: []u8) bool {
    return @intFromPtr(buffer.ptr) % STORAGE_ALIGNMENT == 0;
}

fn occupancy(head: u32, tail: u32, slot_count: u32) Error!u32 {
    const count = head -% tail;
    if (count > slot_count) return error.RingCorrupt;
    return count;
}

fn validRecord(record: Record) bool {
    return record.payload_len <= PAYLOAD_BYTES and record.move_attached <= 1 and
        std.mem.eql(u8, &record._pad, &.{ 0, 0, 0 });
}

fn indexPtr(buffer: []u8, offset: usize) *u32 {
    return @ptrCast(@alignCast(buffer.ptr + offset));
}

fn slotPtr(buffer: []u8, index: u32) *Record {
    const offset = HEADER_BYTES + @as(usize, index) * SLOT_BYTES;
    return @ptrCast(@alignCast(buffer.ptr + offset));
}

test "ipc ring moves fixed slots without a kernel endpoint queue" {
    var storage: [HEADER_BYTES + SLOT_BYTES * 2]u8 align(64) = undefined;
    _ = try init(&storage, SLOT_BYTES * 2);
    try push(&storage, "notes");
    try push(&storage, "docs");
    try std.testing.expectError(error.RingFull, push(&storage, "more"));
    var first: [8]u8 = undefined;
    var second: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try pop(&storage, &first));
    try std.testing.expectEqualStrings("notes", first[0..5]);
    try std.testing.expectEqual(@as(usize, 4), try pop(&storage, &second));
    try std.testing.expectEqualStrings("docs", second[0..4]);
    try std.testing.expectError(error.RingEmpty, pop(&storage, &first));
}

test "ipc ring rejects invalid geometry and alignment without modifying storage" {
    var storage: [minimumBytes(8) + STORAGE_ALIGNMENT]u8 align(STORAGE_ALIGNMENT) = @splat(0xa5);
    const before = storage;
    for ([_]u32{ SLOT_BYTES + 1, SLOT_BYTES * 3, SLOT_BYTES * 5 }) |capacity| {
        try std.testing.expectError(error.RingCorrupt, init(&storage, capacity));
    }
    try std.testing.expectError(error.RingTooSmall, init(&storage, SLOT_BYTES * 16));
    try std.testing.expectError(error.RingCorrupt, init(storage[1..], SLOT_BYTES));
    try std.testing.expectError(error.RingCorrupt, queued(storage[1..]));
    try std.testing.expectError(error.RingCorrupt, popRecord(storage[1..]));
    try std.testing.expectEqualSlices(u8, &before, &storage);

    _ = try init(&storage, SLOT_BYTES * 8);
    try std.testing.expectEqualSlices(u8, &(@as([HEADER_BYTES - @sizeOf(Preface)]u8, @splat(0))), storage[@sizeOf(Preface)..HEADER_BYTES]);
    try std.testing.expectEqual(@as(u8, 0xa5), storage[minimumBytes(8)]);
}

test "ipc ring retains FIFO order and full detection across sequence rollover" {
    inline for (.{ 1, 2, 4, 8, 32 }) |capacity| {
        var storage: [minimumBytes(capacity)]u8 align(STORAGE_ALIGNMENT) = undefined;
        _ = try init(&storage, capacity * SLOT_BYTES);
        const start = std.math.maxInt(u32) - 1;
        @atomicStore(u32, indexPtr(&storage, HEAD_OFFSET), start, .release);
        @atomicStore(u32, indexPtr(&storage, TAIL_OFFSET), start, .release);
        for (0..4) |round| {
            for (0..capacity) |sequence| {
                try pushRecord(&storage, .{ .correlation_id = round * capacity + sequence });
            }
            try std.testing.expectEqual(@as(u32, capacity), try queued(&storage));
            const full = storage;
            try std.testing.expectError(error.RingFull, push(&storage, "overflow"));
            try std.testing.expectEqualSlices(u8, &full, &storage);
            for (0..capacity) |sequence| {
                const expected = round * capacity + sequence;
                try std.testing.expectEqual(@as(u64, expected), (try peekRecord(&storage)).correlation_id);
                try std.testing.expectEqual(@as(u64, expected), (try popRecord(&storage)).correlation_id);
            }
            try std.testing.expectEqual(@as(u32, 0), try queued(&storage));
            try std.testing.expectError(error.RingEmpty, popRecord(&storage));
        }
    }
}

test "ipc ring rejects impossible occupancy before reading or overwriting a slot" {
    var storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    for ([_][2]u32{ .{ 3, 0 }, .{ 0, 1 }, .{ 0, std.math.maxInt(u32) - 2 } }) |counters| {
        _ = try init(&storage, SLOT_BYTES * 2);
        @atomicStore(u32, indexPtr(&storage, HEAD_OFFSET), counters[0], .release);
        @atomicStore(u32, indexPtr(&storage, TAIL_OFFSET), counters[1], .release);
        const before = storage;
        var out: [PAYLOAD_BYTES]u8 = @splat(0xa5);
        try std.testing.expectError(error.RingCorrupt, queued(&storage));
        try std.testing.expectError(error.RingCorrupt, push(&storage, "overwrite"));
        try std.testing.expectError(error.RingCorrupt, peekRecord(&storage));
        try std.testing.expectError(error.RingCorrupt, popRecord(&storage));
        try std.testing.expectError(error.RingCorrupt, receive(&storage, &out));
        try std.testing.expectEqualSlices(u8, &before, &storage);
        try std.testing.expectEqualSlices(u8, &(@as([PAYLOAD_BYTES]u8, @splat(0xa5))), &out);
    }
}

test "ipc ring rejects malformed records without consuming or exposing payload" {
    var storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    for ([_]Record{
        .{ .payload_len = PAYLOAD_BYTES + 1 },
        .{ .payload_len = std.math.maxInt(u16) },
        .{ .move_attached = 2 },
        .{ ._pad = .{ 0, 1, 0 } },
    }) |malformed| {
        _ = try init(&storage, SLOT_BYTES * 2);
        try push(&storage, "valid");
        slotPtr(&storage, 0).* = malformed;
        const before = storage;
        var out: [PAYLOAD_BYTES + 1]u8 = @splat(0xa5);
        try std.testing.expectError(error.RingCorrupt, peekRecord(&storage));
        try std.testing.expectError(error.RingCorrupt, popRecord(&storage));
        try std.testing.expectError(error.RingCorrupt, receive(&storage, &out));
        try std.testing.expectEqualSlices(u8, &before, &storage);
        for (out) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    }
}

test "ipc ring short receives preserve message capability and output" {
    var storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    _ = try init(&storage, SLOT_BYTES * 2);
    var record = Record{ .payload_len = 5, .attached_capability_id = 42, .move_attached = 1 };
    @memcpy(record.bytes[0..5], "notes");
    try pushRecord(&storage, record);
    const before = storage;
    var short: [4]u8 = @splat(0xa5);
    try std.testing.expectError(error.PayloadTooLarge, pop(&storage, &short));
    try std.testing.expectEqualSlices(u8, &before, &storage);
    for (short) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    var out: [5]u8 = undefined;
    const received = try receive(&storage, &out);
    try std.testing.expectEqualStrings("notes", &out);
    try std.testing.expectEqual(@as(u64, 42), received.attached_capability_id);
    try std.testing.expectEqual(@as(u8, 1), received.move_attached);
    try std.testing.expectEqual(@as(u32, 0), try queued(&storage));
}
