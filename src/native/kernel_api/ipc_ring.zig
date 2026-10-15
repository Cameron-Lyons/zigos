const std = @import("std");

pub const DATA_PLANE_USES_SEALED_RINGS = true;
pub const MAGIC: u32 = 0x5247_4950;
pub const SLOT_BYTES: usize = 128;
pub const PAYLOAD_BYTES: usize = 88;
pub const HEADER_BYTES: usize = 192;
pub const HEAD_OFFSET: usize = 64;
pub const TAIL_OFFSET: usize = 128;
pub const STORAGE_ALIGNMENT: usize = 64;

pub const RecordHeader = extern struct {
    sender_endpoint_id: u64 = 0,
    sender_task_id: u64 = 0,
    correlation_id: u64 = 0,
    attached_capability_id: u64 = 0,
    flags: u16 = 0,
    payload_len: u16 = 0,
    move_attached: u8 = 0,
    _pad: [3]u8 = .{ 0, 0, 0 },
};

pub const Record = extern struct {
    sender_endpoint_id: u64 = 0,
    sender_task_id: u64 = 0,
    correlation_id: u64 = 0,
    attached_capability_id: u64 = 0,
    flags: u16 = 0,
    payload_len: u16 = 0,
    move_attached: u8 = 0,
    _pad: [3]u8 = .{ 0, 0, 0 },
    bytes: [PAYLOAD_BYTES]u8 = @as([PAYLOAD_BYTES]u8, @splat(0)),
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
    if (@sizeOf(RecordHeader) != @offsetOf(Record, "bytes")) @compileError("ipc ring header must occupy the record prefix");
    for (@typeInfo(RecordHeader).@"struct".field_names) |field_name| {
        if (@FieldType(RecordHeader, field_name) != @FieldType(Record, field_name) or @offsetOf(RecordHeader, field_name) != @offsetOf(Record, field_name))
            @compileError("ipc ring header fields must match the full record");
    }
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

// Build the sealed slot from small metadata and an already-owned payload.
// Consume aliased source bytes before scrubbing the tail or writing metadata,
// and publish only after validation and the complete record write.
pub fn pushPayload(buffer: []u8, header: RecordHeader, payload: []const u8) Error!void {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    if (payload.len > PAYLOAD_BYTES or header.payload_len > PAYLOAD_BYTES) return error.PayloadTooLarge;
    if (header.payload_len != payload.len or !validRecord(header)) return error.RingCorrupt;
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .acquire);
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .monotonic);
    if (try occupancy(head, tail, preface.slot_count) == preface.slot_count) return error.RingFull;

    const slot = slotPtr(buffer, head & (preface.slot_count - 1));
    if (payload.len == PAYLOAD_BYTES) {
        @memmove(&slot.bytes, payload[0..PAYLOAD_BYTES]);
    } else if (payload.len == 0) {
        @memset(&slot.bytes, 0);
    } else {
        const destination = @intFromPtr(&slot.bytes);
        const source = @intFromPtr(payload.ptr);
        const overlaps = if (source >= destination)
            source - destination < PAYLOAD_BYTES
        else
            destination - source < payload.len;
        if (overlaps) {
            @memmove(slot.bytes[0..payload.len], payload);
            @memset(slot.bytes[payload.len..], 0);
        } else {
            @memset(&slot.bytes, 0);
            @memcpy(slot.bytes[0..payload.len], payload);
        }
    }
    const slot_header: *RecordHeader = @ptrCast(slot);
    slot_header.* = header;
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

// Snapshot metadata before copying from the still-owned slot. Overlapping
// output is consumed before release; a short receive changes no bytes.
pub fn receive(buffer: []u8, out: []u8) Error!RecordHeader {
    const pending = try readPendingSlot(buffer);
    const header = pending.header;
    if (header.payload_len > out.len) return error.PayloadTooLarge;
    @memmove(out[0..header.payload_len], pending.slot.bytes[0..header.payload_len]);
    @atomicStore(u32, indexPtr(buffer, TAIL_OFFSET), pending.tail +% 1, .release);
    return header;
}

const Pending = struct { tail: u32, record: Record };
const PendingSlot = struct { tail: u32, slot: *const Record, header: RecordHeader };

inline fn readPending(buffer: []u8) Error!Pending {
    const pending = try readPendingSlot(buffer);
    return .{ .tail = pending.tail, .record = pending.slot.* };
}

inline fn readPendingSlot(buffer: []u8) Error!PendingSlot {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .acquire);
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .monotonic);
    if (try occupancy(head, tail, preface.slot_count) == 0) return error.RingEmpty;
    const slot = slotPtr(buffer, tail & (preface.slot_count - 1));
    const header: *const RecordHeader = @ptrCast(slot);
    const snapshot = header.*;
    if (!validRecord(snapshot)) return error.RingCorrupt;
    return .{ .tail = tail, .slot = slot, .header = snapshot };
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

fn validRecord(record: anytype) bool {
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
        try std.testing.expectError(error.RingCorrupt, pushPayload(&storage, .{}, ""));
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

test "ipc ring receives overlapping payloads with original metadata before release" {
    var storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    for ([_]usize{ 0, 1, 17, PAYLOAD_BYTES }) |length| {
        for ([_]usize{ @sizeOf(RecordHeader) - 1, @sizeOf(RecordHeader) + 1, 0 }) |offset| {
            _ = try init(&storage, SLOT_BYTES * 2);
            var record = Record{
                .sender_endpoint_id = 11,
                .sender_task_id = 22,
                .correlation_id = 33,
                .attached_capability_id = 44,
                .flags = 5,
                .payload_len = @intCast(length),
                .move_attached = 1,
            };
            for (&record.bytes, 0..) |*byte, index| byte.* = @truncate(index * 19 + 1);
            try pushRecord(&storage, record);
            const before = storage;
            const destination = storage[HEADER_BYTES + offset ..][0..length];
            const received = try receive(&storage, destination);
            inline for (@typeInfo(RecordHeader).@"struct".field_names) |field_name| {
                try std.testing.expectEqualDeep(@field(record, field_name), @field(received, field_name));
            }
            try std.testing.expectEqualSlices(u8, record.bytes[0..length], destination);
            for (storage, 0..) |byte, index| {
                if (index == TAIL_OFFSET or
                    (index >= HEADER_BYTES + offset and index < HEADER_BYTES + offset + length)) continue;
                try std.testing.expectEqual(before[index], byte);
            }
            try std.testing.expectEqual(@as(u32, 0), try queued(&storage));
        }
    }
}

test "ipc payload enqueue matches full record writes across lengths and rollover" {
    var expected_storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    var actual_storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    _ = try init(&expected_storage, SLOT_BYTES * 2);
    _ = try init(&actual_storage, SLOT_BYTES * 2);
    const start = std.math.maxInt(u32) - 1;
    inline for (.{ HEAD_OFFSET, TAIL_OFFSET }) |offset| {
        @atomicStore(u32, indexPtr(&expected_storage, offset), start, .release);
        @atomicStore(u32, indexPtr(&actual_storage, offset), start, .release);
    }
    var payload: [PAYLOAD_BYTES]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index * 19 + 1);
    for ([_]usize{ 0, 1, 17, PAYLOAD_BYTES }) |length| {
        const header = RecordHeader{
            .sender_endpoint_id = 11,
            .sender_task_id = 22,
            .correlation_id = 33,
            .attached_capability_id = 44,
            .flags = 5,
            .payload_len = @intCast(length),
            .move_attached = 1,
        };
        var record = Record{};
        inline for (@typeInfo(RecordHeader).@"struct".field_names) |field_name| {
            @field(record, field_name) = @field(header, field_name);
        }
        @memcpy(record.bytes[0..length], payload[0..length]);
        try pushRecord(&expected_storage, record);
        try pushPayload(&actual_storage, header, payload[0..length]);
        try std.testing.expectEqualSlices(u8, &expected_storage, &actual_storage);
        try std.testing.expectEqualDeep(try popRecord(&expected_storage), try popRecord(&actual_storage));
    }
}

test "ipc payload enqueue validates metadata capacity and geometry before mutation" {
    var storage: [minimumBytes(1)]u8 align(STORAGE_ALIGNMENT) = undefined;
    _ = try init(&storage, SLOT_BYTES);
    for ([_]RecordHeader{
        .{ .payload_len = 2 },
        .{ .payload_len = 1, .move_attached = 2 },
        .{ .payload_len = 1, ._pad = .{ 0, 1, 0 } },
    }) |header| {
        const before = storage;
        try std.testing.expectError(error.RingCorrupt, pushPayload(&storage, header, "x"));
        try std.testing.expectEqualSlices(u8, &before, &storage);
    }
    const before = storage;
    try std.testing.expectError(error.PayloadTooLarge, pushPayload(&storage, .{ .payload_len = PAYLOAD_BYTES + 1 }, ""));
    const oversized: [PAYLOAD_BYTES + 1]u8 = @splat('x');
    try std.testing.expectError(error.PayloadTooLarge, pushPayload(&storage, .{}, &oversized));
    try std.testing.expectEqualSlices(u8, &before, &storage);

    try pushPayload(&storage, .{ .payload_len = 1 }, "x");
    const full = storage;
    try std.testing.expectError(error.RingFull, pushPayload(&storage, .{ .payload_len = 1 }, "y"));
    try std.testing.expectEqualSlices(u8, &full, &storage);
    storage[0] ^= 0xff;
    const corrupt = storage;
    try std.testing.expectError(error.RingCorrupt, pushPayload(&storage, .{ .payload_len = 1 }, "y"));
    try std.testing.expectEqualSlices(u8, &corrupt, &storage);
    try std.testing.expectError(error.RingCorrupt, pushPayload(storage[1..], .{}, ""));
    try std.testing.expectEqualSlices(u8, &corrupt, &storage);
}

test "ipc payload enqueue consumes overlapping sources before replacing and scrubbing a slot" {
    var storage: [minimumBytes(1)]u8 align(STORAGE_ALIGNMENT) = undefined;
    for ([_]usize{ 0, 1, 40, 41, 70, 88, 100, 120 }) |source_offset| {
        _ = try init(&storage, SLOT_BYTES);
        const slot_bytes = storage[HEADER_BYTES..];
        for (slot_bytes, 0..) |*byte, index| byte.* = @truncate(index * 13 + 1);
        const length = @min(PAYLOAD_BYTES, slot_bytes.len - source_offset);
        var expected: [PAYLOAD_BYTES]u8 = undefined;
        @memcpy(expected[0..length], slot_bytes[source_offset..][0..length]);
        try pushPayload(&storage, .{
            .sender_endpoint_id = 11,
            .attached_capability_id = 44,
            .payload_len = @intCast(length),
            .move_attached = 1,
        }, slot_bytes[source_offset..][0..length]);
        const record = try popRecord(&storage);
        try std.testing.expectEqual(@as(u64, 11), record.sender_endpoint_id);
        try std.testing.expectEqual(@as(u64, 44), record.attached_capability_id);
        try std.testing.expectEqual(@as(u8, 1), record.move_attached);
        try std.testing.expectEqualSlices(u8, expected[0..length], record.bytes[0..length]);
        for (record.bytes[length..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "ipc payload producer and consumer preserve records through concurrent slot and sequence reuse" {
    const transfers = 10_000;
    const Context = struct {
        buffer: []u8,
        started: std.Io.Timestamp,
        failed: std.atomic.Value(bool) = .init(false),

        fn retry(self: *@This(), spins: *u32) bool {
            if (self.failed.load(.acquire)) return false;
            spins.* +%= 1;
            // A lost publication must fail the test instead of hanging the
            // producer, consumer, or join indefinitely. Leave scheduling room
            // for hosted x86 tests running under translation.
            if (spins.* % 1024 == 0 and
                self.started.durationTo(std.Io.Clock.awake.now(std.testing.io)).toNanoseconds() > 10_000_000_000)
            {
                self.failed.store(true, .release);
                return false;
            }
            std.atomic.spinLoopHint();
            return true;
        }

        fn consume(self: *@This()) void {
            for (0..transfers) |sequence| {
                var out: [PAYLOAD_BYTES]u8 = undefined;
                var spins: u32 = 0;
                const header = while (true) {
                    if (self.failed.load(.acquire)) return;
                    const received = receive(self.buffer, &out) catch |err| {
                        if (err == error.RingEmpty and self.retry(&spins)) continue;
                        self.failed.store(true, .release);
                        return;
                    };
                    break received;
                };
                const length = sequence % (PAYLOAD_BYTES + 1);
                if (header.sender_endpoint_id != 11 or header.sender_task_id != 22 or
                    header.correlation_id != sequence or header.attached_capability_id != sequence + 1 or
                    header.flags != 5 or header.payload_len != length or header.move_attached != 1 or
                    !std.mem.eql(u8, &header._pad, &.{ 0, 0, 0 }))
                {
                    self.failed.store(true, .release);
                    return;
                }
                for (out[0..length], 0..) |byte, index| {
                    if (byte != @as(u8, @truncate(sequence + index * 19))) {
                        self.failed.store(true, .release);
                        return;
                    }
                }
            }
        }
    };
    var storage: [minimumBytes(2)]u8 align(STORAGE_ALIGNMENT) = undefined;
    _ = try init(&storage, SLOT_BYTES * 2);
    const start = std.math.maxInt(u32) - 7;
    @atomicStore(u32, indexPtr(&storage, HEAD_OFFSET), start, .release);
    @atomicStore(u32, indexPtr(&storage, TAIL_OFFSET), start, .release);
    var context = Context{ .buffer = &storage, .started = std.Io.Clock.awake.now(std.testing.io) };
    const consumer = try std.Thread.spawn(.{}, Context.consume, .{&context});
    for (0..transfers) |sequence| {
        var bytes: [PAYLOAD_BYTES]u8 = undefined;
        for (&bytes, 0..) |*byte, index| byte.* = @truncate(sequence + index * 19);
        const length = sequence % (PAYLOAD_BYTES + 1);
        var spins: u32 = 0;
        while (!context.failed.load(.acquire)) {
            pushPayload(&storage, .{
                .sender_endpoint_id = 11,
                .sender_task_id = 22,
                .correlation_id = sequence,
                .attached_capability_id = sequence + 1,
                .flags = 5,
                .payload_len = @intCast(length),
                .move_attached = 1,
            }, bytes[0..length]) catch |err| {
                if (err == error.RingFull and context.retry(&spins)) continue;
                context.failed.store(true, .release);
                break;
            };
            break;
        }
        if (context.failed.load(.acquire)) break;
    }
    consumer.join();
    try std.testing.expect(!context.failed.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), try queued(&storage));
}
