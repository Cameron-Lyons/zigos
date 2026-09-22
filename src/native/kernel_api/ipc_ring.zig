const std = @import("std");

pub const DATA_PLANE_USES_SEALED_RINGS = true;
pub const MAGIC: u32 = 0x5247_4950;
pub const SLOT_BYTES: usize = 128;
pub const PAYLOAD_BYTES: usize = 96;
pub const HEADER_BYTES: usize = 192;
pub const HEAD_OFFSET: usize = 64;
pub const TAIL_OFFSET: usize = 128;

pub const Record = extern struct {
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
    const slot_count: u32 = @intCast(capacity / SLOT_BYTES);
    if (slot_count == 0 or buffer.len < minimumBytes(slot_count)) return error.RingTooSmall;
    const preface: *Preface = @ptrCast(@alignCast(buffer.ptr));
    preface.* = .{
        .magic = MAGIC,
        .slot_count = slot_count,
    };
    @atomicStore(u32, indexPtr(buffer, HEAD_OFFSET), 0, .release);
    @atomicStore(u32, indexPtr(buffer, TAIL_OFFSET), 0, .release);
    @memset(buffer[HEADER_BYTES..minimumBytes(slot_count)], 0);
    return preface;
}

pub fn queued(buffer: []u8) Error!u32 {
    if (prefaceOf(buffer) == null) return error.RingCorrupt;
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .acquire);
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .acquire);
    return head -% tail;
}

pub fn pushRecord(buffer: []u8, record: Record) Error!void {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    if (record.payload_len > PAYLOAD_BYTES) return error.PayloadTooLarge;
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .acquire);
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .monotonic);
    if (head -% tail == preface.slot_count) return error.RingFull;
    slotPtr(buffer, head % preface.slot_count).* = record;
    @atomicStore(u32, indexPtr(buffer, HEAD_OFFSET), head +% 1, .release);
}

pub fn peekRecord(buffer: []u8) Error!Record {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .acquire);
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .monotonic);
    if (head == tail) return error.RingEmpty;
    return slotPtr(buffer, tail % preface.slot_count).*;
}

pub fn popRecord(buffer: []u8) Error!Record {
    const preface = prefaceOf(buffer) orelse return error.RingCorrupt;
    const head = @atomicLoad(u32, indexPtr(buffer, HEAD_OFFSET), .acquire);
    const tail = @atomicLoad(u32, indexPtr(buffer, TAIL_OFFSET), .monotonic);
    if (head == tail) return error.RingEmpty;
    const record = slotPtr(buffer, tail % preface.slot_count).*;
    @atomicStore(u32, indexPtr(buffer, TAIL_OFFSET), tail +% 1, .release);
    return record;
}

pub fn push(buffer: []u8, bytes: []const u8) Error!void {
    if (bytes.len > PAYLOAD_BYTES) return error.PayloadTooLarge;
    var record = Record{ .payload_len = @intCast(bytes.len) };
    if (bytes.len != 0) @memcpy(record.bytes[0..bytes.len], bytes);
    return pushRecord(buffer, record);
}

pub fn pop(buffer: []u8, out: []u8) Error!usize {
    const record = try popRecord(buffer);
    if (record.payload_len > out.len) return error.PayloadTooLarge;
    if (record.payload_len != 0) @memcpy(out[0..record.payload_len], record.bytes[0..record.payload_len]);
    return record.payload_len;
}

fn prefaceOf(buffer: []u8) ?*Preface {
    if (buffer.len < HEADER_BYTES) return null;
    const preface: *Preface = @ptrCast(@alignCast(buffer.ptr));
    if (preface.magic != MAGIC or preface.slot_count == 0 or preface.slot_bytes != SLOT_BYTES) return null;
    if (buffer.len < minimumBytes(preface.slot_count)) return null;
    return preface;
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
