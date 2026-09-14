const std = @import("std");

pub const DATA_PLANE_USES_SEALED_RINGS = true;
pub const MAGIC: u32 = 0x5247_4950;
pub const HEADER_BYTES: usize = @sizeOf(Header);

pub const Header = extern struct {
    magic: u32 = MAGIC,
    capacity: u32,
    head: u32 = 0,
    tail: u32 = 0,
};

pub const Error = error{
    RingTooSmall,
    RingCorrupt,
    RingFull,
    RingEmpty,
    PayloadTooLarge,
};

pub fn minimumBytes(capacity: u32) usize {
    return HEADER_BYTES + @as(usize, capacity);
}

pub fn init(buffer: []u8, capacity: u32) Error!*Header {
    if (buffer.len < minimumBytes(capacity) or capacity == 0) return error.RingTooSmall;
    const header: *Header = @ptrCast(@alignCast(buffer.ptr));
    header.* = .{
        .magic = MAGIC,
        .capacity = capacity,
        .head = 0,
        .tail = 0,
    };
    @memset(payload(buffer, header), 0);
    return header;
}

pub fn push(buffer: []u8, bytes: []const u8) Error!void {
    const header = headerOf(buffer) orelse return error.RingCorrupt;
    if (bytes.len > header.capacity) return error.PayloadTooLarge;
    const used = usedBytes(header);
    const record_bytes = recordSize(bytes.len);
    if (used + record_bytes > header.capacity) return error.RingFull;
    writeRecord(payload(buffer, header), header.capacity, header.head, bytes);
    header.head = wrap(header.head + record_bytes, header.capacity);
}

pub fn pop(buffer: []u8, out: []u8) Error!usize {
    const header = headerOf(buffer) orelse return error.RingCorrupt;
    if (header.head == header.tail) return error.RingEmpty;
    const ring = payload(buffer, header);
    const len = readLength(ring, header.capacity, header.tail);
    if (len > out.len) return error.PayloadTooLarge;
    copyFromRing(ring, header.capacity, wrap(header.tail + 2, header.capacity), out[0..len]);
    header.tail = wrap(header.tail + recordSize(len), header.capacity);
    return len;
}

fn headerOf(buffer: []u8) ?*Header {
    if (buffer.len < HEADER_BYTES) return null;
    const header: *Header = @ptrCast(@alignCast(buffer.ptr));
    if (header.magic != MAGIC or header.capacity == 0) return null;
    if (buffer.len < minimumBytes(header.capacity)) return null;
    return header;
}

fn payload(buffer: []u8, header: *const Header) []u8 {
    return buffer[HEADER_BYTES .. HEADER_BYTES + header.capacity];
}

fn usedBytes(header: *const Header) u32 {
    if (header.head >= header.tail) return header.head - header.tail;
    return header.capacity - (header.tail - header.head);
}

fn recordSize(payload_len: usize) u32 {
    return @intCast(2 + payload_len);
}

fn wrap(index: u32, capacity: u32) u32 {
    return if (index >= capacity) index - capacity else index;
}

fn writeRecord(ring: []u8, capacity: u32, start: u32, bytes: []const u8) void {
    const len: u16 = @intCast(bytes.len);
    ring[start] = @truncate(len);
    ring[wrap(start + 1, capacity)] = @truncate(len >> 8);
    copyToRing(ring, capacity, wrap(start + 2, capacity), bytes);
}

fn readLength(ring: []const u8, capacity: u32, start: u32) u16 {
    const lo: u16 = ring[start];
    const hi: u16 = ring[wrap(start + 1, capacity)];
    return lo | (hi << 8);
}

fn copyToRing(ring: []u8, capacity: u32, start: u32, bytes: []const u8) void {
    if (bytes.len == 0) return;
    const cap: usize = capacity;
    const offset: usize = start;
    const first = @min(bytes.len, cap - offset);
    @memcpy(ring[offset..][0..first], bytes[0..first]);
    if (first < bytes.len) {
        @memcpy(ring[0 .. bytes.len - first], bytes[first..]);
    }
}

fn copyFromRing(ring: []const u8, capacity: u32, start: u32, out: []u8) void {
    if (out.len == 0) return;
    const cap: usize = capacity;
    const offset: usize = start;
    const first = @min(out.len, cap - offset);
    @memcpy(out[0..first], ring[offset..][0..first]);
    if (first < out.len) {
        @memcpy(out[first..], ring[0 .. out.len - first]);
    }
}

test "ipc ring moves payloads without a kernel endpoint queue" {
    var storage: [HEADER_BYTES + 64]u8 = undefined;
    _ = try init(&storage, 64);
    try push(&storage, "notes");
    try push(&storage, "docs");
    var first: [8]u8 = undefined;
    var second: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try pop(&storage, &first));
    try std.testing.expectEqualStrings("notes", first[0..5]);
    try std.testing.expectEqual(@as(usize, 4), try pop(&storage, &second));
    try std.testing.expectEqualStrings("docs", second[0..4]);
    try std.testing.expectError(error.RingEmpty, pop(&storage, &first));
}
