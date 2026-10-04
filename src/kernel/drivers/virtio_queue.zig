//! Bounded split virtqueues on the modern VirtIO PCI transport. No legacy
//! transport, indirect descriptors, chains, event thresholds or offloads.
//! https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html (2.7, 5.1)
const std = @import("std");

pub const CAPACITY: u16 = 32;
pub const BUFFER_BYTES: u32 = 2048;
pub const HEADER_BYTES: usize = 12;
pub const WRITE: u16 = 2;
pub const Descriptor = extern struct { address: u64, length: u32, flags: u16, next: u16 };
pub const Available = extern struct { flags: u16, index: u16, entries: [CAPACITY]u16 };
pub const UsedElement = extern struct { id: u32, length: u32 };
pub const Used = extern struct { flags: u16, index: u16, entries: [CAPACITY]UsedElement };
pub const Ring = extern struct { descriptors: [CAPACITY]Descriptor, available: Available, used: Used };
pub const Completion = struct { id: u16, length: u32 };
pub const Error = error{ InvalidBuffer, QueueFull, InvalidCompletion };

pub const Queue = struct {
    occupied: u32 = 0,
    available_index: u16 = 0,
    used_index: u16 = 0,
    device_writable: bool,

    pub fn freeId(self: *const Queue) ?u16 {
        if (self.occupied == std.math.maxInt(u32)) return null;
        return @intCast(@ctz(~self.occupied));
    }

    pub fn submit(self: *Queue, ring: *volatile Ring, id: u16, address: u64, length: u32) Error!void {
        if (id >= CAPACITY or address == 0 or length == 0 or length > BUFFER_BYTES or
            (self.device_writable and length != BUFFER_BYTES)) return error.InvalidBuffer;
        if (self.freeId() == null) return error.QueueFull;
        const bit = @as(u32, 1) << @as(u5, @intCast(id));
        if (self.occupied & bit != 0) return error.InvalidBuffer;
        ring.descriptors[id] = .{ .address = address, .length = length, .flags = if (self.device_writable) WRITE else 0, .next = 0 };
        ring.available.entries[self.available_index % CAPACITY] = id;
        self.occupied |= bit;
        self.available_index +%= 1;
        publish();
        ring.available.index = self.available_index;
    }

    pub fn completionReady(self: *const Queue, ring: *volatile Ring) bool {
        return ring.used.index != self.used_index;
    }

    pub fn nextTransmitWake(self: *const Queue, submitted_ticks: *const [CAPACITY]u64, timeout_ticks: u64) ?u64 {
        if (timeout_ticks == 0) return null;
        var occupied = self.occupied;
        var wake: ?u64 = null;
        while (occupied != 0) {
            const index = @ctz(occupied);
            occupied &= occupied - 1;
            const deadline = submitted_ticks[index] +| timeout_ticks;
            wake = if (wake) |current| @min(current, deadline) else deadline;
        }
        return wake;
    }

    pub fn complete(self: *Queue, ring: *volatile Ring) Error!?Completion {
        const pending = ring.used.index -% self.used_index;
        if (pending == 0) return null;
        if (pending > @popCount(self.occupied)) return error.InvalidCompletion;
        consume();
        const element = ring.used.entries[self.used_index % CAPACITY];
        if (element.id >= CAPACITY) return error.InvalidCompletion;
        const bit = @as(u32, 1) << @as(u5, @intCast(element.id));
        if (self.occupied & bit == 0) return error.InvalidCompletion;
        // Each receive buffer is always posted at its full fixed capacity. TX
        // has no device-writable bytes, so its returned length is never used.
        const length = if (self.device_writable) element.length else 0;
        if (length > BUFFER_BYTES) return error.InvalidCompletion;
        self.occupied &= ~bit;
        self.used_index +%= 1;
        return .{ .id = @intCast(element.id), .length = length };
    }

    pub fn shouldNotify(ring: *volatile Ring) bool {
        publish();
        return ring.used.flags & 1 == 0;
    }
};

pub fn publish() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

pub fn consume() void {
    asm volatile ("lfence" ::: .{ .memory = true });
}

pub fn receivedFrame(buffer: []const u8) error{InvalidHeader}![]const u8 {
    if (buffer.len < HEADER_BYTES or buffer.len > BUFFER_BYTES) return error.InvalidHeader;
    if (buffer[0] != 0 or buffer[1] != 0) return error.InvalidHeader;
    // MRG_RXBUF is never negotiated. One completion owns one whole packet;
    // num_buffers cannot authorize additional descriptors or extend its length.
    return buffer[HEADER_BYTES..];
}

comptime {
    if (@sizeOf(Descriptor) != 16 or @sizeOf(UsedElement) != 8 or @sizeOf(Ring) > 1024 or
        @offsetOf(Ring, "available") % 2 != 0 or @offsetOf(Ring, "used") % 4 != 0 or
        @sizeOf(Queue) > 12) @compileError("VirtIO queue layout exceeded its budget");
}

test "virtio queues wrap 16-bit indices and accept out-of-order owned completions" {
    var ring = std.mem.zeroes(Ring);
    var queue = Queue{ .device_writable = true };
    for (0..4097) |_| {
        for (0..CAPACITY) |index| try queue.submit(&ring, queue.freeId().?, 0x1000 + index * BUFFER_BYTES, BUFFER_BYTES);
        try std.testing.expectEqual(@as(?u16, null), queue.freeId());
        try std.testing.expectError(error.QueueFull, queue.submit(&ring, 0, 0x1000, BUFFER_BYTES));
        try std.testing.expect(!queue.completionReady(&ring));
        for (0..CAPACITY) |index| {
            ring.used.entries[ring.used.index % CAPACITY] = .{ .id = @intCast(CAPACITY - 1 - index), .length = 100 };
            ring.used.index +%= 1;
        }
        for (0..CAPACITY) |index| {
            const completed = (try queue.complete(&ring)).?;
            try std.testing.expectEqual(CAPACITY - 1 - index, completed.id);
            try std.testing.expectEqual(@as(u32, 100), completed.length);
        }
        try std.testing.expectEqual(@as(u32, 0), queue.occupied);
        try std.testing.expectEqual(@as(?Completion, null), try queue.complete(&ring));
    }
}

test "virtio queues contain excessive progress invalid lengths and duplicate completions" {
    var ring = std.mem.zeroes(Ring);
    var queue = Queue{ .device_writable = true };
    try queue.submit(&ring, 0, 0x1000, BUFFER_BYTES);
    const before = queue;
    ring.used.index = 2;
    try std.testing.expectError(error.InvalidCompletion, queue.complete(&ring));
    ring.used.index = 1;
    ring.used.entries[0] = .{ .id = CAPACITY, .length = 100 };
    try std.testing.expectError(error.InvalidCompletion, queue.complete(&ring));
    ring.used.entries[0].id = 1;
    try std.testing.expectError(error.InvalidCompletion, queue.complete(&ring));
    ring.used.entries[0] = .{ .id = 0, .length = BUFFER_BYTES + 1 };
    try std.testing.expectError(error.InvalidCompletion, queue.complete(&ring));
    try std.testing.expectEqualDeep(before, queue);
    ring.used.entries[0].length = 100;
    _ = try queue.complete(&ring);
    try queue.submit(&ring, 1, 0x2000, BUFFER_BYTES);
    ring.used.entries[1] = .{ .id = 0, .length = 100 };
    ring.used.index = 2;
    try std.testing.expectError(error.InvalidCompletion, queue.complete(&ring));
    try std.testing.expectEqual(@as(u32, 2), queue.occupied);
}

test "virtio queues use submission ownership and ignore reserved TX completion length" {
    var ring = std.mem.zeroes(Ring);
    var queue = Queue{ .device_writable = false };
    try queue.submit(&ring, 0, 0x1000, 128);
    try std.testing.expectError(error.InvalidBuffer, queue.submit(&ring, 0, 0x2000, 128));
    // Hardware cannot change CPU ownership by rewriting its descriptor copy.
    ring.descriptors[0].address = std.math.maxInt(u64);
    ring.used.entries[0] = .{ .id = 0, .length = std.math.maxInt(u32) };
    ring.used.index = 1;
    try std.testing.expectEqual(@as(u32, 0), (try queue.complete(&ring)).?.length);
    try std.testing.expect(Queue.shouldNotify(&ring));
    ring.used.flags = 1;
    try std.testing.expect(!Queue.shouldNotify(&ring));
    ring.used.index = 2;
    try std.testing.expectError(error.InvalidCompletion, queue.complete(&ring));
}

test "virtio net bounds a single receive buffer and rejects unnegotiated offloads" {
    var buffer = @as([72]u8, @splat(0));
    buffer[10] = 1;
    try std.testing.expectEqual(@as(usize, 60), (try receivedFrame(&buffer)).len);
    for ([_]usize{ 0, 1 }) |index| {
        buffer[index] = 1;
        try std.testing.expectError(error.InvalidHeader, receivedFrame(&buffer));
        buffer[index] = 0;
    }
    buffer[10] = 2;
    buffer[11] = 0xFF;
    try std.testing.expectEqual(@as(usize, 60), (try receivedFrame(&buffer)).len);
    try std.testing.expectError(error.InvalidHeader, receivedFrame(buffer[0..11]));
}

test "virtio transmit wake tracks owned slots across out-of-order completion and reuse" {
    var ring = std.mem.zeroes(Ring);
    var queue = Queue{ .device_writable = false };
    var submitted_ticks = @as([CAPACITY]u64, @splat(0));
    try std.testing.expect(queue.nextTransmitWake(&submitted_ticks, 100) == null);
    try queue.submit(&ring, 31, 0x1000, 128);
    submitted_ticks[31] = 107;
    try queue.submit(&ring, 0, 0x2000, 128);
    submitted_ticks[0] = 108;
    try std.testing.expectEqual(@as(?u64, 207), queue.nextTransmitWake(&submitted_ticks, 100));
    ring.used.entries[0] = .{ .id = 31, .length = 0 };
    ring.used.index = 1;
    _ = try queue.complete(&ring);
    try std.testing.expectEqual(@as(?u64, 208), queue.nextTransmitWake(&submitted_ticks, 100));
    try queue.submit(&ring, 31, 0x1000, 128);
    submitted_ticks[31] = 109;
    ring.used.entries[1] = .{ .id = 0, .length = 0 };
    ring.used.index = 2;
    _ = try queue.complete(&ring);
    try std.testing.expectEqual(@as(?u64, 209), queue.nextTransmitWake(&submitted_ticks, 100));
    try std.testing.expect(queue.nextTransmitWake(&submitted_ticks, 0) == null);
    submitted_ticks[31] = std.math.maxInt(u64) - 4;
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), queue.nextTransmitWake(&submitted_ticks, 100));
    ring.used.entries[2] = .{ .id = 31, .length = 0 };
    ring.used.index = 3;
    _ = try queue.complete(&ring);
    try std.testing.expect(queue.nextTransmitWake(&submitted_ticks, 100) == null);
}
