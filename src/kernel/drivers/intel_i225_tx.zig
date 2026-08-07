const std = @import("std");

pub const DESCRIPTOR_COUNT: u32 = 64;
pub const CAPACITY: u32 = DESCRIPTOR_COUNT - 1;
pub const DESCRIPTOR_BYTES: u32 = 16;
pub const RING_BYTES: u32 = DESCRIPTOR_COUNT * DESCRIPTOR_BYTES;
pub const BUFFER_BYTES: u32 = 2048;
pub const BUFFER_REGION_BYTES: u32 = DESCRIPTOR_COUNT * BUFFER_BYTES;

const ADVANCED_DATA: u32 = 0x0030_0000;
const END_OF_PACKET: u32 = 0x0100_0000;
const INSERT_FCS: u32 = 0x0200_0000;
const REPORT_STATUS: u32 = 0x0800_0000;
const EXTENDED: u32 = 0x2000_0000;
const PAYLOAD_LENGTH_SHIFT: u5 = 14;
const STATUS_DONE: u32 = 1;

pub const Descriptor = extern struct {
    buffer_addr: u64,
    cmd_type_len: u32,
    olinfo_status: u32,
};

pub const Queue = struct {
    head: u32 = 0,
    tail: u32 = 0,
    in_flight: u32 = 0,
    submitted_at_ticks: [DESCRIPTOR_COUNT]u64 = [_]u64{0} ** DESCRIPTOR_COUNT,

    pub fn reserve(self: *Queue, now_ticks: u64) error{RingFull}!u32 {
        if (self.in_flight == CAPACITY) return error.RingFull;
        const descriptor_index = self.tail;
        self.submitted_at_ticks[descriptor_index] = now_ticks;
        self.tail = nextIndex(self.tail);
        self.in_flight += 1;
        return descriptor_index;
    }

    pub fn reclaimCompleted(self: *Queue, completion_status: u32) ?u32 {
        if (self.in_flight == 0 or !completionDone(completion_status)) return null;
        const descriptor_index = self.head;
        self.submitted_at_ticks[descriptor_index] = 0;
        self.head = nextIndex(self.head);
        self.in_flight -= 1;
        return descriptor_index;
    }

    pub fn full(self: *const Queue) bool {
        return self.in_flight == CAPACITY;
    }

    pub fn oldestSubmissionExpired(self: *const Queue, now_ticks: u64, timeout_ticks: u64) bool {
        if (self.in_flight == 0 or timeout_ticks == 0) return false;
        return now_ticks -% self.submitted_at_ticks[self.head] >= timeout_ticks;
    }
};

comptime {
    if (@sizeOf(Descriptor) != DESCRIPTOR_BYTES) @compileError("I225 TX descriptor layout changed");
    if (@alignOf(Descriptor) != @alignOf(u64)) @compileError("I225 TX descriptor alignment changed");
}

pub fn submissionDescriptor(buffer_address: u32, frame_len: usize) error{InvalidFrameLength}!Descriptor {
    if (frame_len == 0 or frame_len > BUFFER_BYTES) return error.InvalidFrameLength;
    return .{
        .buffer_addr = buffer_address,
        .cmd_type_len = ADVANCED_DATA | EXTENDED | INSERT_FCS | END_OF_PACKET |
            REPORT_STATUS | @as(u32, @intCast(frame_len)),
        .olinfo_status = @as(u32, @intCast(frame_len)) << PAYLOAD_LENGTH_SHIFT,
    };
}

pub fn completionDone(status: u32) bool {
    return (status & STATUS_DONE) != 0;
}

pub fn bufferAddress(region_base: u32, descriptor_index: u32) ?u32 {
    if (descriptor_index >= DESCRIPTOR_COUNT) return null;
    return std.math.add(u32, region_base, descriptor_index * BUFFER_BYTES) catch null;
}

pub fn nextIndex(descriptor_index: u32) u32 {
    return (descriptor_index + 1) % DESCRIPTOR_COUNT;
}

test "I225 transmit descriptors and buffers are bounded" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Descriptor));
    try std.testing.expectEqual(@as(u32, 1024), RING_BYTES);
    try std.testing.expectEqual(@as(u32, 128 * 1024), BUFFER_REGION_BYTES);
    try std.testing.expectEqual(@as(u32, 0x2000), bufferAddress(0x2000, 0).?);
    try std.testing.expectEqual(@as(u32, 0x2000 + (63 * 2048)), bufferAddress(0x2000, 63).?);
    try std.testing.expect(bufferAddress(0x2000, 64) == null);
    try std.testing.expect(bufferAddress(std.math.maxInt(u32) - 1024, 1) == null);

    const descriptor = try submissionDescriptor(0x4000, 1514);
    try std.testing.expectEqual(@as(u64, 0x4000), descriptor.buffer_addr);
    try std.testing.expectEqual(@as(u32, 1514), descriptor.cmd_type_len & 0xFFFF);
    try std.testing.expect(!completionDone(descriptor.olinfo_status));
    try std.testing.expect(completionDone(descriptor.olinfo_status | STATUS_DONE));
    try std.testing.expectError(error.InvalidFrameLength, submissionDescriptor(0x4000, 0));
    try std.testing.expectError(error.InvalidFrameLength, submissionDescriptor(0x4000, BUFFER_BYTES + 1));
}

test "I225 transmit queue applies backpressure and reuses reclaimed slots" {
    var queue = Queue{};
    var index: u32 = 0;
    while (index < CAPACITY) : (index += 1) {
        try std.testing.expectEqual(index, try queue.reserve(100 + index));
    }
    try std.testing.expect(queue.full());
    try std.testing.expectError(error.RingFull, queue.reserve(200));
    try std.testing.expectEqual(@as(u32, 0), queue.reclaimCompleted(STATUS_DONE).?);
    try std.testing.expectEqual(@as(u32, CAPACITY - 1), queue.in_flight);
    try std.testing.expectEqual(@as(u32, CAPACITY), try queue.reserve(200));
    try std.testing.expect(queue.full());

    index = 1;
    while (index <= CAPACITY) : (index += 1) {
        try std.testing.expectEqual(index, queue.reclaimCompleted(STATUS_DONE).?);
    }
    try std.testing.expect(queue.reclaimCompleted(STATUS_DONE) == null);
}

test "I225 transmit queue detects only an expired oldest submission" {
    var queue = Queue{};
    try std.testing.expect(!queue.oldestSubmissionExpired(100, 10));
    try std.testing.expectEqual(@as(u32, 0), try queue.reserve(100));
    try std.testing.expectEqual(@as(u32, 1), try queue.reserve(105));
    try std.testing.expect(!queue.oldestSubmissionExpired(109, 10));
    try std.testing.expect(queue.oldestSubmissionExpired(110, 10));
    try std.testing.expect(queue.reclaimCompleted(0) == null);
    try std.testing.expectEqual(@as(u32, 0), queue.reclaimCompleted(STATUS_DONE).?);
    try std.testing.expect(!queue.oldestSubmissionExpired(114, 10));
    try std.testing.expect(queue.oldestSubmissionExpired(115, 10));
    try std.testing.expectEqual(@as(u32, 1), queue.reclaimCompleted(STATUS_DONE).?);
    try std.testing.expect(!queue.oldestSubmissionExpired(1_000, 10));

    try std.testing.expectEqual(@as(u32, 2), try queue.reserve(std.math.maxInt(u64) - 4));
    try std.testing.expect(!queue.oldestSubmissionExpired(4, 10));
    try std.testing.expect(queue.oldestSubmissionExpired(5, 10));
}
