const std = @import("std");

pub const DESCRIPTOR_COUNT: u32 = 64;
pub const DESCRIPTOR_BYTES: u32 = 16;
pub const RING_BYTES: u32 = DESCRIPTOR_COUNT * DESCRIPTOR_BYTES;
pub const BUFFER_BYTES: u32 = 2048;
pub const BUFFER_REGION_BYTES: u32 = DESCRIPTOR_COUNT * BUFFER_BYTES;

const STATUS_DONE: u32 = 1;
const STATUS_END_OF_PACKET: u32 = 1 << 1;
const ERROR_RECEIVE: u32 = 1 << 31;

pub const Descriptor = extern struct {
    packet_or_metadata: u64,
    header_or_writeback: u64,
};

pub const Completion = struct {
    done: bool,
    end_of_packet: bool,
    receive_error: bool,
    length: u16,
    vlan: u16,

    pub fn validSingleBuffer(self: Completion) bool {
        return self.done and self.end_of_packet and !self.receive_error and
            self.length != 0 and self.length <= BUFFER_BYTES;
    }
};

comptime {
    if (@sizeOf(Descriptor) != DESCRIPTOR_BYTES) @compileError("I225 RX descriptor layout changed");
    if (@alignOf(Descriptor) != @alignOf(u64)) @compileError("I225 RX descriptor alignment changed");
}

pub fn availableDescriptor(buffer_address: u32) Descriptor {
    return .{
        .packet_or_metadata = buffer_address,
        .header_or_writeback = 0,
    };
}

pub fn decodeCompletion(writeback: u64) Completion {
    const status_error: u32 = @truncate(writeback);
    return .{
        .done = (status_error & STATUS_DONE) != 0,
        .end_of_packet = (status_error & STATUS_END_OF_PACKET) != 0,
        .receive_error = (status_error & ERROR_RECEIVE) != 0,
        .length = @truncate(writeback >> 32),
        .vlan = @truncate(writeback >> 48),
    };
}

pub fn bufferAddress(region_base: u32, descriptor_index: u32) ?u32 {
    if (descriptor_index >= DESCRIPTOR_COUNT) return null;
    return std.math.add(u32, region_base, descriptor_index * BUFFER_BYTES) catch null;
}

pub fn nextIndex(descriptor_index: u32) u32 {
    return (descriptor_index + 1) % DESCRIPTOR_COUNT;
}

test "I225 advanced receive descriptor layout and buffer plan are bounded" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Descriptor));
    try std.testing.expectEqual(@as(u32, 1024), RING_BYTES);
    try std.testing.expectEqual(@as(u32, 128 * 1024), BUFFER_REGION_BYTES);
    try std.testing.expectEqual(@as(u32, 0x2000), bufferAddress(0x2000, 0).?);
    try std.testing.expectEqual(@as(u32, 0x2000 + (63 * 2048)), bufferAddress(0x2000, 63).?);
    try std.testing.expect(bufferAddress(0x2000, 64) == null);
    try std.testing.expect(bufferAddress(std.math.maxInt(u32) - 1024, 1) == null);
    try std.testing.expectEqual(@as(u32, 0), nextIndex(63));
}

test "I225 receive completion decoding requires done end-of-packet and no receive error" {
    const valid_raw = @as(u64, 3) | (@as(u64, 1514) << 32) | (@as(u64, 7) << 48);
    const valid = decodeCompletion(valid_raw);
    try std.testing.expect(valid.validSingleBuffer());
    try std.testing.expectEqual(@as(u16, 1514), valid.length);
    try std.testing.expectEqual(@as(u16, 7), valid.vlan);

    try std.testing.expect(!decodeCompletion(@as(u64, 2) | (@as(u64, 64) << 32)).validSingleBuffer());
    try std.testing.expect(!decodeCompletion(@as(u64, 1) | (@as(u64, 64) << 32)).validSingleBuffer());
    try std.testing.expect(!decodeCompletion(@as(u64, 0x8000_0003) | (@as(u64, 64) << 32)).validSingleBuffer());
    try std.testing.expect(!decodeCompletion(@as(u64, 3) | (@as(u64, BUFFER_BYTES + 1) << 32)).validSingleBuffer());
}
