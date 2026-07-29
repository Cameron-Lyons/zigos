const std = @import("std");
const acpi = @import("acpi.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

pub const MCFG_SIGNATURE = "MCFG";
pub const ALLOCATION_OFFSET: usize = acpi.SDT_HEADER_LENGTH + 8;
pub const ALLOCATION_BYTES: usize = 16;
pub const ECAM_BUS_BYTES: u64 = 1 << 20;

const SEGMENT_GROUP_OFFSET: usize = 8;
const START_BUS_OFFSET: usize = 10;
const END_BUS_OFFSET: usize = 11;
const RESERVED_OFFSET: usize = 12;
const TEST_TABLE_BYTES: usize = ALLOCATION_OFFSET + ALLOCATION_BYTES;

pub const Error = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    InvalidLength,
    InvalidAllocation,
    MissingSegmentZero,
};

pub const Allocation = struct {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,

    pub fn busCount(self: Allocation) u16 {
        return @as(u16, self.end_bus) - self.start_bus + 1;
    }

    pub fn containsBus(self: Allocation, bus: u8) bool {
        return bus >= self.start_bus and bus <= self.end_bus;
    }
};

pub fn segmentZeroAllocation(table: []const u8) Error!Allocation {
    if (table.len < ALLOCATION_OFFSET) return error.TooSmall;
    if (!std.mem.eql(u8, table[0..MCFG_SIGNATURE.len], MCFG_SIGNATURE)) return error.BadSignature;

    const header = try acpi.parseSdtHeader(table);
    const table_length: usize = @intCast(header.length);
    if (table_length < ALLOCATION_OFFSET + ALLOCATION_BYTES) return error.InvalidLength;
    const payload_bytes = table_length - ALLOCATION_OFFSET;
    if (payload_bytes % ALLOCATION_BYTES != 0) return error.InvalidLength;

    var selected: ?Allocation = null;
    var offset = ALLOCATION_OFFSET;
    while (offset < table_length) : (offset += ALLOCATION_BYTES) {
        const entry = table[offset .. offset + ALLOCATION_BYTES];
        const allocation = Allocation{
            .base_address = endian.readU64Le(entry[0..8]),
            .segment_group = endian.readU16Le(entry[SEGMENT_GROUP_OFFSET..][0..2]),
            .start_bus = entry[START_BUS_OFFSET],
            .end_bus = entry[END_BUS_OFFSET],
        };
        if (!allocationValid(allocation) or endian.readU32Le(entry[RESERVED_OFFSET..][0..4]) != 0) {
            return error.InvalidAllocation;
        }
        if (allocation.segment_group == 0 and allocation.start_bus == 0) {
            if (selected != null) return error.InvalidAllocation;
            selected = allocation;
        }
    }
    return selected orelse error.MissingSegmentZero;
}

fn allocationValid(allocation: Allocation) bool {
    if (allocation.base_address == 0 or allocation.base_address % ECAM_BUS_BYTES != 0) return false;
    if (allocation.start_bus > allocation.end_bus) return false;
    const span = std.math.mul(u64, allocation.busCount(), ECAM_BUS_BYTES) catch return false;
    _ = std.math.add(u64, allocation.base_address, span - 1) catch return false;
    return true;
}

fn validMcfg() [TEST_TABLE_BYTES]u8 {
    var table = [_]u8{0} ** TEST_TABLE_BYTES;
    @memcpy(table[0..4], MCFG_SIGNATURE);
    endian.writeU32Le(table[4..8], table.len);
    table[8] = 1;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "PCIEECAM");
    endian.writeU64Le(table[ALLOCATION_OFFSET..][0..8], 0x0000_0000_B000_0000);
    endian.writeU16Le(table[ALLOCATION_OFFSET + SEGMENT_GROUP_OFFSET ..][0..2], 0);
    table[ALLOCATION_OFFSET + START_BUS_OFFSET] = 0;
    table[ALLOCATION_OFFSET + END_BUS_OFFSET] = 0xFF;
    checksum.finishSum8Prefix(table[0..], 9, table.len);
    return table;
}

test "MCFG parser selects the segment-zero ECAM allocation" {
    const table = validMcfg();
    const allocation = try segmentZeroAllocation(table[0..]);
    try std.testing.expectEqual(@as(u64, 0xB000_0000), allocation.base_address);
    try std.testing.expectEqual(@as(u16, 0), allocation.segment_group);
    try std.testing.expectEqual(@as(u8, 0), allocation.start_bus);
    try std.testing.expectEqual(@as(u8, 0xFF), allocation.end_bus);
    try std.testing.expectEqual(@as(u16, 256), allocation.busCount());
    try std.testing.expect(allocation.containsBus(0x80));
}

test "MCFG parser rejects malformed allocation metadata" {
    var bad_checksum = validMcfg();
    bad_checksum[ALLOCATION_OFFSET] +%= 1;
    try std.testing.expectError(error.BadChecksum, segmentZeroAllocation(bad_checksum[0..]));

    var reserved = validMcfg();
    reserved[ALLOCATION_OFFSET + RESERVED_OFFSET] = 1;
    checksum.finishSum8Prefix(reserved[0..], 9, reserved.len);
    try std.testing.expectError(error.InvalidAllocation, segmentZeroAllocation(reserved[0..]));

    var unaligned = validMcfg();
    endian.writeU64Le(unaligned[ALLOCATION_OFFSET..][0..8], 0xB000_1000);
    checksum.finishSum8Prefix(unaligned[0..], 9, unaligned.len);
    try std.testing.expectError(error.InvalidAllocation, segmentZeroAllocation(unaligned[0..]));

    var reversed = validMcfg();
    reversed[ALLOCATION_OFFSET + START_BUS_OFFSET] = 2;
    reversed[ALLOCATION_OFFSET + END_BUS_OFFSET] = 1;
    checksum.finishSum8Prefix(reversed[0..], 9, reversed.len);
    try std.testing.expectError(error.InvalidAllocation, segmentZeroAllocation(reversed[0..]));
}

test "MCFG parser requires a root-bus allocation in segment zero" {
    var table = validMcfg();
    endian.writeU16Le(table[ALLOCATION_OFFSET + SEGMENT_GROUP_OFFSET ..][0..2], 1);
    checksum.finishSum8Prefix(table[0..], 9, table.len);
    try std.testing.expectError(error.MissingSegmentZero, segmentZeroAllocation(table[0..]));
}
