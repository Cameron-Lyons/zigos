const std = @import("std");

pub const FADT_SIGNATURE = "FACP";
pub const SDT_HEADER_LENGTH: usize = 36;
pub const MIN_FADT_PM_LENGTH: usize = 96;
pub const RESET_REGISTER_OFFSET: usize = 116;
pub const RESET_VALUE_OFFSET: usize = 128;
pub const GENERIC_ADDRESS_STRUCTURE_BYTES: usize = 12;

pub const Error = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    InvalidLength,
    MissingPmControlBlock,
    InvalidPmControlLength,
};

pub const GenericAddress = struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

pub const FixedAcpiDescription = struct {
    revision: u8,
    dsdt_address: u64,
    sci_interrupt: u16,
    pm1a_event_block: u32,
    pm1b_event_block: u32,
    pm1a_control_block: u32,
    pm1b_control_block: u32,
    pm_timer_block: u32,
    pm1_event_length: u8,
    pm1_control_length: u8,
    pm_timer_length: u8,
    reset_register: ?GenericAddress,
    reset_value: u8,
};

pub fn parseFadt(table: []const u8) Error!FixedAcpiDescription {
    if (table.len < MIN_FADT_PM_LENGTH) return error.TooSmall;
    if (!std.mem.eql(u8, table[0..FADT_SIGNATURE.len], FADT_SIGNATURE)) return error.BadSignature;

    const table_length = readU32Le(table[4..8]);
    if (table_length < MIN_FADT_PM_LENGTH or table_length > table.len) return error.InvalidLength;
    if (!checksumIsValid(table[0..table_length])) return error.BadChecksum;

    const pm1a_control_block = readU32Le(table[64..68]);
    const pm1b_control_block = readU32Le(table[68..72]);
    const pm1_control_length = table[89];
    if (pm1a_control_block == 0 and pm1b_control_block == 0) return error.MissingPmControlBlock;
    if (pm1_control_length < 2) return error.InvalidPmControlLength;

    return .{
        .revision = table[8],
        .dsdt_address = readU32Le(table[40..44]),
        .sci_interrupt = readU16Le(table[46..48]),
        .pm1a_event_block = readU32Le(table[56..60]),
        .pm1b_event_block = readU32Le(table[60..64]),
        .pm1a_control_block = pm1a_control_block,
        .pm1b_control_block = pm1b_control_block,
        .pm_timer_block = readU32Le(table[76..80]),
        .pm1_event_length = table[88],
        .pm1_control_length = pm1_control_length,
        .pm_timer_length = table[91],
        .reset_register = parseResetRegister(table[0..table_length]),
        .reset_value = if (table_length > RESET_VALUE_OFFSET) table[RESET_VALUE_OFFSET] else 0,
    };
}

fn parseResetRegister(table: []const u8) ?GenericAddress {
    if (table.len < RESET_REGISTER_OFFSET + GENERIC_ADDRESS_STRUCTURE_BYTES) return null;
    const gas = table[RESET_REGISTER_OFFSET .. RESET_REGISTER_OFFSET + GENERIC_ADDRESS_STRUCTURE_BYTES];
    const address = readU64Le(gas[4..12]);
    if (address == 0) return null;
    return .{
        .address_space_id = gas[0],
        .register_bit_width = gas[1],
        .register_bit_offset = gas[2],
        .access_size = gas[3],
        .address = address,
    };
}

fn checksumIsValid(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum == 0;
}

fn readU16Le(bytes: []const u8) u16 {
    return @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
}

fn readU32Le(bytes: []const u8) u32 {
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn readU64Le(bytes: []const u8) u64 {
    return @as(u64, bytes[0]) |
        (@as(u64, bytes[1]) << 8) |
        (@as(u64, bytes[2]) << 16) |
        (@as(u64, bytes[3]) << 24) |
        (@as(u64, bytes[4]) << 32) |
        (@as(u64, bytes[5]) << 40) |
        (@as(u64, bytes[6]) << 48) |
        (@as(u64, bytes[7]) << 56);
}

fn writeU16Le(bytes: []u8, value: u16) void {
    bytes[0] = @truncate(value);
    bytes[1] = @truncate(value >> 8);
}

fn writeU32Le(bytes: []u8, value: u32) void {
    bytes[0] = @truncate(value);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value >> 16);
    bytes[3] = @truncate(value >> 24);
}

fn writeU64Le(bytes: []u8, value: u64) void {
    bytes[0] = @truncate(value);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value >> 16);
    bytes[3] = @truncate(value >> 24);
    bytes[4] = @truncate(value >> 32);
    bytes[5] = @truncate(value >> 40);
    bytes[6] = @truncate(value >> 48);
    bytes[7] = @truncate(value >> 56);
}

fn finishChecksum(bytes: []u8, checksum_index: usize, length: usize) void {
    bytes[checksum_index] = 0;
    var sum: u8 = 0;
    for (bytes[0..length]) |byte| {
        sum +%= byte;
    }
    bytes[checksum_index] = 0 -% sum;
}

fn validFadt() [132]u8 {
    var table = [_]u8{0} ** 132;
    @memcpy(table[0..4], FADT_SIGNATURE);
    writeU32Le(table[4..8], table.len);
    table[8] = 6;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11TN ");
    writeU32Le(table[40..44], 0x00AB_C000);
    writeU16Le(table[46..48], 9);
    writeU32Le(table[56..60], 0x1800);
    writeU32Le(table[64..68], 0x1804);
    writeU32Le(table[76..80], 0x1808);
    table[88] = 4;
    table[89] = 2;
    table[91] = 4;
    table[RESET_REGISTER_OFFSET] = 1;
    table[RESET_REGISTER_OFFSET + 1] = 8;
    table[RESET_REGISTER_OFFSET + 3] = 1;
    writeU64Le(table[RESET_REGISTER_OFFSET + 4 .. RESET_REGISTER_OFFSET + 12], 0xCF9);
    table[RESET_VALUE_OFFSET] = 0x06;
    finishChecksum(table[0..], 9, table.len);
    return table;
}

test "FADT parser extracts PM control and reset plumbing" {
    const table = validFadt();
    const fadt = try parseFadt(table[0..]);
    try std.testing.expectEqual(@as(u8, 6), fadt.revision);
    try std.testing.expectEqual(@as(u64, 0x00AB_C000), fadt.dsdt_address);
    try std.testing.expectEqual(@as(u16, 9), fadt.sci_interrupt);
    try std.testing.expectEqual(@as(u32, 0x1804), fadt.pm1a_control_block);
    try std.testing.expectEqual(@as(u8, 2), fadt.pm1_control_length);
    try std.testing.expectEqual(@as(u64, 0xCF9), fadt.reset_register.?.address);
    try std.testing.expectEqual(@as(u8, 0x06), fadt.reset_value);
}

test "FADT parser rejects missing PM control blocks" {
    var table = validFadt();
    writeU32Le(table[64..68], 0);
    finishChecksum(table[0..], 9, table.len);
    try std.testing.expectError(error.MissingPmControlBlock, parseFadt(table[0..]));
}

test "FADT parser rejects corrupt checksum" {
    var table = validFadt();
    table[64] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseFadt(table[0..]));
}
