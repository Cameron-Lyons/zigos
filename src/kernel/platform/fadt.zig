const std = @import("std");
const acpi = @import("acpi.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const finishChecksum = checksum.finishSum8Prefix;
const readU16Le = endian.readU16Le;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU16Le = endian.writeU16Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const FADT_SIGNATURE = "FACP";
pub const SDT_HEADER_LENGTH: usize = acpi.SDT_HEADER_LENGTH;
pub const MIN_FADT_PM_LENGTH: usize = 96;
const FADT_TEST_TABLE_BYTES: usize = 132;
const FADT_REVISION_OFFSET: usize = 8;
const FADT_DSDT_OFFSET: usize = 40;
const FADT_SCI_INTERRUPT_OFFSET: usize = 46;
const FADT_PM1A_EVENT_BLOCK_OFFSET: usize = 56;
const FADT_PM1B_EVENT_BLOCK_OFFSET: usize = 60;
const FADT_PM1A_CONTROL_BLOCK_OFFSET: usize = 64;
const FADT_PM1B_CONTROL_BLOCK_OFFSET: usize = 68;
const FADT_PM_TIMER_BLOCK_OFFSET: usize = 76;
const FADT_PM1_EVENT_LENGTH_OFFSET: usize = 88;
const FADT_PM1_CONTROL_LENGTH_OFFSET: usize = 89;
const FADT_PM_TIMER_LENGTH_OFFSET: usize = 91;
const MIN_PM1_CONTROL_LENGTH: u8 = 2;
pub const RESET_REGISTER_OFFSET: usize = 116;
pub const RESET_VALUE_OFFSET: usize = 128;
pub const GENERIC_ADDRESS_STRUCTURE_BYTES: usize = 12;
const GAS_ADDRESS_OFFSET: usize = 4;

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

    const sdt = try acpi.parseSdtHeader(table);
    const table_length = sdt.length;
    if (table_length < MIN_FADT_PM_LENGTH or table_length > table.len) return error.InvalidLength;

    const pm1a_control_block = readU32Le(table[FADT_PM1A_CONTROL_BLOCK_OFFSET..][0..4]);
    const pm1b_control_block = readU32Le(table[FADT_PM1B_CONTROL_BLOCK_OFFSET..][0..4]);
    const pm1_control_length = table[FADT_PM1_CONTROL_LENGTH_OFFSET];
    if (pm1a_control_block == 0 and pm1b_control_block == 0) return error.MissingPmControlBlock;
    if (pm1_control_length < MIN_PM1_CONTROL_LENGTH) return error.InvalidPmControlLength;

    return .{
        .revision = table[FADT_REVISION_OFFSET],
        .dsdt_address = readU32Le(table[FADT_DSDT_OFFSET..][0..4]),
        .sci_interrupt = readU16Le(table[FADT_SCI_INTERRUPT_OFFSET..][0..2]),
        .pm1a_event_block = readU32Le(table[FADT_PM1A_EVENT_BLOCK_OFFSET..][0..4]),
        .pm1b_event_block = readU32Le(table[FADT_PM1B_EVENT_BLOCK_OFFSET..][0..4]),
        .pm1a_control_block = pm1a_control_block,
        .pm1b_control_block = pm1b_control_block,
        .pm_timer_block = readU32Le(table[FADT_PM_TIMER_BLOCK_OFFSET..][0..4]),
        .pm1_event_length = table[FADT_PM1_EVENT_LENGTH_OFFSET],
        .pm1_control_length = pm1_control_length,
        .pm_timer_length = table[FADT_PM_TIMER_LENGTH_OFFSET],
        .reset_register = parseResetRegister(table[0..table_length]),
        .reset_value = if (table_length > RESET_VALUE_OFFSET) table[RESET_VALUE_OFFSET] else 0,
    };
}

fn parseResetRegister(table: []const u8) ?GenericAddress {
    if (table.len < RESET_REGISTER_OFFSET + GENERIC_ADDRESS_STRUCTURE_BYTES) return null;
    const gas = table[RESET_REGISTER_OFFSET .. RESET_REGISTER_OFFSET + GENERIC_ADDRESS_STRUCTURE_BYTES];
    const address = readU64Le(gas[GAS_ADDRESS_OFFSET..][0..8]);
    if (address == 0) return null;
    return .{
        .address_space_id = gas[0],
        .register_bit_width = gas[1],
        .register_bit_offset = gas[2],
        .access_size = gas[3],
        .address = address,
    };
}

fn validFadt() [FADT_TEST_TABLE_BYTES]u8 {
    var table = [_]u8{0} ** FADT_TEST_TABLE_BYTES;
    @memcpy(table[0..4], FADT_SIGNATURE);
    writeU32Le(table[4..8], table.len);
    table[FADT_REVISION_OFFSET] = 6;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11TN ");
    writeU32Le(table[FADT_DSDT_OFFSET..][0..4], 0x00AB_C000);
    writeU16Le(table[FADT_SCI_INTERRUPT_OFFSET..][0..2], 9);
    writeU32Le(table[FADT_PM1A_EVENT_BLOCK_OFFSET..][0..4], 0x1800);
    writeU32Le(table[FADT_PM1A_CONTROL_BLOCK_OFFSET..][0..4], 0x1804);
    writeU32Le(table[FADT_PM_TIMER_BLOCK_OFFSET..][0..4], 0x1808);
    table[FADT_PM1_EVENT_LENGTH_OFFSET] = 4;
    table[FADT_PM1_CONTROL_LENGTH_OFFSET] = MIN_PM1_CONTROL_LENGTH;
    table[FADT_PM_TIMER_LENGTH_OFFSET] = 4;
    table[RESET_REGISTER_OFFSET] = 1;
    table[RESET_REGISTER_OFFSET + 1] = 8;
    table[RESET_REGISTER_OFFSET + 3] = 1;
    writeU64Le(table[RESET_REGISTER_OFFSET + GAS_ADDRESS_OFFSET ..][0..8], 0xCF9);
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
    writeU32Le(table[FADT_PM1A_CONTROL_BLOCK_OFFSET..][0..4], 0);
    finishChecksum(table[0..], 9, table.len);
    try std.testing.expectError(error.MissingPmControlBlock, parseFadt(table[0..]));
}

test "FADT parser rejects corrupt checksum" {
    var table = validFadt();
    table[FADT_PM1A_CONTROL_BLOCK_OFFSET] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseFadt(table[0..]));
}
