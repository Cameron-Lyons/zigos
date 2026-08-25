const std = @import("std");
const ascii = @import("../utils/ascii.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const checksumIsValid = checksum.sum8IsZero;
const finishChecksum = checksum.finishSum8;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

const SMBIOS3_ANCHOR = "_SM3_";
const BIOS_SCAN_BASE: usize = 0xF0000;
const BIOS_SCAN_LENGTH: usize = 0x10000;
const ENTRY_ALIGNMENT: usize = 16;
const SMBIOS3_MIN_LENGTH: usize = 0x18;
const SMBIOS3_MAJOR_VERSION: u8 = 3;
const MAX_TABLE_BYTES: usize = 1024 * 1024;
const STRUCTURE_HEADER_BYTES: usize = 4;
const STRUCTURE_TYPE_OFFSET: usize = 0;
const STRUCTURE_FORMATTED_LENGTH_OFFSET: usize = 1;
const SYSTEM_INFORMATION_TYPE: u8 = 1;
const BASEBOARD_INFORMATION_TYPE: u8 = 2;
const END_OF_TABLE_TYPE: u8 = 127;
const STRING_SET_TERMINATOR_BYTES: usize = 2;
const SMBIOS3_CHECKSUM_OFFSET: usize = 5;
const SMBIOS3_LENGTH_OFFSET: usize = 6;
const SMBIOS3_MAJOR_VERSION_OFFSET: usize = 7;
const SMBIOS3_MINOR_VERSION_OFFSET: usize = 8;
const SMBIOS3_TABLE_LENGTH_OFFSET: usize = 0x0C;
const SMBIOS3_TABLE_ADDRESS_OFFSET: usize = 0x10;

pub const NUC11TNKI5_SKU = "NUC11TNKi5";
pub const REQUIRES_SMBIOS3 = true;

pub const Error = error{
    TooSmall,
    BadAnchor,
    BadChecksum,
    InvalidLength,
    UnsupportedVersion,
};

pub const EntryPoint = struct {
    table_address: u64,
    table_length: usize,
};

pub fn scanBiosForEntryPoint() ?EntryPoint {
    const bytes = @as([*]const u8, @ptrFromInt(BIOS_SCAN_BASE))[0..BIOS_SCAN_LENGTH];
    return findEntryPoint(bytes, BIOS_SCAN_BASE);
}

pub fn scanBiosForNuc11Tnki5() bool {
    const entry = scanBiosForEntryPoint() orelse return false;
    if (entry.table_length == 0 or entry.table_length > MAX_TABLE_BYTES) return false;
    const max_address: u64 = std.math.maxInt(usize);
    if (entry.table_address > max_address - @as(u64, @intCast(entry.table_length))) return false;
    const table = @as([*]const u8, @ptrFromInt(@as(usize, @intCast(entry.table_address))))[0..entry.table_length];
    return tableContainsTargetSku(table, NUC11TNKI5_SKU);
}

pub fn findEntryPoint(buffer: []const u8, base_physical_address: usize) ?EntryPoint {
    var offset: usize = alignedOffset(base_physical_address);
    while (offset + SMBIOS3_MIN_LENGTH <= buffer.len) : (offset += ENTRY_ALIGNMENT) {
        if (parseEntryPoint(buffer[offset..])) |entry| {
            return entry;
        } else |_| {}
    }
    return null;
}

pub fn parseEntryPoint(bytes: []const u8) Error!EntryPoint {
    if (bytes.len < SMBIOS3_MIN_LENGTH) return error.TooSmall;
    if (!std.mem.eql(u8, bytes[0..SMBIOS3_ANCHOR.len], SMBIOS3_ANCHOR)) return error.BadAnchor;
    return parseSmbios3EntryPoint(bytes);
}

pub fn tableContainsTargetSku(table: []const u8, target: []const u8) bool {
    if (target.len == 0) return false;

    var offset: usize = 0;
    while (offset + STRUCTURE_HEADER_BYTES <= table.len) {
        const structure_type = table[offset + STRUCTURE_TYPE_OFFSET];
        const formatted_length = table[offset + STRUCTURE_FORMATTED_LENGTH_OFFSET];
        if (formatted_length < STRUCTURE_HEADER_BYTES or offset + formatted_length > table.len) return false;

        const end = structureEnd(table, offset + formatted_length) orelse return false;
        const structure = table[offset..end];
        if ((structure_type == SYSTEM_INFORMATION_TYPE or structure_type == BASEBOARD_INFORMATION_TYPE) and ascii.containsIgnoreCase(structure, target)) {
            return true;
        }
        if (structure_type == END_OF_TABLE_TYPE) return false;
        offset = end;
    }
    return false;
}

fn parseSmbios3EntryPoint(bytes: []const u8) Error!EntryPoint {
    const length = bytes[SMBIOS3_LENGTH_OFFSET];
    if (length < SMBIOS3_MIN_LENGTH or length > bytes.len) return error.InvalidLength;
    if (!checksumIsValid(bytes[0..length])) return error.BadChecksum;
    if (bytes[SMBIOS3_MAJOR_VERSION_OFFSET] < SMBIOS3_MAJOR_VERSION) return error.UnsupportedVersion;

    const table_length = readU32Le(bytes[SMBIOS3_TABLE_LENGTH_OFFSET..][0..4]);
    const table_address = readU64Le(bytes[SMBIOS3_TABLE_ADDRESS_OFFSET..][0..8]);
    if (table_length == 0 or table_length > MAX_TABLE_BYTES or table_address == 0) return error.InvalidLength;

    return .{
        .table_address = table_address,
        .table_length = table_length,
    };
}

fn structureEnd(table: []const u8, strings_start: usize) ?usize {
    var index = strings_start;
    while (index + 1 < table.len) : (index += 1) {
        if (table[index] == 0 and table[index + 1] == 0) return index + STRING_SET_TERMINATOR_BYTES;
    }
    return null;
}

fn alignedOffset(base_physical_address: usize) usize {
    const remainder = base_physical_address % ENTRY_ALIGNMENT;
    return if (remainder == 0) 0 else ENTRY_ALIGNMENT - remainder;
}

test "SMBIOS parser finds NUC11TNKi5 SKU in system information strings" {
    const table = [_]u8{
        1,   0x1B, 0x01, 0x00,
        1,   2,    3,    4,
        0,   0,    0,    0,
        0,   0,    0,    0,
        0,   0,    0,    0,
        0,   0,    0,    0,
        5,   6,    0,    'I',
        'n', 't',  'e',  'l',
        0,   'N',  'U',  'C',
        ' ', '1',  '1',  ' ',
        'P', 'r',  'o',  0,
        'T', 'N',  0,    'S',
        'E', 'R',  'I',  'A',
        'L', 0,    'N',  'U',
        'C', '1',  '1',  'T',
        'N', 'K',  'i',  '5',
        0,   'T',  'i',  'g',
        'e', 'r',  ' ',  'C',
        'a', 'n',  'y',  'o',
        'n', 0,    0,    127,
        4,   0x7F, 0x00, 0,
        0,
    };
    try std.testing.expect(tableContainsTargetSku(table[0..], NUC11TNKI5_SKU));
    try std.testing.expect(!tableContainsTargetSku(table[0..], "NUC12"));
}

test "SMBIOS 3 entry point validates checksum and table address" {
    var entry = [_]u8{0} ** SMBIOS3_MIN_LENGTH;
    @memcpy(entry[0..SMBIOS3_ANCHOR.len], SMBIOS3_ANCHOR);
    entry[SMBIOS3_LENGTH_OFFSET] = SMBIOS3_MIN_LENGTH;
    entry[SMBIOS3_MAJOR_VERSION_OFFSET] = 3;
    entry[SMBIOS3_MINOR_VERSION_OFFSET] = 4;
    writeU32Le(entry[SMBIOS3_TABLE_LENGTH_OFFSET..][0..4], 128);
    writeU64Le(entry[SMBIOS3_TABLE_ADDRESS_OFFSET..][0..8], 0x0000_0000_00F1_0000);
    finishChecksum(entry[0..], SMBIOS3_CHECKSUM_OFFSET);

    const parsed = try parseEntryPoint(entry[0..]);
    try std.testing.expectEqual(@as(usize, 128), parsed.table_length);
    try std.testing.expectEqual(@as(u64, 0xF1_0000), parsed.table_address);

    @memcpy(entry[0..4], "_SM_");
    try std.testing.expectError(error.BadAnchor, parseEntryPoint(entry[0..]));

    @memcpy(entry[0..SMBIOS3_ANCHOR.len], SMBIOS3_ANCHOR);
    entry[SMBIOS3_MAJOR_VERSION_OFFSET] = SMBIOS3_MAJOR_VERSION - 1;
    finishChecksum(entry[0..], SMBIOS3_CHECKSUM_OFFSET);
    try std.testing.expectError(error.UnsupportedVersion, parseEntryPoint(entry[0..]));
}
