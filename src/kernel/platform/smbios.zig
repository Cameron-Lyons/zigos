const std = @import("std");
const paging = @import("../memory/paging64.zig");
const ascii = @import("../utils/ascii.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const checksumIsValid = checksum.sum8IsZero;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
const EFI_SYSTEM_TABLE_MIN_REVISION: u32 = 0x0002_0000;
const EFI_SYSTEM_TABLE_BYTES: usize = 120;
const EFI_SYSTEM_TABLE_REVISION_OFFSET: usize = 8;
const EFI_SYSTEM_TABLE_HEADER_SIZE_OFFSET: usize = 12;
const EFI_SYSTEM_TABLE_CRC32_OFFSET: usize = 16;
const EFI_SYSTEM_TABLE_ENTRY_COUNT_OFFSET: usize = 104;
const EFI_SYSTEM_TABLE_CONFIG_ADDRESS_OFFSET: usize = 112;
const EFI_CONFIGURATION_ENTRY_BYTES: usize = 24;
const EFI_CONFIGURATION_ENTRY_ADDRESS_OFFSET: usize = 16;
const MAX_CONFIGURATION_ENTRIES: usize = 256;
const SMBIOS3_TABLE_GUID = [_]u8{
    0x44, 0x15, 0xfd, 0xf2,
    0x94, 0x97, 0x2c, 0x4a,
    0x99, 0x2e, 0xe5, 0xbb,
    0xcf, 0x20, 0xe3, 0x94,
};

const SMBIOS3_ANCHOR = "_SM3_";
const SMBIOS3_MIN_LENGTH: usize = 0x18;
const SMBIOS3_MAJOR_VERSION: u8 = 3;
const SMBIOS3_CHECKSUM_OFFSET: usize = 5;
const SMBIOS3_LENGTH_OFFSET: usize = 6;
const SMBIOS3_MAJOR_VERSION_OFFSET: usize = 7;
const SMBIOS3_TABLE_LENGTH_OFFSET: usize = 0x0C;
const SMBIOS3_TABLE_ADDRESS_OFFSET: usize = 0x10;
const MAX_TABLE_BYTES: usize = 1024 * 1024;

const STRUCTURE_HEADER_BYTES: usize = 4;
const STRUCTURE_TYPE_OFFSET: usize = 0;
const STRUCTURE_FORMATTED_LENGTH_OFFSET: usize = 1;
const SYSTEM_INFORMATION_TYPE: u8 = 1;
const BASEBOARD_INFORMATION_TYPE: u8 = 2;
const END_OF_TABLE_TYPE: u8 = 127;
const STRING_SET_TERMINATOR_BYTES: usize = 2;

pub const NUC11TNKI5_SKU = "NUC11TNKi5";
pub const REQUIRES_SMBIOS3 = true;
pub const USES_EFI64_SYSTEM_TABLE_HANDOFF = true;

const Error = error{
    TooSmall,
    BadSignature,
    BadAnchor,
    BadChecksum,
    InvalidLength,
    UnsupportedVersion,
};

const EfiSystemTable = struct {
    configuration_table_address: u64,
    configuration_table_count: usize,
};

const EntryPoint = struct {
    table_address: u64,
    table_length: usize,
};

pub fn efiSystemTableContainsTargetSku(system_table_address: u64, target: []const u8) bool {
    if (target.len == 0) return false;

    const system_table_bytes = mappedPhysicalBytes(system_table_address, EFI_SYSTEM_TABLE_BYTES) orelse
        return false;
    const system_table = parseEfiSystemTable(system_table_bytes) catch return false;
    const entries_length = std.math.mul(
        usize,
        system_table.configuration_table_count,
        EFI_CONFIGURATION_ENTRY_BYTES,
    ) catch return false;
    const entries = mappedPhysicalBytes(system_table.configuration_table_address, entries_length) orelse
        return false;
    const entry_point_address = findSmbios3EntryPointAddress(entries) orelse return false;

    const fixed_entry_point = mappedPhysicalBytes(entry_point_address, SMBIOS3_MIN_LENGTH) orelse return false;
    const entry_point_length = fixed_entry_point[SMBIOS3_LENGTH_OFFSET];
    if (entry_point_length < SMBIOS3_MIN_LENGTH) return false;
    const entry_point_bytes = mappedPhysicalBytes(entry_point_address, entry_point_length) orelse return false;
    const entry_point = parseSmbios3EntryPoint(entry_point_bytes) catch return false;
    const table = mappedPhysicalBytes(entry_point.table_address, entry_point.table_length) orelse return false;
    return tableContainsTargetSku(table, target);
}

fn mappedPhysicalBytes(physical_address: u64, length: usize) ?[]const u8 {
    if (length == 0) return null;
    const last_physical_address = std.math.add(
        u64,
        physical_address,
        std.math.cast(u64, length - 1) orelse return null,
    ) catch return null;
    _ = paging.directMapAddress(last_physical_address) orelse return null;
    const alias = paging.directMapAddress(physical_address) orelse return null;
    return @as([*]const u8, @ptrFromInt(alias))[0..length];
}

fn parseEfiSystemTable(bytes: []const u8) Error!EfiSystemTable {
    if (bytes.len < EFI_SYSTEM_TABLE_BYTES) return error.TooSmall;
    if (readU64Le(bytes[0..8]) != EFI_SYSTEM_TABLE_SIGNATURE) return error.BadSignature;
    if (readU32Le(bytes[EFI_SYSTEM_TABLE_REVISION_OFFSET..][0..4]) < EFI_SYSTEM_TABLE_MIN_REVISION) {
        return error.UnsupportedVersion;
    }
    if (readU32Le(bytes[EFI_SYSTEM_TABLE_HEADER_SIZE_OFFSET..][0..4]) != EFI_SYSTEM_TABLE_BYTES) {
        return error.InvalidLength;
    }
    if (!efiTableHeaderChecksumIsValid(bytes[0..EFI_SYSTEM_TABLE_BYTES])) return error.BadChecksum;

    const entry_count_u64 = readU64Le(bytes[EFI_SYSTEM_TABLE_ENTRY_COUNT_OFFSET..][0..8]);
    const entry_count = std.math.cast(usize, entry_count_u64) orelse return error.InvalidLength;
    const configuration_table_address = readU64Le(bytes[EFI_SYSTEM_TABLE_CONFIG_ADDRESS_OFFSET..][0..8]);
    if (entry_count == 0 or entry_count > MAX_CONFIGURATION_ENTRIES or configuration_table_address == 0) {
        return error.InvalidLength;
    }
    return .{
        .configuration_table_address = configuration_table_address,
        .configuration_table_count = entry_count,
    };
}

fn efiTableHeaderChecksumIsValid(bytes: []const u8) bool {
    if (bytes.len != EFI_SYSTEM_TABLE_BYTES) return false;
    var crc: std.hash.Crc32 = .init();
    crc.update(bytes[0..EFI_SYSTEM_TABLE_CRC32_OFFSET]);
    crc.update(&[_]u8{0} ** 4);
    crc.update(bytes[EFI_SYSTEM_TABLE_CRC32_OFFSET + 4 ..]);
    return crc.final() == readU32Le(bytes[EFI_SYSTEM_TABLE_CRC32_OFFSET..][0..4]);
}

fn findSmbios3EntryPointAddress(entries: []const u8) ?u64 {
    if (entries.len == 0 or entries.len % EFI_CONFIGURATION_ENTRY_BYTES != 0) return null;
    var offset: usize = 0;
    while (offset < entries.len) : (offset += EFI_CONFIGURATION_ENTRY_BYTES) {
        const entry = entries[offset..][0..EFI_CONFIGURATION_ENTRY_BYTES];
        if (!std.mem.eql(u8, entry[0..SMBIOS3_TABLE_GUID.len], &SMBIOS3_TABLE_GUID)) continue;
        const address = readU64Le(entry[EFI_CONFIGURATION_ENTRY_ADDRESS_OFFSET..][0..8]);
        return if (address == 0) null else address;
    }
    return null;
}

fn parseSmbios3EntryPoint(bytes: []const u8) Error!EntryPoint {
    if (bytes.len < SMBIOS3_MIN_LENGTH) return error.TooSmall;
    if (!std.mem.eql(u8, bytes[0..SMBIOS3_ANCHOR.len], SMBIOS3_ANCHOR)) return error.BadAnchor;

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

pub fn tableContainsTargetSku(table: []const u8, target: []const u8) bool {
    if (target.len == 0) return false;

    var offset: usize = 0;
    while (offset + STRUCTURE_HEADER_BYTES <= table.len) {
        const structure_type = table[offset + STRUCTURE_TYPE_OFFSET];
        const formatted_length = table[offset + STRUCTURE_FORMATTED_LENGTH_OFFSET];
        if (formatted_length < STRUCTURE_HEADER_BYTES or offset + formatted_length > table.len) return false;

        const end = structureEnd(table, offset + formatted_length) orelse return false;
        const structure = table[offset..end];
        if ((structure_type == SYSTEM_INFORMATION_TYPE or structure_type == BASEBOARD_INFORMATION_TYPE) and
            ascii.containsIgnoreCase(structure, target))
        {
            return true;
        }
        if (structure_type == END_OF_TABLE_TYPE) return false;
        offset = end;
    }
    return false;
}

fn structureEnd(table: []const u8, strings_start: usize) ?usize {
    var index = strings_start;
    while (index + 1 < table.len) : (index += 1) {
        if (table[index] == 0 and table[index + 1] == 0) return index + STRING_SET_TERMINATOR_BYTES;
    }
    return null;
}

test "EFI64 system table exposes bounded configuration entries" {
    var bytes = [_]u8{0} ** EFI_SYSTEM_TABLE_BYTES;
    writeU64Le(bytes[0..8], EFI_SYSTEM_TABLE_SIGNATURE);
    writeU32Le(bytes[EFI_SYSTEM_TABLE_REVISION_OFFSET..][0..4], EFI_SYSTEM_TABLE_MIN_REVISION);
    writeU32Le(bytes[EFI_SYSTEM_TABLE_HEADER_SIZE_OFFSET..][0..4], EFI_SYSTEM_TABLE_BYTES);
    writeU64Le(bytes[EFI_SYSTEM_TABLE_ENTRY_COUNT_OFFSET..][0..8], 12);
    writeU64Le(bytes[EFI_SYSTEM_TABLE_CONFIG_ADDRESS_OFFSET..][0..8], 0x1234_5000);
    writeU32Le(bytes[EFI_SYSTEM_TABLE_CRC32_OFFSET..][0..4], std.hash.Crc32.hash(&bytes));

    const parsed = try parseEfiSystemTable(&bytes);
    try std.testing.expectEqual(@as(usize, 12), parsed.configuration_table_count);
    try std.testing.expectEqual(@as(u64, 0x1234_5000), parsed.configuration_table_address);

    writeU64Le(bytes[EFI_SYSTEM_TABLE_ENTRY_COUNT_OFFSET..][0..8], MAX_CONFIGURATION_ENTRIES + 1);
    writeU32Le(bytes[EFI_SYSTEM_TABLE_CRC32_OFFSET..][0..4], 0);
    writeU32Le(bytes[EFI_SYSTEM_TABLE_CRC32_OFFSET..][0..4], std.hash.Crc32.hash(&bytes));
    try std.testing.expectError(error.InvalidLength, parseEfiSystemTable(&bytes));
    writeU64Le(bytes[EFI_SYSTEM_TABLE_ENTRY_COUNT_OFFSET..][0..8], 12);
    writeU64Le(bytes[0..8], 0);
    try std.testing.expectError(error.BadSignature, parseEfiSystemTable(&bytes));
}

test "SMBIOS 3 entry point validates checksum and table address" {
    var entry = [_]u8{0} ** SMBIOS3_MIN_LENGTH;
    @memcpy(entry[0..SMBIOS3_ANCHOR.len], SMBIOS3_ANCHOR);
    entry[SMBIOS3_LENGTH_OFFSET] = SMBIOS3_MIN_LENGTH;
    entry[SMBIOS3_MAJOR_VERSION_OFFSET] = SMBIOS3_MAJOR_VERSION;
    writeU32Le(entry[SMBIOS3_TABLE_LENGTH_OFFSET..][0..4], 128);
    writeU64Le(entry[SMBIOS3_TABLE_ADDRESS_OFFSET..][0..8], 0x0000_0000_00f1_0000);
    checksum.finishSum8(entry[0..], SMBIOS3_CHECKSUM_OFFSET);

    const parsed = try parseSmbios3EntryPoint(&entry);
    try std.testing.expectEqual(@as(usize, 128), parsed.table_length);
    try std.testing.expectEqual(@as(u64, 0xf1_0000), parsed.table_address);

    entry[SMBIOS3_CHECKSUM_OFFSET] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseSmbios3EntryPoint(&entry));
}

test "EFI configuration table locates only the SMBIOS 3 entry point" {
    var entries = [_]u8{0} ** (EFI_CONFIGURATION_ENTRY_BYTES * 2);
    @memcpy(entries[EFI_CONFIGURATION_ENTRY_BYTES..][0..SMBIOS3_TABLE_GUID.len], &SMBIOS3_TABLE_GUID);
    writeU64Le(entries[EFI_CONFIGURATION_ENTRY_BYTES + EFI_CONFIGURATION_ENTRY_ADDRESS_OFFSET ..][0..8], 0x8000_4000);
    try std.testing.expectEqual(@as(?u64, 0x8000_4000), findSmbios3EntryPointAddress(&entries));

    entries[EFI_CONFIGURATION_ENTRY_BYTES] ^= 0xff;
    try std.testing.expectEqual(@as(?u64, null), findSmbios3EntryPointAddress(&entries));
    try std.testing.expectEqual(@as(?u64, null), findSmbios3EntryPointAddress(entries[0 .. entries.len - 1]));
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

test "SMBIOS parser rejects malformed structure bounds" {
    try std.testing.expect(!tableContainsTargetSku(&[_]u8{ 1, 3, 0, 0, 0, 0 }, NUC11TNKI5_SKU));
    try std.testing.expect(!tableContainsTargetSku(&[_]u8{ 1, 8, 0, 0, 'N', 'U', 'C', '1' }, NUC11TNKI5_SKU));
    try std.testing.expect(!tableContainsTargetSku(&[_]u8{ 127, 4, 0, 0, 0, 0 }, NUC11TNKI5_SKU));
}
