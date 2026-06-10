const std = @import("std");

const SMBIOS2_ANCHOR = "_SM_";
const SMBIOS3_ANCHOR = "_SM3_";
const BIOS_SCAN_BASE: usize = 0xF0000;
const BIOS_SCAN_LENGTH: usize = 0x10000;
const ENTRY_ALIGNMENT: usize = 16;
const SMBIOS2_MIN_LENGTH: usize = 0x1F;
const SMBIOS3_MIN_LENGTH: usize = 0x18;
const MAX_TABLE_BYTES: usize = 1024 * 1024;

pub const NUC11TNKI5_SKU = "NUC11TNKi5";

pub const Error = error{
    TooSmall,
    BadAnchor,
    BadChecksum,
    InvalidLength,
    InvalidTable,
};

pub const EntryPoint = struct {
    major_version: u8,
    minor_version: u8,
    table_address: u64,
    table_length: usize,
    structure_count: u16,
};

pub const EntryLocation = struct {
    physical_address: usize,
    entry: EntryPoint,
};

pub fn scanBiosForEntryPoint() ?EntryLocation {
    const bytes = @as([*]const u8, @ptrFromInt(BIOS_SCAN_BASE))[0..BIOS_SCAN_LENGTH];
    return findEntryPoint(bytes, BIOS_SCAN_BASE);
}

pub fn scanBiosForNuc11Tnki5() bool {
    const location = scanBiosForEntryPoint() orelse return false;
    if (location.entry.table_length == 0 or location.entry.table_length > MAX_TABLE_BYTES) return false;
    const max_address: u64 = std.math.maxInt(usize);
    if (location.entry.table_address > max_address - @as(u64, @intCast(location.entry.table_length))) return false;
    const table = @as([*]const u8, @ptrFromInt(@as(usize, @intCast(location.entry.table_address))))[0..location.entry.table_length];
    return tableContainsTargetSku(table, location.entry.structure_count, NUC11TNKI5_SKU);
}

pub fn findEntryPoint(buffer: []const u8, base_physical_address: usize) ?EntryLocation {
    var offset: usize = alignedOffset(base_physical_address);
    while (offset + SMBIOS3_MIN_LENGTH <= buffer.len) : (offset += ENTRY_ALIGNMENT) {
        if (parseEntryPoint(buffer[offset..])) |entry| {
            return .{
                .physical_address = base_physical_address + offset,
                .entry = entry,
            };
        } else |_| {}
    }
    return null;
}

pub fn parseEntryPoint(bytes: []const u8) Error!EntryPoint {
    if (bytes.len >= SMBIOS3_MIN_LENGTH and std.mem.eql(u8, bytes[0..SMBIOS3_ANCHOR.len], SMBIOS3_ANCHOR)) {
        return parseSmbios3EntryPoint(bytes);
    }
    if (bytes.len >= SMBIOS2_MIN_LENGTH and std.mem.eql(u8, bytes[0..SMBIOS2_ANCHOR.len], SMBIOS2_ANCHOR)) {
        return parseSmbios2EntryPoint(bytes);
    }
    return error.BadAnchor;
}

pub fn tableContainsTargetSku(table: []const u8, structure_count: u16, target: []const u8) bool {
    if (target.len == 0) return false;

    var offset: usize = 0;
    var seen: u16 = 0;
    while (offset + 4 <= table.len and (structure_count == 0 or seen < structure_count)) : (seen += 1) {
        const structure_type = table[offset];
        const formatted_length = table[offset + 1];
        if (formatted_length < 4 or offset + formatted_length > table.len) return false;

        const end = structureEnd(table, offset + formatted_length) orelse return false;
        const structure = table[offset..end];
        if ((structure_type == 1 or structure_type == 2) and containsAsciiIgnoreCase(structure, target)) {
            return true;
        }
        if (structure_type == 127) return false;
        offset = end;
    }
    return false;
}

fn parseSmbios2EntryPoint(bytes: []const u8) Error!EntryPoint {
    const length = bytes[5];
    if (length < SMBIOS2_MIN_LENGTH or length > bytes.len) return error.InvalidLength;
    if (!checksumIsValid(bytes[0..length])) return error.BadChecksum;
    if (!std.mem.eql(u8, bytes[0x10..0x15], "_DMI_")) return error.BadAnchor;
    if (!checksumIsValid(bytes[0x10 .. 0x10 + 0x0F])) return error.BadChecksum;

    const table_length = readU16Le(bytes[0x16..0x18]);
    const table_address = readU32Le(bytes[0x18..0x1C]);
    if (table_length == 0 or table_length > MAX_TABLE_BYTES or table_address == 0) return error.InvalidLength;

    return .{
        .major_version = bytes[6],
        .minor_version = bytes[7],
        .table_address = table_address,
        .table_length = table_length,
        .structure_count = readU16Le(bytes[0x1C..0x1E]),
    };
}

fn parseSmbios3EntryPoint(bytes: []const u8) Error!EntryPoint {
    const length = bytes[6];
    if (length < SMBIOS3_MIN_LENGTH or length > bytes.len) return error.InvalidLength;
    if (!checksumIsValid(bytes[0..length])) return error.BadChecksum;

    const table_length = readU32Le(bytes[0x0C..0x10]);
    const table_address = readU64Le(bytes[0x10..0x18]);
    if (table_length == 0 or table_length > MAX_TABLE_BYTES or table_address == 0) return error.InvalidLength;

    return .{
        .major_version = bytes[7],
        .minor_version = bytes[8],
        .table_address = table_address,
        .table_length = table_length,
        .structure_count = 0,
    };
}

fn structureEnd(table: []const u8, strings_start: usize) ?usize {
    var index = strings_start;
    while (index + 1 < table.len) : (index += 1) {
        if (table[index] == 0 and table[index + 1] == 0) return index + 2;
    }
    return null;
}

fn alignedOffset(base_physical_address: usize) usize {
    const remainder = base_physical_address % ENTRY_ALIGNMENT;
    return if (remainder == 0) 0 else ENTRY_ALIGNMENT - remainder;
}

fn checksumIsValid(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum == 0;
}

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var offset: usize = 0;
    while (offset + needle.len <= haystack.len) : (offset += 1) {
        var matched = true;
        for (needle, 0..) |needle_byte, index| {
            if (std.ascii.toLower(haystack[offset + index]) != std.ascii.toLower(needle_byte)) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
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

fn finishChecksum(bytes: []u8, checksum_index: usize) void {
    bytes[checksum_index] = 0;
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    bytes[checksum_index] = 0 -% sum;
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
    try std.testing.expect(tableContainsTargetSku(table[0..], 2, NUC11TNKI5_SKU));
    try std.testing.expect(!tableContainsTargetSku(table[0..], 2, "NUC12"));
}

test "SMBIOS 3 entry point validates checksum and table address" {
    var entry = [_]u8{0} ** SMBIOS3_MIN_LENGTH;
    @memcpy(entry[0..5], SMBIOS3_ANCHOR);
    entry[6] = SMBIOS3_MIN_LENGTH;
    entry[7] = 3;
    entry[8] = 4;
    writeU32Le(entry[0x0C..0x10], 128);
    writeU64Le(entry[0x10..0x18], 0x0000_0000_00F1_0000);
    finishChecksum(entry[0..], 5);

    const parsed = try parseEntryPoint(entry[0..]);
    try std.testing.expectEqual(@as(u8, 3), parsed.major_version);
    try std.testing.expectEqual(@as(usize, 128), parsed.table_length);
    try std.testing.expectEqual(@as(u64, 0xF1_0000), parsed.table_address);
}
