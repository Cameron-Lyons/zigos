const std = @import("std");

pub const RSDP_SIGNATURE = "RSD PTR ";
pub const RSDP_V1_LENGTH: usize = 20;
pub const RSDP_V2_MIN_LENGTH: usize = 36;
pub const RSDP_ALIGNMENT: usize = 16;
pub const SDT_HEADER_LENGTH: usize = 36;
pub const RSDT_SIGNATURE = "RSDT";
pub const XSDT_SIGNATURE = "XSDT";

pub const Error = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    InvalidLength,
};

pub const Rsdp = struct {
    revision: u8,
    oem_id: [6]u8,
    rsdt_address: u32,
    xsdt_address: u64,
    length: u32,
};

pub const RsdpLocation = struct {
    physical_address: usize,
    descriptor: Rsdp,
};

pub const SdtHeader = struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
};

pub fn parseSdtHeader(table: []const u8) Error!SdtHeader {
    if (table.len < SDT_HEADER_LENGTH) return error.TooSmall;
    const length = readU32Le(table[4..8]);
    if (length < SDT_HEADER_LENGTH or length > table.len) return error.InvalidLength;
    if (!checksumIsValid(table[0..length])) return error.BadChecksum;

    var signature: [4]u8 = undefined;
    var oem_id: [6]u8 = undefined;
    var oem_table_id: [8]u8 = undefined;
    @memcpy(signature[0..], table[0..4]);
    @memcpy(oem_id[0..], table[10..16]);
    @memcpy(oem_table_id[0..], table[16..24]);
    return .{
        .signature = signature,
        .length = length,
        .revision = table[8],
        .oem_id = oem_id,
        .oem_table_id = oem_table_id,
    };
}

pub fn rootTableEntryCount(root_table: []const u8) Error!u32 {
    const header = try parseSdtHeader(root_table);
    const entry_size = try rootEntrySize(header.signature[0..]);
    const payload_len = header.length - SDT_HEADER_LENGTH;
    if ((payload_len % entry_size) != 0) return error.InvalidLength;
    return @intCast(payload_len / entry_size);
}

pub fn rootTableEntryAddress(root_table: []const u8, index: u32) Error!u64 {
    const header = try parseSdtHeader(root_table);
    const entry_size = try rootEntrySize(header.signature[0..]);
    const count = try rootTableEntryCount(root_table);
    if (index >= count) return error.InvalidLength;
    const offset = SDT_HEADER_LENGTH + @as(usize, index) * entry_size;
    return if (entry_size == @sizeOf(u64))
        readU64Le(root_table[offset .. offset + 8])
    else
        readU32Le(root_table[offset .. offset + 4]);
}

pub fn signatureMatches(bytes: []const u8) bool {
    return bytes.len >= RSDP_SIGNATURE.len and std.mem.eql(u8, bytes[0..RSDP_SIGNATURE.len], RSDP_SIGNATURE);
}

pub fn parseRsdp(bytes: []const u8) Error!Rsdp {
    if (bytes.len < RSDP_V1_LENGTH) return error.TooSmall;
    if (!signatureMatches(bytes)) return error.BadSignature;
    if (!checksumIsValid(bytes[0..RSDP_V1_LENGTH])) return error.BadChecksum;

    var oem_id: [6]u8 = undefined;
    @memcpy(&oem_id, bytes[9..15]);

    const revision = bytes[15];
    const rsdt_address = readU32Le(bytes[16..20]);
    if (revision < 2) {
        return .{
            .revision = revision,
            .oem_id = oem_id,
            .rsdt_address = rsdt_address,
            .xsdt_address = 0,
            .length = RSDP_V1_LENGTH,
        };
    }

    if (bytes.len < RSDP_V2_MIN_LENGTH) return error.TooSmall;
    const length = readU32Le(bytes[20..24]);
    if (length < RSDP_V2_MIN_LENGTH or length > bytes.len) return error.InvalidLength;
    if (!checksumIsValid(bytes[0..length])) return error.BadChecksum;

    return .{
        .revision = revision,
        .oem_id = oem_id,
        .rsdt_address = rsdt_address,
        .xsdt_address = readU64Le(bytes[24..32]),
        .length = length,
    };
}

pub fn findRsdp(buffer: []const u8, base_physical_address: usize) ?RsdpLocation {
    var offset: usize = alignedOffset(base_physical_address);
    while (offset + RSDP_V1_LENGTH <= buffer.len) : (offset += RSDP_ALIGNMENT) {
        const descriptor = parseRsdp(buffer[offset..]) catch continue;
        return .{
            .physical_address = base_physical_address + offset,
            .descriptor = descriptor,
        };
    }
    return null;
}

fn alignedOffset(base_physical_address: usize) usize {
    const remainder = base_physical_address % RSDP_ALIGNMENT;
    return if (remainder == 0) 0 else RSDP_ALIGNMENT - remainder;
}

fn checksumIsValid(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum == 0;
}

fn rootEntrySize(signature: []const u8) Error!usize {
    if (std.mem.eql(u8, signature, XSDT_SIGNATURE)) return @sizeOf(u64);
    if (std.mem.eql(u8, signature, RSDT_SIGNATURE)) return @sizeOf(u32);
    return error.BadSignature;
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

fn validXsdt() [SDT_HEADER_LENGTH + 16]u8 {
    var table = [_]u8{0} ** (SDT_HEADER_LENGTH + 16);
    @memcpy(table[0..4], XSDT_SIGNATURE);
    writeU32Le(table[4..8], table.len);
    table[8] = 1;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11TN ");
    writeU64Le(table[SDT_HEADER_LENGTH .. SDT_HEADER_LENGTH + 8], 0x0000_0000_00AB_C000);
    writeU64Le(table[SDT_HEADER_LENGTH + 8 .. SDT_HEADER_LENGTH + 16], 0x0000_0000_00AC_C000);
    finishChecksum(table[0..], 9, table.len);
    return table;
}

fn validRsdpV2() [RSDP_V2_MIN_LENGTH]u8 {
    var rsdp = [_]u8{0} ** RSDP_V2_MIN_LENGTH;
    @memcpy(rsdp[0..8], RSDP_SIGNATURE);
    @memcpy(rsdp[9..15], "ZIGOS ");
    rsdp[15] = 2;
    rsdp[16] = 0x34;
    rsdp[17] = 0x12;
    rsdp[20] = RSDP_V2_MIN_LENGTH;
    rsdp[24] = 0x88;
    rsdp[25] = 0x77;
    rsdp[26] = 0x66;
    rsdp[27] = 0x55;
    rsdp[28] = 0x44;
    rsdp[29] = 0x33;
    rsdp[30] = 0x22;
    rsdp[31] = 0x11;
    finishChecksum(rsdp[0..], 8, RSDP_V1_LENGTH);
    finishChecksum(rsdp[0..], 32, RSDP_V2_MIN_LENGTH);
    return rsdp;
}

test "ACPI RSDP parser accepts revision 2 descriptors" {
    const rsdp_bytes = validRsdpV2();
    const rsdp = try parseRsdp(rsdp_bytes[0..]);
    try std.testing.expectEqual(@as(u8, 2), rsdp.revision);
    try std.testing.expectEqual(@as(u32, 0x1234), rsdp.rsdt_address);
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), rsdp.xsdt_address);
    try std.testing.expectEqual(@as(u32, RSDP_V2_MIN_LENGTH), rsdp.length);
    try std.testing.expectEqualStrings("ZIGOS ", rsdp.oem_id[0..]);
}

test "ACPI RSDP parser rejects corrupted checksums" {
    var rsdp_bytes = validRsdpV2();
    rsdp_bytes[16] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseRsdp(rsdp_bytes[0..]));
}

test "ACPI RSDP scanner finds aligned descriptors" {
    const rsdp_bytes = validRsdpV2();
    var memory = [_]u8{0} ** 128;
    @memcpy(memory[32 .. 32 + rsdp_bytes.len], rsdp_bytes[0..]);
    const found = findRsdp(memory[0..], 0xE0000) orelse return error.MissingRsdp;
    try std.testing.expectEqual(@as(usize, 0xE0020), found.physical_address);
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), found.descriptor.xsdt_address);
}

test "ACPI RSDP scanner aligns by physical address" {
    const rsdp_bytes = validRsdpV2();
    var memory = [_]u8{0} ** 128;
    @memcpy(memory[15 .. 15 + rsdp_bytes.len], rsdp_bytes[0..]);
    const found = findRsdp(memory[0..], 0xE0001) orelse return error.MissingRsdp;
    try std.testing.expectEqual(@as(usize, 0xE0010), found.physical_address);
}

test "ACPI XSDT parser exposes root table entries" {
    const table = validXsdt();
    const header = try parseSdtHeader(table[0..]);
    try std.testing.expectEqualStrings(XSDT_SIGNATURE, header.signature[0..]);
    try std.testing.expectEqual(@as(u32, 2), try rootTableEntryCount(table[0..]));
    try std.testing.expectEqual(@as(u64, 0x00AB_C000), try rootTableEntryAddress(table[0..], 0));
    try std.testing.expectEqual(@as(u64, 0x00AC_C000), try rootTableEntryAddress(table[0..], 1));
}
