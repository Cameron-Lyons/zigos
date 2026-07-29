const std = @import("std");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const checksumIsValid = checksum.sum8IsZero;
const finishChecksum = checksum.finishSum8Prefix;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const RSDP_SIGNATURE = "RSD PTR ";
pub const RSDP_BASE_CHECKSUM_LENGTH: usize = 20;
pub const RSDP_V2_MIN_LENGTH: usize = 36;
pub const SDT_HEADER_LENGTH: usize = 36;
pub const XSDT_SIGNATURE = "XSDT";
const SDT_SIGNATURE_OFFSET: usize = 0;
const SDT_SIGNATURE_BYTES: usize = 4;
const SDT_LENGTH_OFFSET: usize = 4;
const SDT_REVISION_OFFSET: usize = 8;
const SDT_CHECKSUM_OFFSET: usize = 9;
const SDT_OEM_ID_OFFSET: usize = 10;
const SDT_OEM_ID_BYTES: usize = 6;
const SDT_OEM_TABLE_ID_OFFSET: usize = 16;
const SDT_OEM_TABLE_ID_BYTES: usize = 8;
const RSDP_CHECKSUM_OFFSET: usize = 8;
const RSDP_OEM_ID_OFFSET: usize = 9;
const RSDP_OEM_ID_BYTES: usize = 6;
const RSDP_REVISION_OFFSET: usize = 15;
const RSDP_LENGTH_OFFSET: usize = 20;
const RSDP_XSDT_ADDRESS_OFFSET: usize = 24;
const RSDP_EXTENDED_CHECKSUM_OFFSET: usize = 32;

pub const SdtError = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    InvalidLength,
};

pub const RsdpError = SdtError || error{
    UnsupportedRevision,
    MissingXsdt,
};

pub const Rsdp = struct {
    revision: u8,
    oem_id: [6]u8,
    xsdt_address: u64,
    length: u32,
};

pub const SdtHeader = struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
};

pub fn sdtLengthFromHeader(header: []const u8) SdtError!u32 {
    if (header.len < SDT_HEADER_LENGTH) return error.TooSmall;
    const length = readU32Le(header[SDT_LENGTH_OFFSET..][0..4]);
    if (length < SDT_HEADER_LENGTH) return error.InvalidLength;
    return length;
}

pub fn parseSdtHeader(table: []const u8) SdtError!SdtHeader {
    const length = try sdtLengthFromHeader(table);
    if (length > table.len) return error.InvalidLength;
    if (!checksumIsValid(table[0..length])) return error.BadChecksum;

    var signature: [4]u8 = undefined;
    var oem_id: [6]u8 = undefined;
    var oem_table_id: [8]u8 = undefined;
    @memcpy(signature[0..], table[SDT_SIGNATURE_OFFSET..][0..SDT_SIGNATURE_BYTES]);
    @memcpy(oem_id[0..], table[SDT_OEM_ID_OFFSET..][0..SDT_OEM_ID_BYTES]);
    @memcpy(oem_table_id[0..], table[SDT_OEM_TABLE_ID_OFFSET..][0..SDT_OEM_TABLE_ID_BYTES]);
    return .{
        .signature = signature,
        .length = length,
        .revision = table[SDT_REVISION_OFFSET],
        .oem_id = oem_id,
        .oem_table_id = oem_table_id,
    };
}

pub fn xsdtEntryCount(xsdt: []const u8) SdtError!u32 {
    const header = try parseSdtHeader(xsdt);
    if (!std.mem.eql(u8, header.signature[0..], XSDT_SIGNATURE)) return error.BadSignature;
    const payload_len = header.length - SDT_HEADER_LENGTH;
    if ((payload_len % @sizeOf(u64)) != 0) return error.InvalidLength;
    return @intCast(payload_len / @sizeOf(u64));
}

pub fn xsdtEntryAddress(xsdt: []const u8, index: u32) SdtError!u64 {
    const count = try xsdtEntryCount(xsdt);
    if (index >= count) return error.InvalidLength;
    const offset = SDT_HEADER_LENGTH + @as(usize, index) * @sizeOf(u64);
    return readU64Le(xsdt[offset .. offset + @sizeOf(u64)]);
}

pub fn signatureMatches(bytes: []const u8) bool {
    return bytes.len >= RSDP_SIGNATURE.len and std.mem.eql(u8, bytes[0..RSDP_SIGNATURE.len], RSDP_SIGNATURE);
}

pub fn parseRsdp(bytes: []const u8) RsdpError!Rsdp {
    if (bytes.len < RSDP_BASE_CHECKSUM_LENGTH) return error.TooSmall;
    if (!signatureMatches(bytes)) return error.BadSignature;
    if (!checksumIsValid(bytes[0..RSDP_BASE_CHECKSUM_LENGTH])) return error.BadChecksum;

    var oem_id: [6]u8 = undefined;
    @memcpy(&oem_id, bytes[RSDP_OEM_ID_OFFSET..][0..RSDP_OEM_ID_BYTES]);

    const revision = bytes[RSDP_REVISION_OFFSET];
    if (revision < 2) return error.UnsupportedRevision;

    if (bytes.len < RSDP_V2_MIN_LENGTH) return error.TooSmall;
    const length = readU32Le(bytes[RSDP_LENGTH_OFFSET..][0..4]);
    if (length < RSDP_V2_MIN_LENGTH or length > bytes.len) return error.InvalidLength;
    if (!checksumIsValid(bytes[0..length])) return error.BadChecksum;
    const xsdt_address = readU64Le(bytes[RSDP_XSDT_ADDRESS_OFFSET..][0..8]);
    if (xsdt_address == 0) return error.MissingXsdt;

    return .{
        .revision = revision,
        .oem_id = oem_id,
        .xsdt_address = xsdt_address,
        .length = length,
    };
}

fn validXsdt() [SDT_HEADER_LENGTH + 16]u8 {
    var table = [_]u8{0} ** (SDT_HEADER_LENGTH + 16);
    @memcpy(table[SDT_SIGNATURE_OFFSET..][0..SDT_SIGNATURE_BYTES], XSDT_SIGNATURE);
    writeU32Le(table[SDT_LENGTH_OFFSET..][0..4], table.len);
    table[SDT_REVISION_OFFSET] = 1;
    @memcpy(table[SDT_OEM_ID_OFFSET..][0..SDT_OEM_ID_BYTES], "ZIGOS ");
    @memcpy(table[SDT_OEM_TABLE_ID_OFFSET..][0..SDT_OEM_TABLE_ID_BYTES], "NUC11TN ");
    writeU64Le(table[SDT_HEADER_LENGTH .. SDT_HEADER_LENGTH + 8], 0x0000_0000_00AB_C000);
    writeU64Le(table[SDT_HEADER_LENGTH + 8 .. SDT_HEADER_LENGTH + 16], 0x0000_0000_00AC_C000);
    finishChecksum(table[0..], SDT_CHECKSUM_OFFSET, table.len);
    return table;
}

fn validRsdpV2() [RSDP_V2_MIN_LENGTH]u8 {
    var rsdp = [_]u8{0} ** RSDP_V2_MIN_LENGTH;
    @memcpy(rsdp[0..8], RSDP_SIGNATURE);
    @memcpy(rsdp[RSDP_OEM_ID_OFFSET..][0..RSDP_OEM_ID_BYTES], "ZIGOS ");
    rsdp[RSDP_REVISION_OFFSET] = 2;
    writeU32Le(rsdp[RSDP_LENGTH_OFFSET..][0..4], RSDP_V2_MIN_LENGTH);
    writeU64Le(rsdp[RSDP_XSDT_ADDRESS_OFFSET..][0..8], 0x1122_3344_5566_7788);
    finishChecksum(rsdp[0..], RSDP_CHECKSUM_OFFSET, RSDP_BASE_CHECKSUM_LENGTH);
    finishChecksum(rsdp[0..], RSDP_EXTENDED_CHECKSUM_OFFSET, RSDP_V2_MIN_LENGTH);
    return rsdp;
}

test "ACPI RSDP parser accepts revision 2 descriptors" {
    const rsdp_bytes = validRsdpV2();
    const rsdp = try parseRsdp(rsdp_bytes[0..]);
    try std.testing.expectEqual(@as(u8, 2), rsdp.revision);
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), rsdp.xsdt_address);
    try std.testing.expectEqual(@as(u32, RSDP_V2_MIN_LENGTH), rsdp.length);
    try std.testing.expectEqualStrings("ZIGOS ", rsdp.oem_id[0..]);
}

test "ACPI RSDP parser rejects corrupted checksums" {
    var rsdp_bytes = validRsdpV2();
    rsdp_bytes[16] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseRsdp(rsdp_bytes[0..]));
}

test "ACPI RSDP parser rejects revision 1 and missing XSDT" {
    var rsdp_bytes = validRsdpV2();
    rsdp_bytes[RSDP_REVISION_OFFSET] = 0;
    finishChecksum(rsdp_bytes[0..], RSDP_CHECKSUM_OFFSET, RSDP_BASE_CHECKSUM_LENGTH);
    try std.testing.expectError(error.UnsupportedRevision, parseRsdp(rsdp_bytes[0..]));

    rsdp_bytes = validRsdpV2();
    writeU64Le(rsdp_bytes[RSDP_XSDT_ADDRESS_OFFSET..][0..8], 0);
    finishChecksum(rsdp_bytes[0..], RSDP_EXTENDED_CHECKSUM_OFFSET, RSDP_V2_MIN_LENGTH);
    try std.testing.expectError(error.MissingXsdt, parseRsdp(rsdp_bytes[0..]));
}

test "ACPI XSDT parser exposes root table entries" {
    const table = validXsdt();
    const header = try parseSdtHeader(table[0..]);
    try std.testing.expectEqualStrings(XSDT_SIGNATURE, header.signature[0..]);
    try std.testing.expectEqual(@as(u32, 2), try xsdtEntryCount(table[0..]));
    try std.testing.expectEqual(@as(u64, 0x00AB_C000), try xsdtEntryAddress(table[0..], 0));
    try std.testing.expectEqual(@as(u64, 0x00AC_C000), try xsdtEntryAddress(table[0..], 1));
}

test "ACPI XSDT parser rejects 32-bit root tables" {
    var table = validXsdt();
    @memcpy(table[SDT_SIGNATURE_OFFSET..][0..SDT_SIGNATURE_BYTES], "RSDT");
    finishChecksum(table[0..], SDT_CHECKSUM_OFFSET, table.len);
    try std.testing.expectError(error.BadSignature, xsdtEntryCount(table[0..]));
}
