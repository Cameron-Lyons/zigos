const std = @import("std");
const acpi = @import("acpi.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const finishChecksum = checksum.finishSum8Prefix;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const MADT_SIGNATURE = "APIC";
pub const SDT_HEADER_LENGTH: usize = acpi.SDT_HEADER_LENGTH;
pub const MADT_HEADER_LENGTH: usize = 44;
const MADT_TEST_TABLE_BYTES: usize = 88;
const MADT_LOCAL_APIC_ADDRESS_OFFSET = SDT_HEADER_LENGTH;
const MADT_FLAGS_OFFSET = SDT_HEADER_LENGTH + 4;
const MADT_PC_AT_COMPATIBLE_FLAG: u32 = 0x1;
const MADT_ENTRY_HEADER_BYTES: usize = 2;
const MADT_ENTRY_TYPE_OFFSET: usize = 0;
const MADT_ENTRY_LENGTH_OFFSET: usize = 1;
const MADT_LOCAL_APIC_MIN_BYTES: usize = 8;
const MADT_LOCAL_APIC_FLAGS_OFFSET: usize = 4;
const MADT_IO_APIC_MIN_BYTES: usize = 12;
const MADT_ISO_MIN_BYTES: usize = 10;
const MADT_LOCAL_APIC_NMI_MIN_BYTES: usize = 6;
const MADT_LOCAL_APIC_ADDRESS_OVERRIDE_MIN_BYTES: usize = 12;
const MADT_LOCAL_APIC_ADDRESS_OVERRIDE_OFFSET: usize = 4;
const MADT_X2APIC_MIN_BYTES: usize = 16;
const MADT_X2APIC_FLAGS_OFFSET: usize = 12;
const MADT_PROCESSOR_ENABLED_FLAG: u32 = 0x1;

pub const Error = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    InvalidLength,
    InvalidEntryLength,
};

pub const EntryType = enum(u8) {
    processor_local_apic = 0,
    io_apic = 1,
    interrupt_source_override = 2,
    non_maskable_interrupt = 3,
    local_apic_nmi = 4,
    local_apic_address_override = 5,
    processor_local_x2apic = 9,
    unknown = 255,

    pub fn fromByte(value: u8) EntryType {
        return switch (value) {
            0 => .processor_local_apic,
            1 => .io_apic,
            2 => .interrupt_source_override,
            3 => .non_maskable_interrupt,
            4 => .local_apic_nmi,
            5 => .local_apic_address_override,
            9 => .processor_local_x2apic,
            else => .unknown,
        };
    }
};

pub const Summary = struct {
    local_apic_address: u64,
    pc_at_compatible: bool,
    processor_count: u16 = 0,
    enabled_processor_count: u16 = 0,
    io_apic_count: u16 = 0,
    interrupt_source_override_count: u16 = 0,
    local_apic_nmi_count: u16 = 0,
    x2apic_count: u16 = 0,
};

pub fn parseMadt(table: []const u8) Error!Summary {
    if (table.len < MADT_HEADER_LENGTH) return error.TooSmall;
    if (!std.mem.eql(u8, table[0..MADT_SIGNATURE.len], MADT_SIGNATURE)) return error.BadSignature;

    const sdt = try acpi.parseSdtHeader(table);
    const table_length = sdt.length;
    if (table_length < MADT_HEADER_LENGTH or table_length > table.len) return error.InvalidLength;

    var summary = Summary{
        .local_apic_address = readU32Le(table[MADT_LOCAL_APIC_ADDRESS_OFFSET..][0..4]),
        .pc_at_compatible = (readU32Le(table[MADT_FLAGS_OFFSET..][0..4]) & MADT_PC_AT_COMPATIBLE_FLAG) != 0,
    };

    var offset: usize = MADT_HEADER_LENGTH;
    while (offset < table_length) {
        if (offset + MADT_ENTRY_HEADER_BYTES > table_length) return error.InvalidEntryLength;
        const entry_type = EntryType.fromByte(table[offset + MADT_ENTRY_TYPE_OFFSET]);
        const entry_length = table[offset + MADT_ENTRY_LENGTH_OFFSET];
        if (entry_length < MADT_ENTRY_HEADER_BYTES or offset + entry_length > table_length) return error.InvalidEntryLength;

        parseEntry(entry_type, table[offset .. offset + entry_length], &summary);
        offset += entry_length;
    }

    return summary;
}

fn parseEntry(entry_type: EntryType, entry: []const u8, summary: *Summary) void {
    switch (entry_type) {
        .processor_local_apic => {
            if (entry.len < MADT_LOCAL_APIC_MIN_BYTES) return;
            summary.processor_count += 1;
            if ((readU32Le(entry[MADT_LOCAL_APIC_FLAGS_OFFSET..][0..4]) & MADT_PROCESSOR_ENABLED_FLAG) != 0) {
                summary.enabled_processor_count += 1;
            }
        },
        .io_apic => {
            if (entry.len < MADT_IO_APIC_MIN_BYTES) return;
            summary.io_apic_count += 1;
        },
        .interrupt_source_override => {
            if (entry.len < MADT_ISO_MIN_BYTES) return;
            summary.interrupt_source_override_count += 1;
        },
        .local_apic_nmi => {
            if (entry.len < MADT_LOCAL_APIC_NMI_MIN_BYTES) return;
            summary.local_apic_nmi_count += 1;
        },
        .local_apic_address_override => {
            if (entry.len < MADT_LOCAL_APIC_ADDRESS_OVERRIDE_MIN_BYTES) return;
            summary.local_apic_address = readU64Le(entry[MADT_LOCAL_APIC_ADDRESS_OVERRIDE_OFFSET..][0..8]);
        },
        .processor_local_x2apic => {
            if (entry.len < MADT_X2APIC_MIN_BYTES) return;
            summary.x2apic_count += 1;
            if ((readU32Le(entry[MADT_X2APIC_FLAGS_OFFSET..][0..4]) & MADT_PROCESSOR_ENABLED_FLAG) != 0) {
                summary.enabled_processor_count += 1;
            }
        },
        else => {},
    }
}

fn validMadt() [MADT_TEST_TABLE_BYTES]u8 {
    var table = [_]u8{0} ** MADT_TEST_TABLE_BYTES;
    @memcpy(table[0..4], MADT_SIGNATURE);
    writeU32Le(table[4..8], table.len);
    table[8] = 5;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11TN ");
    writeU32Le(table[MADT_LOCAL_APIC_ADDRESS_OFFSET..][0..4], 0xFEE0_0000);
    writeU32Le(table[MADT_FLAGS_OFFSET..][0..4], MADT_PC_AT_COMPATIBLE_FLAG);

    table[44] = @intFromEnum(EntryType.processor_local_apic);
    table[45] = MADT_LOCAL_APIC_MIN_BYTES;
    table[46] = 0;
    table[47] = 1;
    writeU32Le(table[48..52], MADT_PROCESSOR_ENABLED_FLAG);

    table[52] = @intFromEnum(EntryType.io_apic);
    table[53] = MADT_IO_APIC_MIN_BYTES;
    table[54] = 2;
    writeU32Le(table[56..60], 0xFEC0_0000);
    writeU32Le(table[60..64], 0);

    table[64] = @intFromEnum(EntryType.interrupt_source_override);
    table[65] = MADT_ISO_MIN_BYTES;
    table[66] = 0;
    table[67] = 0;
    writeU32Le(table[68..72], 2);
    table[72] = 0x0D;

    table[74] = @intFromEnum(EntryType.local_apic_address_override);
    table[75] = MADT_LOCAL_APIC_ADDRESS_OVERRIDE_MIN_BYTES;
    writeU64Le(table[78..86], 0x0000_0000_FEE0_0000);

    table[86] = @intFromEnum(EntryType.local_apic_nmi);
    table[87] = MADT_ENTRY_HEADER_BYTES;

    finishChecksum(table[0..], 9, table.len);
    return table;
}

test "APIC MADT parser summarizes APIC topology" {
    const table = validMadt();
    const summary = try parseMadt(table[0..]);
    try std.testing.expectEqual(@as(u64, 0xFEE0_0000), summary.local_apic_address);
    try std.testing.expect(summary.pc_at_compatible);
    try std.testing.expectEqual(@as(u16, 1), summary.processor_count);
    try std.testing.expectEqual(@as(u16, 1), summary.enabled_processor_count);
    try std.testing.expectEqual(@as(u16, 1), summary.io_apic_count);
    try std.testing.expectEqual(@as(u16, 1), summary.interrupt_source_override_count);
}

test "APIC MADT parser rejects corrupted checksum" {
    var table = validMadt();
    table[48] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseMadt(table[0..]));
}

test "APIC MADT parser rejects truncated entries" {
    var table = validMadt();
    table[45] = 1;
    finishChecksum(table[0..], 9, table.len);
    try std.testing.expectError(error.InvalidEntryLength, parseMadt(table[0..]));
}
