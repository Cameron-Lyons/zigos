const std = @import("std");

pub const MADT_SIGNATURE = "APIC";
pub const SDT_HEADER_LENGTH: usize = 36;
pub const MADT_HEADER_LENGTH: usize = 44;

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

    const table_length = readU32Le(table[4..8]);
    if (table_length < MADT_HEADER_LENGTH or table_length > table.len) return error.InvalidLength;
    if (!checksumIsValid(table[0..table_length])) return error.BadChecksum;

    var summary = Summary{
        .local_apic_address = readU32Le(table[SDT_HEADER_LENGTH .. SDT_HEADER_LENGTH + 4]),
        .pc_at_compatible = (readU32Le(table[SDT_HEADER_LENGTH + 4 .. SDT_HEADER_LENGTH + 8]) & 0x1) != 0,
    };

    var offset: usize = MADT_HEADER_LENGTH;
    while (offset < table_length) {
        if (offset + 2 > table_length) return error.InvalidEntryLength;
        const entry_type = EntryType.fromByte(table[offset]);
        const entry_length = table[offset + 1];
        if (entry_length < 2 or offset + entry_length > table_length) return error.InvalidEntryLength;

        parseEntry(entry_type, table[offset .. offset + entry_length], &summary);
        offset += entry_length;
    }

    return summary;
}

fn parseEntry(entry_type: EntryType, entry: []const u8, summary: *Summary) void {
    switch (entry_type) {
        .processor_local_apic => {
            if (entry.len < 8) return;
            summary.processor_count += 1;
            if ((readU32Le(entry[4..8]) & 0x1) != 0) {
                summary.enabled_processor_count += 1;
            }
        },
        .io_apic => {
            if (entry.len < 12) return;
            summary.io_apic_count += 1;
        },
        .interrupt_source_override => {
            if (entry.len < 10) return;
            summary.interrupt_source_override_count += 1;
        },
        .local_apic_nmi => {
            if (entry.len < 6) return;
            summary.local_apic_nmi_count += 1;
        },
        .local_apic_address_override => {
            if (entry.len < 12) return;
            summary.local_apic_address = readU64Le(entry[4..12]);
        },
        .processor_local_x2apic => {
            if (entry.len < 16) return;
            summary.x2apic_count += 1;
            if ((readU32Le(entry[12..16]) & 0x1) != 0) {
                summary.enabled_processor_count += 1;
            }
        },
        else => {},
    }
}

fn checksumIsValid(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum == 0;
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

fn validMadt() [88]u8 {
    var table = [_]u8{0} ** 88;
    @memcpy(table[0..4], MADT_SIGNATURE);
    writeU32Le(table[4..8], table.len);
    table[8] = 5;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11TN ");
    writeU32Le(table[SDT_HEADER_LENGTH .. SDT_HEADER_LENGTH + 4], 0xFEE0_0000);
    writeU32Le(table[SDT_HEADER_LENGTH + 4 .. SDT_HEADER_LENGTH + 8], 1);

    table[44] = @intFromEnum(EntryType.processor_local_apic);
    table[45] = 8;
    table[46] = 0;
    table[47] = 1;
    writeU32Le(table[48..52], 1);

    table[52] = @intFromEnum(EntryType.io_apic);
    table[53] = 12;
    table[54] = 2;
    writeU32Le(table[56..60], 0xFEC0_0000);
    writeU32Le(table[60..64], 0);

    table[64] = @intFromEnum(EntryType.interrupt_source_override);
    table[65] = 10;
    table[66] = 0;
    table[67] = 0;
    writeU32Le(table[68..72], 2);
    table[72] = 0x0D;

    table[74] = @intFromEnum(EntryType.local_apic_address_override);
    table[75] = 12;
    writeU64Le(table[78..86], 0x0000_0000_FEE0_0000);

    table[86] = @intFromEnum(EntryType.local_apic_nmi);
    table[87] = 2;

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
