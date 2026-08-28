const std = @import("std");
const endian = @import("../utils/endian.zig");

const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;

const TAG_END: u32 = 0;
const TAG_COMMAND_LINE: u32 = 1;
const TAG_BASIC_MEMORY: u32 = 4;
const TAG_MEMORY_MAP: u32 = 6;
const TAG_FRAMEBUFFER: u32 = 8;
const TAG_EFI64_SYSTEM_TABLE: u32 = 12;
const TAG_ACPI_NEW: u32 = 15;
const TAG_HEADER_BYTES: usize = 8;
const INFO_HEADER_BYTES: usize = 8;
const MEMORY_MAP_HEADER_BYTES: usize = 16;
const MEMORY_MAP_ENTRY_MIN_BYTES: usize = 24;
const FRAMEBUFFER_COMMON_BYTES: usize = 32;
const FRAMEBUFFER_RGB_BYTES: usize = 6;
const EFI64_SYSTEM_TABLE_TAG_BYTES: usize = 16;
const ACPI_RSDP_V2_MIN_BYTES: usize = 36;
const TAG_ALIGNMENT: usize = 8;

pub const Error = error{
    TooSmall,
    InvalidTotalSize,
    InvalidTag,
    DuplicateTag,
    MissingEndTag,
    InvalidCommandLine,
    InvalidMemoryMap,
    InvalidFramebuffer,
    PhysicalRangeOverflow,
};

pub const ParsedInfo = struct {
    total_size: u32,
    has_basic_memory: bool = false,
    has_command_line: bool = false,
    has_memory_map: bool = false,
    has_framebuffer: bool = false,
    has_efi64_system_table: bool = false,
    has_acpi2_rsdp: bool = false,
    mem_lower_kib: u32 = 0,
    mem_upper_kib: u32 = 0,
    cmdline_addr: u32 = 0,
    cmdline_length: u32 = 0,
    mmap_addr: u32 = 0,
    mmap_length: u32 = 0,
    mmap_entry_size: u32 = 0,
    framebuffer_addr: u64 = 0,
    framebuffer_pitch: u32 = 0,
    framebuffer_width: u32 = 0,
    framebuffer_height: u32 = 0,
    framebuffer_bpp: u8 = 0,
    framebuffer_type: u8 = 0,
    framebuffer_rgb: [FRAMEBUFFER_RGB_BYTES]u8 = [_]u8{0} ** FRAMEBUFFER_RGB_BYTES,
    efi64_system_table_addr: u64 = 0,
    acpi2_rsdp_addr: u32 = 0,
    acpi2_rsdp_length: u32 = 0,
};

pub fn declaredTotalSize(header: []const u8) Error!u32 {
    if (header.len < INFO_HEADER_BYTES) return error.TooSmall;
    const total_size = readU32Le(header[0..4]);
    if (total_size < INFO_HEADER_BYTES + TAG_HEADER_BYTES or total_size % TAG_ALIGNMENT != 0) {
        return error.InvalidTotalSize;
    }
    return total_size;
}

pub fn parse(bytes: []const u8, physical_base: u32) Error!ParsedInfo {
    const total_size = try declaredTotalSize(bytes);
    const total_len = std.math.cast(usize, total_size) orelse return error.InvalidTotalSize;
    if (bytes.len < total_len) return error.TooSmall;
    if (readU32Le(bytes[4..8]) != 0) return error.InvalidTotalSize;

    var parsed = ParsedInfo{ .total_size = total_size };
    var seen_command_line = false;
    var seen_basic_memory = false;
    var seen_memory_map = false;
    var seen_framebuffer = false;
    var seen_efi64_system_table = false;
    var seen_acpi_new = false;
    var saw_end = false;
    var offset: usize = INFO_HEADER_BYTES;

    while (offset < total_len) {
        const header_end = std.math.add(usize, offset, TAG_HEADER_BYTES) catch return error.InvalidTag;
        if (header_end > total_len) return error.InvalidTag;
        const tag_type = readU32Le(bytes[offset .. offset + 4]);
        const tag_size_u32 = readU32Le(bytes[offset + 4 .. header_end]);
        const tag_size = std.math.cast(usize, tag_size_u32) orelse return error.InvalidTag;
        if (tag_size < TAG_HEADER_BYTES) return error.InvalidTag;
        const tag_end = std.math.add(usize, offset, tag_size) catch return error.InvalidTag;
        if (tag_end > total_len) return error.InvalidTag;

        if (tag_type == TAG_END) {
            if (tag_size != TAG_HEADER_BYTES) return error.InvalidTag;
            if (alignTag(tag_end) != total_len) return error.InvalidTotalSize;
            saw_end = true;
            break;
        }

        switch (tag_type) {
            TAG_COMMAND_LINE => {
                if (seen_command_line) return error.DuplicateTag;
                seen_command_line = true;
                parsed.has_command_line = true;
                const payload = bytes[header_end..tag_end];
                const terminator = std.mem.indexOfScalar(u8, payload, 0) orelse
                    return error.InvalidCommandLine;
                const length = terminator + 1;
                parsed.cmdline_addr = try physicalAddress(physical_base, header_end);
                parsed.cmdline_length = std.math.cast(u32, length) orelse
                    return error.InvalidCommandLine;
            },
            TAG_BASIC_MEMORY => {
                if (seen_basic_memory) return error.DuplicateTag;
                seen_basic_memory = true;
                parsed.has_basic_memory = true;
                if (tag_size != 16) return error.InvalidTag;
                parsed.mem_lower_kib = readU32Le(bytes[header_end .. header_end + 4]);
                parsed.mem_upper_kib = readU32Le(bytes[header_end + 4 .. header_end + 8]);
            },
            TAG_MEMORY_MAP => {
                if (seen_memory_map) return error.DuplicateTag;
                seen_memory_map = true;
                parsed.has_memory_map = true;
                if (tag_size < MEMORY_MAP_HEADER_BYTES) return error.InvalidMemoryMap;
                const entry_size = readU32Le(bytes[header_end .. header_end + 4]);
                const entry_version = readU32Le(bytes[header_end + 4 .. header_end + 8]);
                if (entry_size < MEMORY_MAP_ENTRY_MIN_BYTES or entry_version != 0) {
                    return error.InvalidMemoryMap;
                }
                const entry_stride = std.math.cast(usize, entry_size) orelse
                    return error.InvalidMemoryMap;
                const entries_length = tag_size - MEMORY_MAP_HEADER_BYTES;
                if (entries_length == 0 or entries_length % entry_stride != 0) {
                    return error.InvalidMemoryMap;
                }
                parsed.mmap_addr = try physicalAddress(physical_base, offset + MEMORY_MAP_HEADER_BYTES);
                parsed.mmap_length = std.math.cast(u32, entries_length) orelse
                    return error.InvalidMemoryMap;
                parsed.mmap_entry_size = entry_size;
            },
            TAG_FRAMEBUFFER => {
                if (seen_framebuffer) return error.DuplicateTag;
                seen_framebuffer = true;
                parsed.has_framebuffer = true;
                if (tag_size < FRAMEBUFFER_COMMON_BYTES) return error.InvalidFramebuffer;
                parsed.framebuffer_addr = readU64Le(bytes[header_end .. header_end + 8]);
                parsed.framebuffer_pitch = readU32Le(bytes[header_end + 8 .. header_end + 12]);
                parsed.framebuffer_width = readU32Le(bytes[header_end + 12 .. header_end + 16]);
                parsed.framebuffer_height = readU32Le(bytes[header_end + 16 .. header_end + 20]);
                parsed.framebuffer_bpp = bytes[header_end + 20];
                parsed.framebuffer_type = bytes[header_end + 21];
                if (parsed.framebuffer_type == 1) {
                    if (tag_size < FRAMEBUFFER_COMMON_BYTES + FRAMEBUFFER_RGB_BYTES) {
                        return error.InvalidFramebuffer;
                    }
                    @memcpy(parsed.framebuffer_rgb[0..], bytes[offset + FRAMEBUFFER_COMMON_BYTES ..][0..FRAMEBUFFER_RGB_BYTES]);
                }
            },
            TAG_EFI64_SYSTEM_TABLE => {
                if (seen_efi64_system_table) return error.DuplicateTag;
                seen_efi64_system_table = true;
                if (tag_size != EFI64_SYSTEM_TABLE_TAG_BYTES) return error.InvalidTag;
                parsed.has_efi64_system_table = true;
                parsed.efi64_system_table_addr = readU64Le(bytes[header_end..tag_end]);
                if (parsed.efi64_system_table_addr == 0) return error.InvalidTag;
            },
            TAG_ACPI_NEW => {
                if (seen_acpi_new) return error.DuplicateTag;
                seen_acpi_new = true;
                const payload_length = tag_size - TAG_HEADER_BYTES;
                if (payload_length < ACPI_RSDP_V2_MIN_BYTES) return error.InvalidTag;
                parsed.has_acpi2_rsdp = true;
                parsed.acpi2_rsdp_addr = try physicalAddress(physical_base, header_end);
                parsed.acpi2_rsdp_length = std.math.cast(u32, payload_length) orelse return error.InvalidTag;
            },
            else => {},
        }

        offset = alignTag(tag_end);
        if (offset > total_len) return error.InvalidTag;
    }

    if (!saw_end) return error.MissingEndTag;
    return parsed;
}

fn alignTag(value: usize) usize {
    return std.mem.alignForward(usize, value, TAG_ALIGNMENT);
}

fn physicalAddress(base: u32, offset: usize) Error!u32 {
    const address = std.math.add(u64, base, std.math.cast(u64, offset) orelse
        return error.PhysicalRangeOverflow) catch return error.PhysicalRangeOverflow;
    return std.math.cast(u32, address) orelse return error.PhysicalRangeOverflow;
}

fn writeU32(bytes: []u8, value: u32) void {
    endian.writeU32Le(bytes, value);
}

fn writeU64(bytes: []u8, value: u64) void {
    endian.writeU64Le(bytes, value);
}

test "Multiboot2 parser normalizes memory map command line and framebuffer tags" {
    var bytes = [_]u8{0} ** 112;
    writeU32(bytes[0..4], bytes.len);

    var offset: usize = INFO_HEADER_BYTES;
    writeU32(bytes[offset .. offset + 4], TAG_COMMAND_LINE);
    writeU32(bytes[offset + 4 .. offset + 8], 14);
    @memcpy(bytes[offset + 8 .. offset + 14], "model\x00");
    offset = alignTag(offset + 14);

    writeU32(bytes[offset .. offset + 4], TAG_MEMORY_MAP);
    writeU32(bytes[offset + 4 .. offset + 8], 40);
    writeU32(bytes[offset + 8 .. offset + 12], 24);
    writeU64(bytes[offset + 16 .. offset + 24], 0x10_0000);
    writeU64(bytes[offset + 24 .. offset + 32], 0x20_0000);
    writeU32(bytes[offset + 32 .. offset + 36], 1);
    offset += 40;

    writeU32(bytes[offset .. offset + 4], TAG_FRAMEBUFFER);
    writeU32(bytes[offset + 4 .. offset + 8], 38);
    writeU64(bytes[offset + 8 .. offset + 16], 0x8000_0000);
    writeU32(bytes[offset + 16 .. offset + 20], 1024 * 4);
    writeU32(bytes[offset + 20 .. offset + 24], 1024);
    writeU32(bytes[offset + 24 .. offset + 28], 768);
    bytes[offset + 28] = 32;
    bytes[offset + 29] = 1;
    @memcpy(bytes[offset + 32 .. offset + 38], &[_]u8{ 16, 8, 8, 8, 0, 8 });
    offset = alignTag(offset + 38);

    writeU32(bytes[offset .. offset + 4], TAG_END);
    writeU32(bytes[offset + 4 .. offset + 8], 8);
    try std.testing.expectEqual(bytes.len, offset + 8);

    const parsed = try parse(&bytes, 0x2000);
    try std.testing.expectEqual(@as(u32, 24), parsed.mmap_entry_size);
    try std.testing.expectEqual(@as(u32, 24), parsed.mmap_length);
    try std.testing.expectEqual(@as(u32, 6), parsed.cmdline_length);
    try std.testing.expectEqual(@as(u64, 0x8000_0000), parsed.framebuffer_addr);
    try std.testing.expectEqual(@as(u32, 1024), parsed.framebuffer_width);
    try std.testing.expectEqual(@as(u8, 1), parsed.framebuffer_type);
}

test "Multiboot2 parser rejects malformed tag extents and map strides" {
    var bytes = [_]u8{0} ** 32;
    writeU32(bytes[0..4], bytes.len);
    writeU32(bytes[8..12], TAG_MEMORY_MAP);
    writeU32(bytes[12..16], 24);
    writeU32(bytes[16..20], 16);
    writeU32(bytes[24..28], TAG_END);
    writeU32(bytes[28..32], 8);
    try std.testing.expectError(error.InvalidMemoryMap, parse(&bytes, 0x1000));

    writeU32(bytes[12..16], 40);
    try std.testing.expectError(error.InvalidTag, parse(&bytes, 0x1000));
}

test "Multiboot2 parser captures only the ACPI 2 RSDP handoff" {
    var bytes = [_]u8{0} ** 64;
    writeU32(bytes[0..4], bytes.len);

    var offset: usize = INFO_HEADER_BYTES;
    writeU32(bytes[offset .. offset + 4], TAG_ACPI_NEW);
    writeU32(bytes[offset + 4 .. offset + 8], TAG_HEADER_BYTES + ACPI_RSDP_V2_MIN_BYTES);
    @memcpy(bytes[offset + TAG_HEADER_BYTES ..][0..8], "RSD PTR ");
    const expected_address = 0x4000 + offset + TAG_HEADER_BYTES;
    offset = alignTag(offset + TAG_HEADER_BYTES + ACPI_RSDP_V2_MIN_BYTES);

    writeU32(bytes[offset .. offset + 4], TAG_END);
    writeU32(bytes[offset + 4 .. offset + 8], TAG_HEADER_BYTES);
    try std.testing.expectEqual(bytes.len, offset + TAG_HEADER_BYTES);

    const parsed = try parse(&bytes, 0x4000);
    try std.testing.expect(parsed.has_acpi2_rsdp);
    try std.testing.expectEqual(@as(u32, @intCast(expected_address)), parsed.acpi2_rsdp_addr);
    try std.testing.expectEqual(@as(u32, ACPI_RSDP_V2_MIN_BYTES), parsed.acpi2_rsdp_length);
}

test "Multiboot2 parser captures the EFI64 system table pointer" {
    var bytes = [_]u8{0} ** 32;
    writeU32(bytes[0..4], bytes.len);

    const offset: usize = INFO_HEADER_BYTES;
    writeU32(bytes[offset .. offset + 4], TAG_EFI64_SYSTEM_TABLE);
    writeU32(bytes[offset + 4 .. offset + 8], EFI64_SYSTEM_TABLE_TAG_BYTES);
    writeU64(bytes[offset + TAG_HEADER_BYTES .. offset + EFI64_SYSTEM_TABLE_TAG_BYTES], 0x1234_5678_9abc_def0);

    const end_offset = offset + EFI64_SYSTEM_TABLE_TAG_BYTES;
    writeU32(bytes[end_offset .. end_offset + 4], TAG_END);
    writeU32(bytes[end_offset + 4 .. end_offset + 8], TAG_HEADER_BYTES);
    try std.testing.expectEqual(bytes.len, end_offset + TAG_HEADER_BYTES);

    const parsed = try parse(&bytes, 0x6000);
    try std.testing.expect(parsed.has_efi64_system_table);
    try std.testing.expectEqual(@as(u64, 0x1234_5678_9abc_def0), parsed.efi64_system_table_addr);

    writeU32(bytes[offset + 4 .. offset + 8], EFI64_SYSTEM_TABLE_TAG_BYTES - 1);
    try std.testing.expectError(error.InvalidTag, parse(&bytes, 0x6000));
}

test "Multiboot2 parser does not accept an obsolete ACPI descriptor as ACPI 2" {
    var bytes = [_]u8{0} ** 48;
    writeU32(bytes[0..4], bytes.len);
    writeU32(bytes[8..12], 14);
    writeU32(bytes[12..16], TAG_HEADER_BYTES + 20);
    @memcpy(bytes[16..24], "RSD PTR ");
    writeU32(bytes[40..44], TAG_END);
    writeU32(bytes[44..48], TAG_HEADER_BYTES);

    const parsed = try parse(&bytes, 0x5000);
    try std.testing.expect(!parsed.has_acpi2_rsdp);

    writeU32(bytes[8..12], TAG_ACPI_NEW);
    try std.testing.expectError(error.InvalidTag, parse(&bytes, 0x5000));
}

test "Multiboot2 parser requires a final end tag and bounded physical offsets" {
    var bytes = [_]u8{0} ** 16;
    writeU32(bytes[0..4], bytes.len);
    writeU32(bytes[8..12], 42);
    writeU32(bytes[12..16], 8);
    try std.testing.expectError(error.MissingEndTag, parse(&bytes, 0x1000));

    writeU32(bytes[8..12], TAG_COMMAND_LINE);
    try std.testing.expectError(error.InvalidCommandLine, parse(&bytes, 0x1000));

    writeU32(bytes[8..12], TAG_END);
    try std.testing.expectError(error.PhysicalRangeOverflow, physicalAddress(0xffff_fff8, 8));
    _ = try parse(&bytes, 0xffff_fff0);
}
