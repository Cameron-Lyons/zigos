const std = @import("std");
const endian = @import("bytes.zig");

const writeU32 = endian.writeU32Le;
const writeU64 = endian.writeU64Le;

pub const TAG_END: u32 = 0;
pub const TAG_COMMAND_LINE: u32 = 1;
pub const TAG_MEMORY_MAP: u32 = 6;
pub const TAG_FRAMEBUFFER: u32 = 8;
pub const TAG_EFI64_SYSTEM_TABLE: u32 = 12;
pub const TAG_ACPI_NEW: u32 = 15;
pub const TAG_HEADER_BYTES: usize = 8;
pub const INFO_HEADER_BYTES: usize = 8;
pub const TAG_ALIGNMENT: usize = 8;
pub const MEMORY_MAP_HEADER_BYTES: usize = 16;
pub const MEMORY_MAP_ENTRY_BYTES: usize = 24;
pub const FRAMEBUFFER_COMMON_BYTES: usize = 32;
pub const FRAMEBUFFER_RGB_BYTES: usize = 6;
pub const EFI64_SYSTEM_TABLE_TAG_BYTES: usize = 16;
pub const ACPI_RSDP_V2_MIN_BYTES: usize = 36;

pub const EFI_MEMORY_TYPE_RESERVED: u32 = 0;
pub const EFI_MEMORY_TYPE_LOADER_CODE: u32 = 1;
pub const EFI_MEMORY_TYPE_LOADER_DATA: u32 = 2;
pub const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE: u32 = 5;
pub const EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
pub const EFI_MEMORY_TYPE_UNUSABLE: u32 = 8;
pub const EFI_MEMORY_TYPE_ACPI_RECLAIM: u32 = 9;
pub const EFI_MEMORY_TYPE_ACPI_NVS: u32 = 10;
pub const EFI_MEMORY_TYPE_MMIO: u32 = 11;
pub const EFI_MEMORY_TYPE_MMIO_PORT_SPACE: u32 = 12;
pub const EFI_MEMORY_TYPE_PAL_CODE: u32 = 13;
pub const EFI_MEMORY_TYPE_PERSISTENT: u32 = 14;

pub const MULTIBOOT_MEMORY_AVAILABLE: u32 = 1;
pub const MULTIBOOT_MEMORY_RESERVED: u32 = 2;
pub const MULTIBOOT_MEMORY_ACPI_RECLAIMABLE: u32 = 3;
pub const MULTIBOOT_MEMORY_NVS: u32 = 4;
pub const MULTIBOOT_MEMORY_BADRAM: u32 = 5;

pub const MmapEntry = struct {
    base: u64,
    length: u64,
    kind: u32,
};

pub const Framebuffer = struct {
    addr: u64,
    pitch: u32,
    width: u32,
    height: u32,
    bpp: u8 = 32,
    rgb: [FRAMEBUFFER_RGB_BYTES]u8,
};

pub const Request = struct {
    cmdline: []const u8 = &.{},
    mmap: []const MmapEntry = &.{},
    framebuffer: ?Framebuffer = null,
    efi_system_table: u64 = 0,
    acpi_rsdp: []const u8 = &.{},
};

pub const USES_NATIVE_EFI_STUB = true;
pub const SYNTHESIZES_MULTIBOOT2_HANDOFF = true;
pub const EXITS_BOOT_SERVICES = true;

pub fn kindFromEfiMemoryType(efi_type: u32) u32 {
    return switch (efi_type) {
        EFI_MEMORY_TYPE_LOADER_CODE,
        EFI_MEMORY_TYPE_LOADER_DATA,
        EFI_MEMORY_TYPE_BOOT_SERVICES_CODE,
        EFI_MEMORY_TYPE_BOOT_SERVICES_DATA,
        EFI_MEMORY_TYPE_CONVENTIONAL,
        EFI_MEMORY_TYPE_PERSISTENT,
        => MULTIBOOT_MEMORY_AVAILABLE,
        EFI_MEMORY_TYPE_ACPI_RECLAIM => MULTIBOOT_MEMORY_ACPI_RECLAIMABLE,
        EFI_MEMORY_TYPE_ACPI_NVS => MULTIBOOT_MEMORY_NVS,
        EFI_MEMORY_TYPE_UNUSABLE => MULTIBOOT_MEMORY_BADRAM,
        else => MULTIBOOT_MEMORY_RESERVED,
    };
}

pub fn rgbFromMasks(red_pos: u8, green_pos: u8, blue_pos: u8) [FRAMEBUFFER_RGB_BYTES]u8 {
    return .{ red_pos, 8, green_pos, 8, blue_pos, 8 };
}

pub fn encodedSize(request: Request) usize {
    var size: usize = INFO_HEADER_BYTES;
    if (request.cmdline.len != 0) {
        size = alignTag(size + TAG_HEADER_BYTES + request.cmdline.len + 1);
    }
    if (request.mmap.len != 0) {
        size += MEMORY_MAP_HEADER_BYTES + request.mmap.len * MEMORY_MAP_ENTRY_BYTES;
        size = alignTag(size);
    }
    if (request.framebuffer) |_| {
        size = alignTag(size + FRAMEBUFFER_COMMON_BYTES + FRAMEBUFFER_RGB_BYTES);
    }
    if (request.efi_system_table != 0) {
        size = alignTag(size + EFI64_SYSTEM_TABLE_TAG_BYTES);
    }
    if (request.acpi_rsdp.len != 0) {
        size = alignTag(size + TAG_HEADER_BYTES + request.acpi_rsdp.len);
    }
    return alignTag(size + TAG_HEADER_BYTES);
}

pub fn encode(buffer: []u8, request: Request) error{BufferTooSmall}![]u8 {
    const needed = encodedSize(request);
    if (buffer.len < needed) return error.BufferTooSmall;
    @memset(buffer[0..needed], 0);
    writeU32(buffer[0..4], @intCast(needed));

    var offset: usize = INFO_HEADER_BYTES;
    if (request.cmdline.len != 0) {
        const payload = request.cmdline.len + 1;
        writeTagHeader(buffer, &offset, TAG_COMMAND_LINE, TAG_HEADER_BYTES + payload);
        @memcpy(buffer[offset .. offset + request.cmdline.len], request.cmdline);
        offset = alignTag(offset + payload);
    }
    if (request.mmap.len != 0) {
        const entries_bytes = request.mmap.len * MEMORY_MAP_ENTRY_BYTES;
        writeTagHeader(buffer, &offset, TAG_MEMORY_MAP, MEMORY_MAP_HEADER_BYTES + entries_bytes);
        writeU32(buffer[offset .. offset + 4], MEMORY_MAP_ENTRY_BYTES);
        offset += 8;
        for (request.mmap) |entry| {
            writeU64(buffer[offset .. offset + 8], entry.base);
            writeU64(buffer[offset + 8 .. offset + 16], entry.length);
            writeU32(buffer[offset + 16 .. offset + 20], entry.kind);
            offset += MEMORY_MAP_ENTRY_BYTES;
        }
        offset = alignTag(offset);
    }
    if (request.framebuffer) |fb| {
        writeTagHeader(buffer, &offset, TAG_FRAMEBUFFER, FRAMEBUFFER_COMMON_BYTES + FRAMEBUFFER_RGB_BYTES);
        writeU64(buffer[offset .. offset + 8], fb.addr);
        writeU32(buffer[offset + 8 .. offset + 12], fb.pitch);
        writeU32(buffer[offset + 12 .. offset + 16], fb.width);
        writeU32(buffer[offset + 16 .. offset + 20], fb.height);
        buffer[offset + 20] = fb.bpp;
        buffer[offset + 21] = 1;
        @memcpy(buffer[offset + 24 .. offset + 24 + FRAMEBUFFER_RGB_BYTES], &fb.rgb);
        offset = alignTag(offset + FRAMEBUFFER_COMMON_BYTES + FRAMEBUFFER_RGB_BYTES - TAG_HEADER_BYTES);
    }
    if (request.efi_system_table != 0) {
        writeTagHeader(buffer, &offset, TAG_EFI64_SYSTEM_TABLE, EFI64_SYSTEM_TABLE_TAG_BYTES);
        writeU64(buffer[offset .. offset + 8], request.efi_system_table);
        offset = alignTag(offset + 8);
    }
    if (request.acpi_rsdp.len != 0) {
        writeTagHeader(buffer, &offset, TAG_ACPI_NEW, TAG_HEADER_BYTES + request.acpi_rsdp.len);
        @memcpy(buffer[offset .. offset + request.acpi_rsdp.len], request.acpi_rsdp);
        offset = alignTag(offset + request.acpi_rsdp.len);
    }
    writeTagHeader(buffer, &offset, TAG_END, TAG_HEADER_BYTES);
    offset = alignTag(offset);
    if (offset != needed) return error.BufferTooSmall;
    return buffer[0..needed];
}

fn writeTagHeader(buffer: []u8, offset: *usize, tag_type: u32, tag_size: usize) void {
    writeU32(buffer[offset.* .. offset.* + 4], tag_type);
    writeU32(buffer[offset.* + 4 .. offset.* + 8], @intCast(tag_size));
    offset.* += TAG_HEADER_BYTES;
}

fn alignTag(value: usize) usize {
    return std.mem.alignForward(usize, value, TAG_ALIGNMENT);
}

test "EFI memory types become Multiboot2 map kinds" {
    try std.testing.expectEqual(MULTIBOOT_MEMORY_AVAILABLE, kindFromEfiMemoryType(EFI_MEMORY_TYPE_CONVENTIONAL));
    try std.testing.expectEqual(MULTIBOOT_MEMORY_AVAILABLE, kindFromEfiMemoryType(EFI_MEMORY_TYPE_LOADER_DATA));
    try std.testing.expectEqual(MULTIBOOT_MEMORY_ACPI_RECLAIMABLE, kindFromEfiMemoryType(EFI_MEMORY_TYPE_ACPI_RECLAIM));
    try std.testing.expectEqual(MULTIBOOT_MEMORY_NVS, kindFromEfiMemoryType(EFI_MEMORY_TYPE_ACPI_NVS));
    try std.testing.expectEqual(MULTIBOOT_MEMORY_RESERVED, kindFromEfiMemoryType(EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE));
    try std.testing.expectEqual(MULTIBOOT_MEMORY_RESERVED, kindFromEfiMemoryType(EFI_MEMORY_TYPE_MMIO));
}
