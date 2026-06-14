const std = @import("std");
const framebuffer = @import("../platform/framebuffer.zig");
const endian = @import("../utils/endian.zig");

const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;

const FLAG_MEMORY_INFO: u32 = 1 << 0;
const FLAG_CMDLINE: u32 = 1 << 2;
const FLAG_MEMORY_MAP: u32 = 1 << 6;
const FLAG_FRAMEBUFFER: u32 = 1 << 12;

const FRAMEBUFFER_RGB_COLOR_INFO_BYTES: usize = 6;
const INFO_MIN_BYTES: usize = 110 + FRAMEBUFFER_RGB_COLOR_INFO_BYTES;
const MAX_CMDLINE_BYTES: usize = 512;
const MULTIBOOT_MMAP_ENTRY_BYTES: usize = 24;

pub export var zigos_multiboot_magic: u32 = 0;
pub export var zigos_multiboot_info_addr: u32 = 0;

pub const Error = error{
    TooSmall,
    BadMagic,
    MissingMemoryMap,
    InvalidMemoryMap,
    UnsupportedFramebuffer,
    InvalidFramebuffer,
};

pub const Info = struct {
    flags: u32,
    mem_lower_kib: u32,
    mem_upper_kib: u32,
    cmdline_addr: u32,
    mmap_length: u32,
    mmap_addr: u32,
    framebuffer_addr: u64,
    framebuffer_pitch: u32,
    framebuffer_width: u32,
    framebuffer_height: u32,
    framebuffer_bpp: u8,
    framebuffer_type: u8,
    framebuffer_rgb: [FRAMEBUFFER_RGB_COLOR_INFO_BYTES]u8,

    pub fn hasMemoryInfo(self: Info) bool {
        return (self.flags & FLAG_MEMORY_INFO) != 0;
    }

    pub fn hasCommandLine(self: Info) bool {
        return (self.flags & FLAG_CMDLINE) != 0 and self.cmdline_addr != 0;
    }

    pub fn hasMemoryMap(self: Info) bool {
        return (self.flags & FLAG_MEMORY_MAP) != 0 and self.mmap_addr != 0 and self.mmap_length > 0;
    }

    pub fn hasFramebuffer(self: Info) bool {
        return (self.flags & FLAG_FRAMEBUFFER) != 0 and self.framebuffer_addr != 0;
    }
};

pub const MemoryMapSummary = struct {
    entry_count: u32 = 0,
    usable_entry_count: u32 = 0,
    acpi_entry_count: u32 = 0,
    usable_bytes: u64 = 0,
    acpi_reclaim_bytes: u64 = 0,
    highest_usable_end: u64 = 0,

    pub fn hasUsableMemory(self: MemoryMapSummary) bool {
        return self.usable_entry_count > 0 and self.usable_bytes > 0 and self.highest_usable_end > 0;
    }
};

pub fn capturedInfo() ?Info {
    if (zigos_multiboot_magic != MULTIBOOT_BOOTLOADER_MAGIC or zigos_multiboot_info_addr == 0) {
        return null;
    }

    const bytes = @as([*]const u8, @ptrFromInt(zigos_multiboot_info_addr))[0..INFO_MIN_BYTES];
    return parseInfo(bytes) catch null;
}

pub fn parseInfo(bytes: []const u8) Error!Info {
    if (bytes.len < INFO_MIN_BYTES) return error.TooSmall;

    var rgb: [FRAMEBUFFER_RGB_COLOR_INFO_BYTES]u8 = [_]u8{0} ** FRAMEBUFFER_RGB_COLOR_INFO_BYTES;
    @memcpy(rgb[0..], bytes[110 .. 110 + FRAMEBUFFER_RGB_COLOR_INFO_BYTES]);

    return .{
        .flags = readU32Le(bytes[0..4]),
        .mem_lower_kib = readU32Le(bytes[4..8]),
        .mem_upper_kib = readU32Le(bytes[8..12]),
        .cmdline_addr = readU32Le(bytes[16..20]),
        .mmap_length = readU32Le(bytes[44..48]),
        .mmap_addr = readU32Le(bytes[48..52]),
        .framebuffer_addr = readU64Le(bytes[88..96]),
        .framebuffer_pitch = readU32Le(bytes[96..100]),
        .framebuffer_width = readU32Le(bytes[100..104]),
        .framebuffer_height = readU32Le(bytes[104..108]),
        .framebuffer_bpp = bytes[108],
        .framebuffer_type = bytes[109],
        .framebuffer_rgb = rgb,
    };
}

pub fn capturedMemoryMapSummary(info: Info) ?MemoryMapSummary {
    if (!info.hasMemoryMap()) return null;
    const bytes = @as([*]const u8, @ptrFromInt(info.mmap_addr))[0..info.mmap_length];
    return parseMemoryMapSummary(bytes) catch null;
}

pub fn parseMemoryMapSummary(bytes: []const u8) Error!MemoryMapSummary {
    var summary = MemoryMapSummary{};
    var offset: usize = 0;

    while (offset < bytes.len) {
        if (offset + 4 > bytes.len) return error.InvalidMemoryMap;
        const entry_size = readU32Le(bytes[offset .. offset + 4]);
        const total_size = @as(usize, entry_size) + 4;
        if (entry_size < 20 or offset + total_size > bytes.len) return error.InvalidMemoryMap;

        const entry = bytes[offset + 4 .. offset + total_size];
        const base = readU64Le(entry[0..8]);
        const length = readU64Le(entry[8..16]);
        const kind = readU32Le(entry[16..20]);
        const end = base +| length;

        summary.entry_count += 1;
        switch (kind) {
            1 => {
                summary.usable_entry_count += 1;
                summary.usable_bytes +|= length;
                summary.highest_usable_end = @max(summary.highest_usable_end, end);
            },
            3 => {
                summary.acpi_entry_count += 1;
                summary.acpi_reclaim_bytes +|= length;
            },
            else => {},
        }

        offset += total_size;
    }

    if (offset != bytes.len or summary.entry_count == 0) return error.InvalidMemoryMap;
    return summary;
}

pub fn framebufferInfo(info: Info) Error!framebuffer.Info {
    if (!info.hasFramebuffer()) return error.InvalidFramebuffer;
    if (info.framebuffer_type != 1 or info.framebuffer_bpp != 32) return error.UnsupportedFramebuffer;

    const pixel_mask = framebuffer.PixelMask{
        .red = maskFromField(info.framebuffer_rgb[0], info.framebuffer_rgb[1]) orelse return error.UnsupportedFramebuffer,
        .green = maskFromField(info.framebuffer_rgb[2], info.framebuffer_rgb[3]) orelse return error.UnsupportedFramebuffer,
        .blue = maskFromField(info.framebuffer_rgb[4], info.framebuffer_rgb[5]) orelse return error.UnsupportedFramebuffer,
        .reserved = reservedMask(info.framebuffer_rgb),
    };

    return framebuffer.validate(.{
        .physical_address = info.framebuffer_addr,
        .width = info.framebuffer_width,
        .height = info.framebuffer_height,
        .pixels_per_scan_line = info.framebuffer_pitch / 4,
        .format = .bitmask,
        .pixel_mask = pixel_mask,
        .buffer_bytes = @as(u64, info.framebuffer_pitch) * @as(u64, info.framebuffer_height),
    }) catch error.InvalidFramebuffer;
}

pub fn commandLineContains(info: Info, needle: []const u8) bool {
    if (!info.hasCommandLine() or needle.len == 0) return false;

    const bytes = @as([*]const u8, @ptrFromInt(info.cmdline_addr))[0..MAX_CMDLINE_BYTES];
    var len: usize = 0;
    while (len < bytes.len and bytes[len] != 0) : (len += 1) {}
    return std.mem.indexOf(u8, bytes[0..len], needle) != null;
}

fn maskFromField(position: u8, size: u8) ?u32 {
    if (size == 0 or size > 32 or position >= 32 or @as(u16, position) + @as(u16, size) > 32) {
        return null;
    }
    const width_mask = if (size == 32) std.math.maxInt(u32) else (@as(u32, 1) << @intCast(size)) - 1;
    return width_mask << @intCast(position);
}

fn reservedMask(rgb: [FRAMEBUFFER_RGB_COLOR_INFO_BYTES]u8) u32 {
    const red = maskFromField(rgb[0], rgb[1]) orelse 0;
    const green = maskFromField(rgb[2], rgb[3]) orelse 0;
    const blue = maskFromField(rgb[4], rgb[5]) orelse 0;
    return ~(red | green | blue);
}

fn appendMemoryMapEntry(bytes: []u8, offset: usize, base: u64, length: u64, kind: u32) usize {
    writeU32Le(bytes[offset .. offset + 4], 20);
    writeU64Le(bytes[offset + 4 .. offset + 12], base);
    writeU64Le(bytes[offset + 12 .. offset + 20], length);
    writeU32Le(bytes[offset + 20 .. offset + 24], kind);
    return offset + MULTIBOOT_MMAP_ENTRY_BYTES;
}

test "multiboot handoff parses memory map summary" {
    var mmap = [_]u8{0} ** (MULTIBOOT_MMAP_ENTRY_BYTES * 2);
    var offset = appendMemoryMapEntry(mmap[0..], 0, 0x100000, 0x2000000, 1);
    offset = appendMemoryMapEntry(mmap[0..], offset, 0x3000000, 0x1000, 3);
    try std.testing.expectEqual(@as(usize, mmap.len), offset);

    const summary = try parseMemoryMapSummary(mmap[0..]);
    try std.testing.expectEqual(@as(u32, 2), summary.entry_count);
    try std.testing.expectEqual(@as(u32, 1), summary.usable_entry_count);
    try std.testing.expectEqual(@as(u64, 0x2000000), summary.usable_bytes);
    try std.testing.expectEqual(@as(u64, 0x2100000), summary.highest_usable_end);
    try std.testing.expectEqual(@as(u64, 0x1000), summary.acpi_reclaim_bytes);
}

test "multiboot handoff validates rgb framebuffer descriptors" {
    var info_bytes = [_]u8{0} ** (INFO_MIN_BYTES + FRAMEBUFFER_RGB_COLOR_INFO_BYTES);
    writeU32Le(info_bytes[0..4], FLAG_FRAMEBUFFER);
    writeU64Le(info_bytes[88..96], 0x8000_0000);
    writeU32Le(info_bytes[96..100], 1920 * 4);
    writeU32Le(info_bytes[100..104], 1920);
    writeU32Le(info_bytes[104..108], 1080);
    info_bytes[108] = 32;
    info_bytes[109] = 1;
    info_bytes[110] = 16;
    info_bytes[111] = 8;
    info_bytes[112] = 8;
    info_bytes[113] = 8;
    info_bytes[114] = 0;
    info_bytes[115] = 8;

    const info = try parseInfo(info_bytes[0..]);
    const fb = try framebufferInfo(info);
    try std.testing.expectEqual(@as(u64, 0x8000_0000), fb.physical_address);
    try std.testing.expectEqual(@as(u32, 1920), fb.width);
    try std.testing.expectEqual(@as(u32, 1080), fb.height);
}
