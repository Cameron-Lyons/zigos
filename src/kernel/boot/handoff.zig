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
pub const CAPTURED_INFO_BYTES: usize = 110 + FRAMEBUFFER_RGB_COLOR_INFO_BYTES;
pub const COMMAND_LINE_SCAN_BYTES: usize = 512;
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

pub const MemoryMapEntry = struct {
    base: u64,
    length: u64,
    end: u64,
    kind: u32,

    pub fn isUsable(self: MemoryMapEntry) bool {
        return self.kind == 1 and self.length != 0;
    }
};

pub const MemoryMapIterator = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn next(self: *MemoryMapIterator) Error!?MemoryMapEntry {
        if (self.offset == self.bytes.len) return null;
        const size_field_end = std.math.add(usize, self.offset, @sizeOf(u32)) catch
            return error.InvalidMemoryMap;
        if (size_field_end > self.bytes.len) return error.InvalidMemoryMap;

        const entry_size_u32 = readU32Le(self.bytes[self.offset..size_field_end]);
        const entry_size = std.math.cast(usize, entry_size_u32) orelse
            return error.InvalidMemoryMap;
        if (entry_size < 20) return error.InvalidMemoryMap;
        const total_size = std.math.add(usize, entry_size, @sizeOf(u32)) catch
            return error.InvalidMemoryMap;
        const next_offset = std.math.add(usize, self.offset, total_size) catch
            return error.InvalidMemoryMap;
        if (next_offset > self.bytes.len) return error.InvalidMemoryMap;

        const entry = self.bytes[size_field_end..next_offset];
        const base = readU64Le(entry[0..8]);
        const length = readU64Le(entry[8..16]);
        const end = std.math.add(u64, base, length) catch return error.InvalidMemoryMap;
        const kind = readU32Le(entry[16..20]);
        self.offset = next_offset;
        return .{
            .base = base,
            .length = length,
            .end = end,
            .kind = kind,
        };
    }
};

pub fn capturedInfo() ?Info {
    const info_address = capturedInfoAddress() orelse return null;
    const bytes = checkedPhysicalBytes(info_address, CAPTURED_INFO_BYTES) orelse return null;
    return parseInfo(bytes) catch null;
}

pub fn capturedInfoAddress() ?u32 {
    if (zigos_multiboot_magic != MULTIBOOT_BOOTLOADER_MAGIC or zigos_multiboot_info_addr == 0) {
        return null;
    }
    _ = checkedPhysicalExtent(zigos_multiboot_info_addr, CAPTURED_INFO_BYTES) orelse return null;
    return zigos_multiboot_info_addr;
}

pub fn parseInfo(bytes: []const u8) Error!Info {
    if (bytes.len < CAPTURED_INFO_BYTES) return error.TooSmall;

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
    const bytes = capturedMemoryMapBytes(info) orelse return null;
    return parseMemoryMapSummary(bytes) catch null;
}

pub fn capturedMemoryMapIterator(info: Info) ?MemoryMapIterator {
    const bytes = capturedMemoryMapBytes(info) orelse return null;
    return .{ .bytes = bytes };
}

pub fn capturedMemoryMapBytes(info: Info) ?[]const u8 {
    if (!info.hasMemoryMap()) return null;
    const length = std.math.cast(usize, info.mmap_length) orelse return null;
    return checkedPhysicalBytes(info.mmap_addr, length);
}

pub fn memoryMapIterator(bytes: []const u8) MemoryMapIterator {
    return .{ .bytes = bytes };
}

pub fn parseMemoryMapSummary(bytes: []const u8) Error!MemoryMapSummary {
    var summary = MemoryMapSummary{};
    var iterator = memoryMapIterator(bytes);
    while (try iterator.next()) |entry| {
        summary.entry_count +|= 1;
        switch (entry.kind) {
            1 => {
                summary.usable_entry_count +|= 1;
                summary.usable_bytes +|= entry.length;
                summary.highest_usable_end = @max(summary.highest_usable_end, entry.end);
            },
            3 => {
                summary.acpi_entry_count +|= 1;
                summary.acpi_reclaim_bytes +|= entry.length;
            },
            else => {},
        }
    }

    if (summary.entry_count == 0) return error.InvalidMemoryMap;
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

    const bytes = checkedPhysicalBytes(info.cmdline_addr, COMMAND_LINE_SCAN_BYTES) orelse return false;
    var len: usize = 0;
    while (len < bytes.len and bytes[len] != 0) : (len += 1) {}
    return std.mem.indexOf(u8, bytes[0..len], needle) != null;
}

const PhysicalExtent = struct {
    base: usize,
    length: usize,
};

/// Validates the complete outer extent before constructing a physical-pointer
/// slice. In particular, a 32-bit Multiboot address near 4 GiB must not wrap
/// when a length is added on either a 32-bit target or a wider host test.
fn checkedPhysicalExtent(address: u32, length: usize) ?PhysicalExtent {
    if (address == 0 or length == 0) return null;
    const base = std.math.cast(usize, address) orelse return null;
    _ = std.math.add(usize, base, length) catch return null;

    const physical_end = std.math.add(u64, address, std.math.cast(u64, length) orelse return null) catch
        return null;
    const physical_limit = @as(u64, std.math.maxInt(u32)) + 1;
    // The exclusive end itself must be representable by target usize. An end
    // exactly at 4 GiB is therefore rejected consistently in wider host tests
    // as well as on the 32-bit kernel target.
    if (physical_end >= physical_limit) return null;
    return .{ .base = base, .length = length };
}

fn checkedPhysicalBytes(address: u32, length: usize) ?[]const u8 {
    const extent = checkedPhysicalExtent(address, length) orelse return null;
    return @as([*]const u8, @ptrFromInt(extent.base))[0..extent.length];
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

test "multiboot memory map iterator rejects truncated and overflowing entries" {
    var truncated = [_]u8{0} ** 4;
    writeU32Le(truncated[0..4], 20);
    var truncated_iterator = memoryMapIterator(&truncated);
    try std.testing.expectError(error.InvalidMemoryMap, truncated_iterator.next());

    var overflowing = [_]u8{0} ** MULTIBOOT_MMAP_ENTRY_BYTES;
    _ = appendMemoryMapEntry(&overflowing, 0, std.math.maxInt(u64) - 1, 4, 1);
    var overflowing_iterator = memoryMapIterator(&overflowing);
    try std.testing.expectError(error.InvalidMemoryMap, overflowing_iterator.next());
}

test "multiboot physical extents reject target-usize and 4 GiB wrap" {
    try std.testing.expect(checkedPhysicalExtent(0x1000, CAPTURED_INFO_BYTES) != null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_ffc0, CAPTURED_INFO_BYTES) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_f000, 0x2000) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_f000, 0x1000) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_ff00, COMMAND_LINE_SCAN_BYTES) == null);
    try std.testing.expect(checkedPhysicalExtent(1, std.math.maxInt(usize)) == null);
    try std.testing.expect(checkedPhysicalExtent(0, CAPTURED_INFO_BYTES) == null);
}

test "captured Multiboot APIs reject wrapping outer extents before dereference" {
    const prior_magic = zigos_multiboot_magic;
    const prior_info_address = zigos_multiboot_info_addr;
    defer {
        zigos_multiboot_magic = prior_magic;
        zigos_multiboot_info_addr = prior_info_address;
    }

    zigos_multiboot_magic = MULTIBOOT_BOOTLOADER_MAGIC;
    zigos_multiboot_info_addr = 0xffff_ffc0;
    try std.testing.expect(capturedInfo() == null);

    const info = Info{
        .flags = FLAG_CMDLINE | FLAG_MEMORY_MAP,
        .mem_lower_kib = 0,
        .mem_upper_kib = 0,
        .cmdline_addr = 0xffff_ff00,
        .mmap_length = 0x2000,
        .mmap_addr = 0xffff_f000,
        .framebuffer_addr = 0,
        .framebuffer_pitch = 0,
        .framebuffer_width = 0,
        .framebuffer_height = 0,
        .framebuffer_bpp = 0,
        .framebuffer_type = 0,
        .framebuffer_rgb = [_]u8{0} ** FRAMEBUFFER_RGB_COLOR_INFO_BYTES,
    };
    try std.testing.expect(capturedMemoryMapBytes(info) == null);
    try std.testing.expect(capturedMemoryMapIterator(info) == null);
    try std.testing.expect(capturedMemoryMapSummary(info) == null);
    try std.testing.expect(!commandLineContains(info, "model_inventory"));
}

test "multiboot handoff validates rgb framebuffer descriptors" {
    var info_bytes = [_]u8{0} ** (CAPTURED_INFO_BYTES + FRAMEBUFFER_RGB_COLOR_INFO_BYTES);
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
