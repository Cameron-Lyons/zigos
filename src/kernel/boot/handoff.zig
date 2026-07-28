const std = @import("std");
const framebuffer = @import("../platform/framebuffer.zig");
const endian = @import("../utils/endian.zig");
const multiboot2 = @import("multiboot2.zig");

const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;

const FLAG_MEMORY_INFO: u32 = 1 << 0;
const FLAG_CMDLINE: u32 = 1 << 2;
const FLAG_MEMORY_MAP: u32 = 1 << 6;
const FLAG_FRAMEBUFFER: u32 = 1 << 12;

const FRAMEBUFFER_RGB_COLOR_INFO_BYTES: usize = 6;
pub const CAPTURED_INFO_BYTES: usize = 110 + FRAMEBUFFER_RGB_COLOR_INFO_BYTES;
pub const COMMAND_LINE_SCAN_BYTES: usize = 512;
const MULTIBOOT_MMAP_ENTRY_BYTES: usize = 24;
const MULTIBOOT2_INFO_HEADER_BYTES: usize = 8;
const MAX_MULTIBOOT2_INFO_BYTES: usize = 1024 * 1024;
const BOOT_IDENTITY_BYTES: u64 = 128 * 1024 * 1024;

pub export var zigos_multiboot_magic: u32 = 0;
pub export var zigos_multiboot_info_addr: u32 = 0;

pub const Error = error{
    TooSmall,
    BadMagic,
    MissingMemoryMap,
    InvalidMemoryMap,
    UnsupportedFramebuffer,
    InvalidFramebuffer,
} || multiboot2.Error;

pub const Protocol = enum {
    multiboot1,
    multiboot2,
};

pub const MemoryMapEncoding = enum {
    multiboot1,
    multiboot2,
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
    protocol: Protocol = .multiboot1,
    info_bytes: u32 = CAPTURED_INFO_BYTES,
    cmdline_length: u32 = COMMAND_LINE_SCAN_BYTES,
    mmap_entry_size: u32 = 0,
    mmap_encoding: MemoryMapEncoding = .multiboot1,

    pub fn hasMemoryInfo(self: Info) bool {
        return (self.flags & FLAG_MEMORY_INFO) != 0;
    }

    pub fn hasCommandLine(self: Info) bool {
        return (self.flags & FLAG_CMDLINE) != 0 and self.cmdline_addr != 0 and self.cmdline_length > 0;
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

pub const MemoryMap = struct {
    bytes: []const u8,
    encoding: MemoryMapEncoding,
    entry_size: u32,

    pub fn iterator(self: MemoryMap) MemoryMapIterator {
        return .{
            .bytes = self.bytes,
            .encoding = self.encoding,
            .entry_size = self.entry_size,
        };
    }
};

pub const MemoryMapIterator = struct {
    bytes: []const u8,
    offset: usize = 0,
    encoding: MemoryMapEncoding = .multiboot1,
    entry_size: u32 = 0,

    pub fn next(self: *MemoryMapIterator) Error!?MemoryMapEntry {
        if (self.offset == self.bytes.len) return null;

        if (self.encoding == .multiboot2) {
            const stride = std.math.cast(usize, self.entry_size) orelse
                return error.InvalidMemoryMap;
            if (stride < 24) return error.InvalidMemoryMap;
            const next_offset = std.math.add(usize, self.offset, stride) catch
                return error.InvalidMemoryMap;
            if (next_offset > self.bytes.len) return error.InvalidMemoryMap;

            const entry = self.bytes[self.offset..next_offset];
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
    const bytes = capturedInfoBytes(info_address) orelse return null;
    return switch (zigos_multiboot_magic) {
        MULTIBOOT_BOOTLOADER_MAGIC => parseInfo(bytes) catch null,
        MULTIBOOT2_BOOTLOADER_MAGIC => parseMultiboot2Info(bytes, info_address) catch null,
        else => null,
    };
}

pub fn capturedInfoAddress() ?u32 {
    if (zigos_multiboot_info_addr == 0) return null;
    switch (zigos_multiboot_magic) {
        MULTIBOOT_BOOTLOADER_MAGIC, MULTIBOOT2_BOOTLOADER_MAGIC => {},
        else => return null,
    }
    _ = capturedInfoBytes(zigos_multiboot_info_addr) orelse return null;
    return zigos_multiboot_info_addr;
}

fn capturedInfoBytes(info_address: u32) ?[]const u8 {
    if (zigos_multiboot_magic == MULTIBOOT_BOOTLOADER_MAGIC) {
        return checkedPhysicalBytes(info_address, CAPTURED_INFO_BYTES);
    }
    if (zigos_multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC) return null;

    const header = checkedPhysicalBytes(info_address, MULTIBOOT2_INFO_HEADER_BYTES) orelse return null;
    const total_size = multiboot2.declaredTotalSize(header) catch return null;
    const total_len = std.math.cast(usize, total_size) orelse return null;
    if (total_len > MAX_MULTIBOOT2_INFO_BYTES) return null;
    return checkedPhysicalBytes(info_address, total_len);
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

pub fn parseMultiboot2Info(bytes: []const u8, physical_base: u32) Error!Info {
    const parsed = try multiboot2.parse(bytes, physical_base);
    var flags: u32 = 0;
    if (parsed.has_basic_memory) flags |= FLAG_MEMORY_INFO;
    if (parsed.has_command_line) flags |= FLAG_CMDLINE;
    if (parsed.has_memory_map) flags |= FLAG_MEMORY_MAP;
    if (parsed.has_framebuffer) flags |= FLAG_FRAMEBUFFER;

    return .{
        .flags = flags,
        .mem_lower_kib = parsed.mem_lower_kib,
        .mem_upper_kib = parsed.mem_upper_kib,
        .cmdline_addr = parsed.cmdline_addr,
        .mmap_length = parsed.mmap_length,
        .mmap_addr = parsed.mmap_addr,
        .framebuffer_addr = parsed.framebuffer_addr,
        .framebuffer_pitch = parsed.framebuffer_pitch,
        .framebuffer_width = parsed.framebuffer_width,
        .framebuffer_height = parsed.framebuffer_height,
        .framebuffer_bpp = parsed.framebuffer_bpp,
        .framebuffer_type = parsed.framebuffer_type,
        .framebuffer_rgb = parsed.framebuffer_rgb,
        .protocol = .multiboot2,
        .info_bytes = parsed.total_size,
        .cmdline_length = parsed.cmdline_length,
        .mmap_entry_size = parsed.mmap_entry_size,
        .mmap_encoding = .multiboot2,
    };
}

pub fn capturedMemoryMapSummary(info: Info) ?MemoryMapSummary {
    const map = capturedMemoryMap(info) orelse return null;
    return summarizeMemoryMap(map) catch null;
}

pub fn capturedMemoryMap(info: Info) ?MemoryMap {
    if (!info.hasMemoryMap()) return null;
    const length = std.math.cast(usize, info.mmap_length) orelse return null;
    const bytes = checkedPhysicalBytes(info.mmap_addr, length) orelse return null;
    if (info.mmap_encoding == .multiboot2 and info.mmap_entry_size < 24) return null;
    return .{
        .bytes = bytes,
        .encoding = info.mmap_encoding,
        .entry_size = info.mmap_entry_size,
    };
}

pub fn multiboot1MemoryMap(bytes: []const u8) MemoryMap {
    return .{ .bytes = bytes, .encoding = .multiboot1, .entry_size = 0 };
}

pub fn multiboot2MemoryMap(bytes: []const u8, entry_size: u32) MemoryMap {
    return .{ .bytes = bytes, .encoding = .multiboot2, .entry_size = entry_size };
}

pub fn parseMemoryMapSummary(bytes: []const u8) Error!MemoryMapSummary {
    return summarizeMemoryMap(multiboot1MemoryMap(bytes));
}

pub fn summarizeMemoryMap(map: MemoryMap) Error!MemoryMapSummary {
    var summary = MemoryMapSummary{};
    var iterator = map.iterator();
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

    const scan_length = std.math.cast(usize, info.cmdline_length) orelse return false;
    const bytes = checkedPhysicalBytes(info.cmdline_addr, scan_length) orelse return false;
    var len: usize = 0;
    while (len < bytes.len and bytes[len] != 0) : (len += 1) {}
    return std.mem.indexOf(u8, bytes[0..len], needle) != null;
}

const PhysicalExtent = struct {
    base: usize,
    length: usize,
};

/// Validates the complete outer extent before constructing a physical-pointer
/// slice. Boot handoff bytes must stay inside the 128 MiB identity aperture
/// installed by both entry paths, and additions must not wrap on any target.
fn checkedPhysicalExtent(address: u32, length: usize) ?PhysicalExtent {
    if (address == 0 or length == 0) return null;
    const base = std.math.cast(usize, address) orelse return null;
    _ = std.math.add(usize, base, length) catch return null;

    const physical_end = std.math.add(u64, address, std.math.cast(u64, length) orelse return null) catch
        return null;
    if (physical_end > BOOT_IDENTITY_BYTES) return null;
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

test "Multiboot2 handoff normalizes tagged map metadata and entries" {
    var info_bytes = [_]u8{0} ** 56;
    writeU32Le(info_bytes[0..4], info_bytes.len);
    writeU32Le(info_bytes[8..12], 6);
    writeU32Le(info_bytes[12..16], 40);
    writeU32Le(info_bytes[16..20], 24);
    writeU64Le(info_bytes[24..32], 0x100000);
    writeU64Le(info_bytes[32..40], 0x2000000);
    writeU32Le(info_bytes[40..44], 1);
    writeU32Le(info_bytes[48..52], 0);
    writeU32Le(info_bytes[52..56], 8);

    const info = try parseMultiboot2Info(&info_bytes, 0x8000);
    try std.testing.expectEqual(Protocol.multiboot2, info.protocol);
    try std.testing.expectEqual(MemoryMapEncoding.multiboot2, info.mmap_encoding);
    try std.testing.expectEqual(@as(u32, 24), info.mmap_entry_size);
    try std.testing.expectEqual(@as(u32, 24), info.mmap_length);

    const map_bytes = info_bytes[24..48];
    const summary = try summarizeMemoryMap(multiboot2MemoryMap(map_bytes, info.mmap_entry_size));
    try std.testing.expectEqual(@as(u32, 1), summary.entry_count);
    try std.testing.expectEqual(@as(u64, 0x2000000), summary.usable_bytes);
    try std.testing.expectEqual(@as(u64, 0x2100000), summary.highest_usable_end);
}

test "Multiboot2 memory map iterator rejects invalid fixed strides" {
    var bytes = [_]u8{0} ** 24;
    var too_small = multiboot2MemoryMap(&bytes, 16).iterator();
    try std.testing.expectError(error.InvalidMemoryMap, too_small.next());

    var truncated = multiboot2MemoryMap(bytes[0..20], 24).iterator();
    try std.testing.expectError(error.InvalidMemoryMap, truncated.next());
}

test "multiboot memory map iterator rejects truncated and overflowing entries" {
    var truncated = [_]u8{0} ** 4;
    writeU32Le(truncated[0..4], 20);
    var truncated_iterator = multiboot1MemoryMap(&truncated).iterator();
    try std.testing.expectError(error.InvalidMemoryMap, truncated_iterator.next());

    var overflowing = [_]u8{0} ** MULTIBOOT_MMAP_ENTRY_BYTES;
    _ = appendMemoryMapEntry(&overflowing, 0, std.math.maxInt(u64) - 1, 4, 1);
    var overflowing_iterator = multiboot1MemoryMap(&overflowing).iterator();
    try std.testing.expectError(error.InvalidMemoryMap, overflowing_iterator.next());
}

test "multiboot physical extents reject target-usize and 4 GiB wrap" {
    try std.testing.expect(checkedPhysicalExtent(0x1000, CAPTURED_INFO_BYTES) != null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_ffc0, CAPTURED_INFO_BYTES) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_f000, 0x2000) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_f000, 0x1000) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_ff00, COMMAND_LINE_SCAN_BYTES) == null);
    try std.testing.expect(checkedPhysicalExtent(0x07ff_f000, 0x1000) != null);
    try std.testing.expect(checkedPhysicalExtent(0x0800_0000, 1) == null);
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
    try std.testing.expect(capturedMemoryMap(info) == null);
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
