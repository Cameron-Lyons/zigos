const std = @import("std");
const framebuffer = @import("../platform/framebuffer.zig");
const endian = @import("../utils/endian.zig");
const multiboot2 = @import("multiboot2.zig");

const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;

const FLAG_MEMORY_INFO: u32 = 1 << 0;
const FLAG_CMDLINE: u32 = 1 << 2;
const FLAG_MEMORY_MAP: u32 = 1 << 6;
const FLAG_FRAMEBUFFER: u32 = 1 << 12;
const FLAG_ACPI2_RSDP: u32 = 1 << 13;

const FRAMEBUFFER_RGB_COLOR_INFO_BYTES: usize = 6;
const MULTIBOOT2_INFO_HEADER_BYTES: usize = 8;
const MULTIBOOT2_MMAP_ENTRY_BYTES: usize = 24;
const MAX_MULTIBOOT2_INFO_BYTES: usize = 1024 * 1024;
const BOOT_IDENTITY_BYTES: u64 = 128 * 1024 * 1024;

pub export var zigos_multiboot_magic: u32 = 0;
pub export var zigos_multiboot_info_addr: u32 = 0;

pub const Error = error{
    MissingMemoryMap,
    InvalidMemoryMap,
    UnsupportedFramebuffer,
    InvalidFramebuffer,
} || multiboot2.Error;

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
    info_bytes: u32,
    cmdline_length: u32,
    mmap_entry_size: u32,
    acpi2_rsdp_addr: u32 = 0,
    acpi2_rsdp_length: u32 = 0,

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

    pub fn hasAcpi2Rsdp(self: Info) bool {
        return (self.flags & FLAG_ACPI2_RSDP) != 0 and self.acpi2_rsdp_addr != 0 and self.acpi2_rsdp_length > 0;
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
    entry_size: u32,

    pub fn iterator(self: MemoryMap) MemoryMapIterator {
        return .{
            .bytes = self.bytes,
            .entry_size = self.entry_size,
        };
    }
};

pub const MemoryMapIterator = struct {
    bytes: []const u8,
    offset: usize = 0,
    entry_size: u32 = 0,

    pub fn next(self: *MemoryMapIterator) Error!?MemoryMapEntry {
        if (self.offset == self.bytes.len) return null;

        const stride = std.math.cast(usize, self.entry_size) orelse
            return error.InvalidMemoryMap;
        if (stride < MULTIBOOT2_MMAP_ENTRY_BYTES) return error.InvalidMemoryMap;
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
};

pub fn capturedInfo() ?Info {
    const info_address = capturedInfoAddress() orelse return null;
    const bytes = capturedInfoBytes(info_address) orelse return null;
    return parseMultiboot2Info(bytes, info_address) catch null;
}

pub fn capturedInfoAddress() ?u32 {
    if (zigos_multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC or zigos_multiboot_info_addr == 0) return null;
    _ = capturedInfoBytes(zigos_multiboot_info_addr) orelse return null;
    return zigos_multiboot_info_addr;
}

fn capturedInfoBytes(info_address: u32) ?[]const u8 {
    if (zigos_multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC) return null;

    const header = checkedPhysicalBytes(info_address, MULTIBOOT2_INFO_HEADER_BYTES) orelse return null;
    const total_size = multiboot2.declaredTotalSize(header) catch return null;
    const total_len = std.math.cast(usize, total_size) orelse return null;
    if (total_len > MAX_MULTIBOOT2_INFO_BYTES) return null;
    return checkedPhysicalBytes(info_address, total_len);
}

pub fn parseMultiboot2Info(bytes: []const u8, physical_base: u32) Error!Info {
    const parsed = try multiboot2.parse(bytes, physical_base);
    var flags: u32 = 0;
    if (parsed.has_basic_memory) flags |= FLAG_MEMORY_INFO;
    if (parsed.has_command_line) flags |= FLAG_CMDLINE;
    if (parsed.has_memory_map) flags |= FLAG_MEMORY_MAP;
    if (parsed.has_framebuffer) flags |= FLAG_FRAMEBUFFER;
    if (parsed.has_acpi2_rsdp) flags |= FLAG_ACPI2_RSDP;

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
        .info_bytes = parsed.total_size,
        .cmdline_length = parsed.cmdline_length,
        .mmap_entry_size = parsed.mmap_entry_size,
        .acpi2_rsdp_addr = parsed.acpi2_rsdp_addr,
        .acpi2_rsdp_length = parsed.acpi2_rsdp_length,
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
    if (info.mmap_entry_size < MULTIBOOT2_MMAP_ENTRY_BYTES) return null;
    return .{
        .bytes = bytes,
        .entry_size = info.mmap_entry_size,
    };
}

pub fn multiboot2MemoryMap(bytes: []const u8, entry_size: u32) MemoryMap {
    return .{ .bytes = bytes, .entry_size = entry_size };
}

pub fn capturedAcpi2Rsdp(info: Info) ?[]const u8 {
    if (!info.hasAcpi2Rsdp()) return null;
    const length = std.math.cast(usize, info.acpi2_rsdp_length) orelse return null;
    return checkedPhysicalBytes(info.acpi2_rsdp_addr, length);
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

pub fn commandLineHasFlag(info: Info, flag: []const u8) bool {
    const command_line = commandLineBytes(info) orelse return false;
    return commandLineHasFlagBytes(command_line, flag);
}

fn commandLineHasFlagBytes(command_line: []const u8, flag: []const u8) bool {
    if (flag.len == 0) return false;
    var arguments = std.mem.tokenizeAny(u8, command_line, " \t");
    while (arguments.next()) |argument| {
        if (std.mem.eql(u8, argument, flag)) return true;
    }
    return false;
}

pub fn commandLineU64(info: Info, key: []const u8) ?u64 {
    const command_line = commandLineBytes(info) orelse return null;
    return commandLineU64Bytes(command_line, key);
}

fn commandLineBytes(info: Info) ?[]const u8 {
    if (!info.hasCommandLine()) return null;

    const scan_length = std.math.cast(usize, info.cmdline_length) orelse return null;
    const bytes = checkedPhysicalBytes(info.cmdline_addr, scan_length) orelse return null;
    var len: usize = 0;
    while (len < bytes.len and bytes[len] != 0) : (len += 1) {}
    return bytes[0..len];
}

fn commandLineU64Bytes(command_line: []const u8, key: []const u8) ?u64 {
    if (key.len == 0) return null;
    var value: ?u64 = null;
    var arguments = std.mem.tokenizeAny(u8, command_line, " \t");
    while (arguments.next()) |argument| {
        if (argument.len <= key.len + 1 or
            !std.mem.eql(u8, argument[0..key.len], key) or
            argument[key.len] != '=')
        {
            continue;
        }
        if (value != null) return null;
        value = std.fmt.parseInt(u64, argument[key.len + 1 ..], 10) catch return null;
    }
    return value;
}

const PhysicalExtent = struct {
    base: usize,
    length: usize,
};

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
    writeU64Le(bytes[offset .. offset + 8], base);
    writeU64Le(bytes[offset + 8 .. offset + 16], length);
    writeU32Le(bytes[offset + 16 .. offset + 20], kind);
    writeU32Le(bytes[offset + 20 .. offset + 24], 0);
    return offset + MULTIBOOT2_MMAP_ENTRY_BYTES;
}

test "Multiboot2 handoff parses memory map summary" {
    var mmap = [_]u8{0} ** (MULTIBOOT2_MMAP_ENTRY_BYTES * 2);
    var offset = appendMemoryMapEntry(mmap[0..], 0, 0x100000, 0x2000000, 1);
    offset = appendMemoryMapEntry(mmap[0..], offset, 0x3000000, 0x1000, 3);
    try std.testing.expectEqual(@as(usize, mmap.len), offset);

    const summary = try summarizeMemoryMap(multiboot2MemoryMap(mmap[0..], MULTIBOOT2_MMAP_ENTRY_BYTES));
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

    var overflowing = [_]u8{0} ** MULTIBOOT2_MMAP_ENTRY_BYTES;
    _ = appendMemoryMapEntry(&overflowing, 0, std.math.maxInt(u64) - 1, 4, 1);
    var overflowing_iterator = multiboot2MemoryMap(&overflowing, MULTIBOOT2_MMAP_ENTRY_BYTES).iterator();
    try std.testing.expectError(error.InvalidMemoryMap, overflowing_iterator.next());
}

test "Multiboot2 physical extents reject target-usize and 4 GiB wrap" {
    try std.testing.expect(checkedPhysicalExtent(0x1000, MULTIBOOT2_INFO_HEADER_BYTES) != null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_ffc0, MULTIBOOT2_INFO_HEADER_BYTES) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_f000, 0x2000) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_f000, 0x1000) == null);
    try std.testing.expect(checkedPhysicalExtent(0xffff_ff00, 512) == null);
    try std.testing.expect(checkedPhysicalExtent(0x07ff_f000, 0x1000) != null);
    try std.testing.expect(checkedPhysicalExtent(0x0800_0000, 1) == null);
    try std.testing.expect(checkedPhysicalExtent(1, std.math.maxInt(usize)) == null);
    try std.testing.expect(checkedPhysicalExtent(0, MULTIBOOT2_INFO_HEADER_BYTES) == null);
}

test "command line parsing requires exact flags and unique integer keys" {
    try std.testing.expect(commandLineHasFlagBytes("model_inventory qemu_tsc_frequency_hz=2400000000", "model_inventory"));
    try std.testing.expect(!commandLineHasFlagBytes("not_model_inventory", "model_inventory"));
    try std.testing.expectEqual(
        @as(?u64, 2_400_000_000),
        commandLineU64Bytes("model_inventory qemu_tsc_frequency_hz=2400000000", "qemu_tsc_frequency_hz"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        commandLineU64Bytes("not_qemu_tsc_frequency_hz=1", "qemu_tsc_frequency_hz"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        commandLineU64Bytes("qemu_tsc_frequency_hz=1 qemu_tsc_frequency_hz=2", "qemu_tsc_frequency_hz"),
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        commandLineU64Bytes("qemu_tsc_frequency_hz=invalid", "qemu_tsc_frequency_hz"),
    );
}

test "captured Multiboot APIs reject wrapping outer extents before dereference" {
    const prior_magic = zigos_multiboot_magic;
    const prior_info_address = zigos_multiboot_info_addr;
    defer {
        zigos_multiboot_magic = prior_magic;
        zigos_multiboot_info_addr = prior_info_address;
    }

    zigos_multiboot_magic = MULTIBOOT2_BOOTLOADER_MAGIC;
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
        .info_bytes = MULTIBOOT2_INFO_HEADER_BYTES,
        .cmdline_length = 512,
        .mmap_entry_size = MULTIBOOT2_MMAP_ENTRY_BYTES,
    };
    try std.testing.expect(capturedMemoryMap(info) == null);
    try std.testing.expect(capturedMemoryMapSummary(info) == null);
    try std.testing.expect(!commandLineHasFlag(info, "model_inventory"));
}

test "Multiboot2 handoff validates rgb framebuffer descriptors" {
    const info = Info{
        .flags = FLAG_FRAMEBUFFER,
        .mem_lower_kib = 0,
        .mem_upper_kib = 0,
        .cmdline_addr = 0,
        .mmap_length = 0,
        .mmap_addr = 0,
        .framebuffer_addr = 0x8000_0000,
        .framebuffer_pitch = 1920 * 4,
        .framebuffer_width = 1920,
        .framebuffer_height = 1080,
        .framebuffer_bpp = 32,
        .framebuffer_type = 1,
        .framebuffer_rgb = .{ 16, 8, 8, 8, 0, 8 },
        .info_bytes = MULTIBOOT2_INFO_HEADER_BYTES,
        .cmdline_length = 0,
        .mmap_entry_size = MULTIBOOT2_MMAP_ENTRY_BYTES,
    };
    const fb = try framebufferInfo(info);
    try std.testing.expectEqual(@as(u64, 0x8000_0000), fb.physical_address);
    try std.testing.expectEqual(@as(u32, 1920), fb.width);
    try std.testing.expectEqual(@as(u32, 1080), fb.height);
}
