const std = @import("std");
const endian = @import("bytes.zig");

const readU16 = endian.readU16Le;
const readU32 = endian.readU32Le;
const readU64 = endian.readU64Le;

pub const EI_MAG = [_]u8{ 0x7F, 'E', 'L', 'F' };
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_X86_64: u16 = 62;
pub const ET_EXEC: u16 = 2;
pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const MAX_LOAD_SEGMENTS: usize = 8;
pub const MAX_LOAD_END: u64 = 1024 * 1024 * 1024;

pub const Error = error{
    Truncated,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedMachine,
    UnsupportedType,
    TooManySegments,
    InvalidSegment,
    AddressOverflow,
};

pub const Segment = struct {
    file_offset: u64,
    file_size: u64,
    phys_addr: u64,
    mem_size: u64,
    flags: u32,

    pub fn pageCount(self: Segment) usize {
        return @intCast((self.mem_size + 4095) / 4096);
    }
};

pub const Image = struct {
    entry: u64,
    segments: [MAX_LOAD_SEGMENTS]Segment = undefined,
    segment_count: usize = 0,
};

pub fn parse(bytes: []const u8) Error!Image {
    if (bytes.len < 64) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &EI_MAG)) return error.InvalidMagic;
    if (bytes[4] != ELFCLASS64 or bytes[5] != ELFDATA2LSB or bytes[6] != 1) return error.UnsupportedClass;
    if (readU16(bytes[16..18]) != ET_EXEC) return error.UnsupportedType;
    if (readU16(bytes[18..20]) != EM_X86_64 or readU32(bytes[20..24]) != 1 or readU16(bytes[52..54]) != 64) return error.UnsupportedMachine;

    var image = Image{ .entry = readU64(bytes[24..32]) };
    if (image.entry == 0 or image.entry >= MAX_LOAD_END) return error.InvalidSegment;

    const phoff = readU64(bytes[32..40]);
    const phentsize = readU16(bytes[54..56]);
    const phnum = readU16(bytes[56..58]);
    if (phentsize != 56 or phnum == 0 or phnum > 32) return error.InvalidSegment;

    var entry_loaded = false;
    var index: u16 = 0;
    while (index < phnum) : (index += 1) {
        const start = std.math.add(u64, phoff, @as(u64, index) * phentsize) catch
            return error.AddressOverflow;
        const end = std.math.add(u64, start, phentsize) catch return error.AddressOverflow;
        if (end > bytes.len) return error.Truncated;
        const header = bytes[@intCast(start)..@intCast(end)];
        if (readU32(header[0..4]) != PT_LOAD) continue;
        if (image.segment_count == MAX_LOAD_SEGMENTS) return error.TooManySegments;

        const file_offset = readU64(header[8..16]);
        const vaddr = readU64(header[16..24]);
        const paddr = readU64(header[24..32]);
        const file_size = readU64(header[32..40]);
        const mem_size = readU64(header[40..48]);
        const flags = readU32(header[4..8]);
        const phys = paddr;
        if (vaddr != phys or phys % 4096 != 0 or mem_size == 0 or flags & ~@as(u32, 7) != 0 or flags & PF_R == 0)
            return error.InvalidSegment;
        const load_end = std.math.add(u64, phys, mem_size) catch return error.AddressOverflow;
        if (phys < 0x100000 or load_end > MAX_LOAD_END or mem_size < file_size) return error.InvalidSegment;
        const file_end = std.math.add(u64, file_offset, file_size) catch return error.AddressOverflow;
        if (file_end > bytes.len) return error.Truncated;

        const page_end = std.mem.alignForward(u64, load_end, 4096);
        for (image.segments[0..image.segment_count]) |existing| {
            const existing_end = existing.phys_addr + existing.pageCount() * 4096;
            if (phys < existing_end and existing.phys_addr < page_end) return error.InvalidSegment;
        }
        if (image.entry >= phys and image.entry - phys < file_size) entry_loaded = true;
        image.segments[image.segment_count] = .{
            .file_offset = file_offset,
            .file_size = file_size,
            .phys_addr = phys,
            .mem_size = mem_size,
            .flags = flags,
        };
        image.segment_count += 1;
    }
    if (image.segment_count == 0 or !entry_loaded) return error.InvalidSegment;
    return image;
}

pub fn load(bytes: []const u8, image: Image) void {
    var index: usize = 0;
    while (index < image.segment_count) : (index += 1) {
        const segment = image.segments[index];
        const dest: [*]u8 = @ptrFromInt(@as(usize, @intCast(segment.phys_addr)));
        const file_off: usize = @intCast(segment.file_offset);
        const file_size: usize = @intCast(segment.file_size);
        const mem_size: usize = @intCast(segment.mem_size);
        @memcpy(dest[0..file_size], bytes[file_off..][0..file_size]);
        if (mem_size > file_size) @memset(dest[file_size..mem_size], 0);
    }
}

test "ELF64 parser accepts a minimal executable load segment" {
    const bytes = testImage();
    const image = try parse(&bytes);
    try std.testing.expectEqual(@as(u64, 0x100000), image.entry);
    try std.testing.expectEqual(@as(usize, 1), image.segment_count);
    try std.testing.expectEqual(@as(u64, 0x100000), image.segments[0].phys_addr);
    try std.testing.expectEqual(@as(usize, 1), image.segments[0].pageCount());
}

test "ELF64 parser rejects unsafe layouts before physical allocation" {
    const cases = [_]struct { offset: usize, value: u64, expected: Error }{
        .{ .offset = 24, .value = 0x100040, .expected = error.InvalidSegment }, // Entry in BSS.
        .{ .offset = 24, .value = 0x200000, .expected = error.InvalidSegment }, // Entry outside loads.
        .{ .offset = 32, .value = std.math.maxInt(u64) - 8, .expected = error.AddressOverflow },
        .{ .offset = 72, .value = std.math.maxInt(u64) - 8, .expected = error.AddressOverflow },
        .{ .offset = 72, .value = 250, .expected = error.Truncated },
        .{ .offset = 80, .value = 0x200000, .expected = error.InvalidSegment }, // Virtual alias.
        .{ .offset = 88, .value = 0, .expected = error.InvalidSegment }, // No fallback to virtual address.
        .{ .offset = 96, .value = 4097, .expected = error.InvalidSegment }, // File larger than memory.
        .{ .offset = 104, .value = 0, .expected = error.InvalidSegment },
        .{ .offset = 104, .value = MAX_LOAD_END, .expected = error.InvalidSegment },
        .{ .offset = 104, .value = std.math.maxInt(u64), .expected = error.AddressOverflow },
    };
    for (cases) |case| {
        var bytes = testImage();
        writeU64(bytes[case.offset..][0..8], case.value);
        try std.testing.expectError(case.expected, parse(&bytes));
    }
    var bytes = testImage();
    try std.testing.expectError(error.Truncated, parse(bytes[0..63]));
    try std.testing.expectError(error.Truncated, parse(bytes[0..255]));
    writeU64(bytes[80..88], 0x100001);
    writeU64(bytes[88..96], 0x100001);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    for ([_]u32{ PF_X, PF_R | 8, 0 }) |flags| {
        bytes = testImage();
        writeU32(bytes[68..72], flags);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    }
    for ([_]usize{ 6, 20, 52, 54, 56 }) |offset| {
        bytes = testImage();
        bytes[offset] = 0;
        if (parse(&bytes)) |_| return error.TestUnexpectedResult else |_| {}
    }
}

test "ELF64 parser rejects page overlap and accepts adjacent reservations" {
    var bytes = testImage();
    writeU16(bytes[56..58], 2);
    @memcpy(bytes[120..176], bytes[64..120]);
    writeU64(bytes[136..144], 0x101000);
    writeU64(bytes[144..152], 0x101000);
    const adjacent = try parse(&bytes);
    try std.testing.expectEqual(@as(usize, 2), adjacent.segment_count);
    writeU64(bytes[104..112], 4097);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    writeU64(bytes[104..112], 4096);
    writeU64(bytes[136..144], 0x100000);
    writeU64(bytes[144..152], 0x100000);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
}

fn testImage() [256]u8 {
    var bytes = [_]u8{0} ** 256;
    @memcpy(bytes[0..4], &EI_MAG);
    bytes[4] = ELFCLASS64;
    bytes[5] = ELFDATA2LSB;
    bytes[6] = 1;
    writeU16(bytes[16..18], ET_EXEC);
    writeU16(bytes[18..20], EM_X86_64);
    writeU32(bytes[20..24], 1);
    writeU64(bytes[24..32], 0x100000);
    writeU64(bytes[32..40], 64);
    writeU16(bytes[52..54], 64);
    writeU16(bytes[54..56], 56);
    writeU16(bytes[56..58], 1);
    writeU32(bytes[64..68], PT_LOAD);
    writeU32(bytes[68..72], PF_R | PF_X);
    writeU64(bytes[72..80], 192);
    writeU64(bytes[80..88], 0x100000);
    writeU64(bytes[88..96], 0x100000);
    writeU64(bytes[96..104], 64);
    writeU64(bytes[104..112], 4096);
    return bytes;
}

fn writeU16(bytes: []u8, value: u16) void {
    endian.writeU16Le(bytes, value);
}

fn writeU32(bytes: []u8, value: u32) void {
    endian.writeU32Le(bytes, value);
}

fn writeU64(bytes: []u8, value: u64) void {
    endian.writeU64Le(bytes, value);
}
