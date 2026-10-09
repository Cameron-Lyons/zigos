const std = @import("std");
const endian = @import("bytes.zig");
const kernel_address = @import("../arch/kernel_address.zig");

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
pub const MAX_LOAD_END: u64 = kernel_address.image_physical_limit;
pub const IMAGE_VIRTUAL_BIAS: u64 = kernel_address.image_virtual_bias;

pub const Mode = enum { native_high, isolated_low_proof };

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
    return parseForMode(bytes, .native_high);
}

pub fn parseForMode(bytes: []const u8, mode: Mode) Error!Image {
    if (bytes.len < 64) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &EI_MAG)) return error.InvalidMagic;
    if (bytes[4] != ELFCLASS64 or bytes[5] != ELFDATA2LSB or bytes[6] != 1) return error.UnsupportedClass;
    if (readU16(bytes[16..18]) != ET_EXEC) return error.UnsupportedType;
    if (readU16(bytes[18..20]) != EM_X86_64 or readU32(bytes[20..24]) != 1 or readU16(bytes[52..54]) != 64) return error.UnsupportedMachine;

    var image = Image{ .entry = readU64(bytes[24..32]) };
    const virtual_bias: u64 = if (mode == .native_high) IMAGE_VIRTUAL_BIAS else 0;
    if (image.entry < virtual_bias or image.entry - virtual_bias >= MAX_LOAD_END) return error.InvalidSegment;

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
        const alignment = readU64(header[48..56]);
        const phys = paddr;
        if (phys >= MAX_LOAD_END or vaddr != virtual_bias + phys or phys % 4096 != 0 or mem_size == 0 or
            (flags != PF_R and flags != (PF_R | PF_X) and flags != (PF_R | PF_W)))
            return error.InvalidSegment;
        if (alignment > 1 and (!std.math.isPowerOfTwo(alignment) or vaddr % alignment != file_offset % alignment)) return error.InvalidSegment;
        const load_end = std.math.add(u64, phys, mem_size) catch return error.AddressOverflow;
        if (phys < 0x100000 or load_end > MAX_LOAD_END or mem_size < file_size) return error.InvalidSegment;
        const file_end = std.math.add(u64, file_offset, file_size) catch return error.AddressOverflow;
        if (file_end > bytes.len) return error.Truncated;

        const page_end = std.mem.alignForward(u64, load_end, 4096);
        for (image.segments[0..image.segment_count]) |existing| {
            const existing_end = existing.phys_addr + existing.pageCount() * 4096;
            if (phys < existing_end and existing.phys_addr < page_end) return error.InvalidSegment;
        }
        // Only file-backed executable bytes can admit entry. Every load is
        // checked before the caller reserves pages or writes any image bytes.
        if (flags & PF_X != 0 and image.entry >= vaddr and image.entry - vaddr < file_size) entry_loaded = true;
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
    try std.testing.expectEqual(IMAGE_VIRTUAL_BIAS + 0x100000, image.entry);
    try std.testing.expectEqual(@as(usize, 1), image.segment_count);
    try std.testing.expectEqual(@as(u64, 0x100000), image.segments[0].phys_addr);
    try std.testing.expectEqual(@as(usize, 1), image.segments[0].pageCount());
}

test "ELF64 parser rejects unsafe layouts before physical allocation" {
    const cases = [_]struct { offset: usize, value: u64, expected: Error }{
        .{ .offset = 24, .value = IMAGE_VIRTUAL_BIAS + 0x100040, .expected = error.InvalidSegment }, // Entry in BSS.
        .{ .offset = 24, .value = IMAGE_VIRTUAL_BIAS + 0x200000, .expected = error.InvalidSegment }, // Entry outside loads.
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
    writeU64(bytes[80..88], IMAGE_VIRTUAL_BIAS + 0x100001);
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
    writeU64(bytes[136..144], IMAGE_VIRTUAL_BIAS + 0x101000);
    writeU64(bytes[144..152], 0x101000);
    const adjacent = try parse(&bytes);
    try std.testing.expectEqual(@as(usize, 2), adjacent.segment_count);
    writeU64(bytes[104..112], 4097);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    writeU64(bytes[104..112], 4096);
    writeU64(bytes[136..144], IMAGE_VIRTUAL_BIAS + 0x100000);
    writeU64(bytes[144..152], 0x100000);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
}

test "ELF64 parser admits disjoint RX RO and RW loads with executable file-backed entry" {
    var bytes = testSplitImage();
    const image = try parse(&bytes);
    try std.testing.expectEqual(@as(usize, 3), image.segment_count);
    for ([_]u32{ PF_R | PF_X, PF_R, PF_R | PF_W }, image.segments[0..3]) |flags, segment| {
        try std.testing.expectEqual(flags, segment.flags);
        try std.testing.expectEqual(@as(usize, 1), segment.pageCount());
    }
    // The writable tail can be BSS without authorizing entry there.
    writeU64(bytes[96 + 2 * 56 ..][0..8], 0);
    _ = try parse(&bytes);
    for ([_]u64{ 0x100040, 0x101000, 0x102000 }) |physical_entry| {
        writeU64(bytes[24..32], IMAGE_VIRTUAL_BIAS + physical_entry);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    }
}

test "ELF64 parser checks every segment permission even after admitting entry" {
    for (0..3) |segment_index| {
        for ([_]u32{ 0, PF_X, PF_W, PF_W | PF_X, PF_R | PF_W | PF_X, PF_R | 8, 0x8000_0004 }) |flags| {
            var bytes = testSplitImage();
            writeU32(bytes[68 + segment_index * 56 ..][0..4], flags);
            try std.testing.expectError(error.InvalidSegment, parse(&bytes));
        }
    }
    // A readable or writable first load cannot admit entry either.
    for ([_]u32{ PF_R, PF_R | PF_W }) |flags| {
        var bytes = testSplitImage();
        writeU32(bytes[68..72], flags);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
        // The same proof policy applies to explicit isolated low images.
        writeU64(bytes[24..32], 0x100000);
        for (0..3) |index| writeU64(bytes[80 + index * 56 ..][0..8], 0x100000 + index * 4096);
        try std.testing.expectError(error.InvalidSegment, parseForMode(&bytes, .isolated_low_proof));
    }
}

test "ELF64 parser rejects a malformed or overlapping tail after valid executable entry" {
    var bytes = testSplitImage();
    // Overlap crosses RO/RW permission boundaries, including page padding.
    writeU64(bytes[104 + 56 ..][0..8], 4097);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    bytes = testSplitImage();
    writeU64(bytes[80 + 2 * 56 ..][0..8], IMAGE_VIRTUAL_BIAS + 0x100000);
    writeU64(bytes[88 + 2 * 56 ..][0..8], 0x100000);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    bytes = testSplitImage();
    writeU64(bytes[72 + 2 * 56 ..][0..8], bytes.len - 1);
    try std.testing.expectError(error.Truncated, parse(&bytes));
    bytes = testSplitImage();
    try std.testing.expectError(error.Truncated, parse(bytes[0 .. 64 + 3 * 56 - 1]));
}

test "ELF64 native loader admits only the fixed upper image alias and bounded physical loads" {
    for ([_]u64{ 0x100000, 0x0000_8000_0010_0000, 0xffff_8000_0010_0000, IMAGE_VIRTUAL_BIAS + MAX_LOAD_END }) |entry| {
        var bytes = testImage();
        writeU64(bytes[24..32], entry);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    }
    for ([_]u64{ 0x100000, 0xffff_8000_0010_0000, IMAGE_VIRTUAL_BIAS + 0x200000 }) |virtual| {
        var bytes = testImage();
        writeU64(bytes[80..88], virtual);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    }
    for ([_]u64{ MAX_LOAD_END, IMAGE_VIRTUAL_BIAS + 0x100000, std.math.maxInt(u64) }) |physical| {
        var bytes = testImage();
        writeU64(bytes[88..96], physical);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    }
    var bytes = testImage();
    const last_page = MAX_LOAD_END - 4096;
    writeU64(bytes[24..32], IMAGE_VIRTUAL_BIAS + last_page);
    writeU64(bytes[80..88], IMAGE_VIRTUAL_BIAS + last_page);
    writeU64(bytes[88..96], last_page);
    try std.testing.expectEqual(last_page, (try parse(&bytes)).segments[0].phys_addr);
    writeU64(bytes[104..112], 4097);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
}

test "ELF64 low image admission requires the explicit isolated proof mode" {
    var bytes = testImage();
    try std.testing.expectError(error.InvalidSegment, parseForMode(&bytes, .isolated_low_proof));
    writeU64(bytes[24..32], 0x100000);
    writeU64(bytes[80..88], 0x100000);
    try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    const proof = try parseForMode(&bytes, .isolated_low_proof);
    try std.testing.expectEqual(@as(u64, 0x100000), proof.entry);
    try std.testing.expectEqual(@as(u64, 0x100000), proof.segments[0].phys_addr);
}

test "ELF64 parser enforces declared alignment before allocation" {
    for ([_]u64{ 3, 128, 4096, std.math.maxInt(u64) }) |alignment| {
        var bytes = testImage();
        writeU64(bytes[112..120], alignment);
        try std.testing.expectError(error.InvalidSegment, parse(&bytes));
    }
    for ([_]u64{ 0, 1, 64 }) |alignment| {
        var bytes = testImage();
        writeU64(bytes[112..120], alignment);
        _ = try parse(&bytes);
    }
}

fn testImage() [256]u8 {
    var bytes = @as([256]u8, @splat(0));
    @memcpy(bytes[0..4], &EI_MAG);
    bytes[4] = ELFCLASS64;
    bytes[5] = ELFDATA2LSB;
    bytes[6] = 1;
    writeU16(bytes[16..18], ET_EXEC);
    writeU16(bytes[18..20], EM_X86_64);
    writeU32(bytes[20..24], 1);
    writeU64(bytes[24..32], IMAGE_VIRTUAL_BIAS + 0x100000);
    writeU64(bytes[32..40], 64);
    writeU16(bytes[52..54], 64);
    writeU16(bytes[54..56], 56);
    writeU16(bytes[56..58], 1);
    writeU32(bytes[64..68], PT_LOAD);
    writeU32(bytes[68..72], PF_R | PF_X);
    writeU64(bytes[72..80], 192);
    writeU64(bytes[80..88], IMAGE_VIRTUAL_BIAS + 0x100000);
    writeU64(bytes[88..96], 0x100000);
    writeU64(bytes[96..104], 64);
    writeU64(bytes[104..112], 4096);
    return bytes;
}

fn testSplitImage() [512]u8 {
    var bytes: [512]u8 = @splat(0);
    const single = testImage();
    @memcpy(bytes[0..single.len], &single);
    writeU16(bytes[56..58], 3);
    for ([_]u32{ PF_R | PF_X, PF_R, PF_R | PF_W }, 0..) |flags, index| {
        const header = bytes[64 + index * 56 ..][0..56];
        @memcpy(header, single[64..120]);
        writeU32(header[4..8], flags);
        writeU64(header[8..16], 320 + index * 64);
        writeU64(header[16..24], IMAGE_VIRTUAL_BIAS + 0x100000 + index * 4096);
        writeU64(header[24..32], 0x100000 + index * 4096);
    }
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
