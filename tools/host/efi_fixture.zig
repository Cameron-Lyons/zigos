//! Firmware-authenticated originals and independently tampered unified images.
const std = @import("std");
const common = @import("common.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn run(ctx: *common.Context, args: []const []const u8) !void {
    try common.requireArgs(args, 4, 4);
    const image = try ctx.read(args[0]);
    const kernel = try ctx.read(args[1]);
    const cmdline = try ctx.read(args[2]);
    const fixture = try prepare(ctx.allocator, image, kernel, cmdline);
    try ctx.mkdir(args[3]);
    const digest = std.fmt.bytesToHex(fixture.digest, .lower);
    try ctx.write(try ctx.fmt("{s}/image.sha256", .{args[3]}), try ctx.fmt("{s}\n", .{digest}));
    try ctx.write(try ctx.fmt("{s}/original.efi", .{args[3]}), image);
    for ([_][]const u8{ "kernel", "cmdline" }, fixture.offsets) |name, offset| {
        image[offset] ^= 1;
        defer image[offset] ^= 1;
        try ctx.write(try ctx.fmt("{s}/tampered-{s}.efi", .{ args[3], name }), image);
    }
}

const Fixture = struct {
    digest: [32]u8,
    offsets: [2]usize,
};

/// Verify both mutations before publishing any fixture files. Their full source
/// payloads must each occur once inside one section that survives image loading.
fn prepare(allocator: std.mem.Allocator, image: []u8, kernel: []const u8, cmdline: []const u8) !Fixture {
    const pe = try Pe.parse(allocator, image);
    defer allocator.free(pe.sections);
    const kernel_start = try pe.retainedPayload(image, kernel);
    const cmdline_start = try pe.retainedPayload(image, cmdline);
    const fixture: Fixture = .{
        .digest = pe.hash(image),
        .offsets = .{ kernel_start + try elfEntryOffset(kernel), cmdline_start },
    };
    for (fixture.offsets) |offset| {
        image[offset] ^= 1;
        const tampered_digest = pe.hash(image);
        image[offset] ^= 1;
        if (std.mem.eql(u8, &fixture.digest, &tampered_digest)) return error.MutationOutsideFirmwareHash;
    }
    return fixture;
}

const Section = struct {
    offset: usize,
    size: usize,
    discardable: bool,

    fn lessThan(_: void, lhs: Section, rhs: Section) bool {
        return lhs.offset < rhs.offset;
    }
};

const Pe = struct {
    checksum: usize,
    security_directory: ?usize,
    header_size: usize,
    certificate_start: usize,
    sections: []Section,

    fn parse(allocator: std.mem.Allocator, image: []const u8) !Pe {
        if (image.len < 64 or !std.mem.eql(u8, image[0..2], "MZ")) return error.InvalidMzHeader;
        const pe_offset: usize = try read(u32, image, 60);
        if (pe_offset < 64) return error.InvalidPeHeader;
        const coff = try range(image, pe_offset, 24);
        if (!std.mem.eql(u8, coff[0..4], "PE\x00\x00")) return error.InvalidPeHeader;
        const section_count = try read(u16, coff, 6);
        const optional_size = try read(u16, coff, 20);
        const optional_offset = pe_offset + 24;
        const optional = try range(image, optional_offset, optional_size);
        const directory_offset: usize = switch (try read(u16, optional, 0)) {
            0x10b => 96, // PE32
            0x20b => 112, // PE32+
            else => return error.InvalidOptionalHeader,
        };
        if (optional.len < directory_offset) return error.TruncatedPeImage;
        const directory_count = try read(u32, optional, directory_offset - 4);
        if (directory_count > (optional.len - directory_offset) / 8) return error.TruncatedPeImage;
        const section_offset = optional_offset + optional_size;
        const section_bytes = try range(image, section_offset, @as(usize, section_count) * 40);
        const header_size: usize = try read(u32, optional, 60);
        if (header_size < section_offset + section_bytes.len or header_size > image.len) return error.InvalidPeHeaderSize;
        const security_directory: ?usize = if (directory_count > 4) optional_offset + directory_offset + 4 * 8 else null;
        var certificate_start = image.len;
        if (security_directory) |offset| {
            const certificate_offset: usize = try read(u32, image, offset);
            const certificate_size: usize = try read(u32, image, offset + 4);
            if ((certificate_offset == 0) != (certificate_size == 0)) return error.InvalidCertificateTable;
            if (certificate_size != 0) {
                _ = try range(image, certificate_offset, certificate_size);
                // OVMF's Authenticode algorithm subtracts certificate size from
                // EOF. Reject other placements rather than silently exclude
                // unrelated bytes or hash the declared certificate table.
                if (certificate_offset < header_size or certificate_offset % 8 != 0 or certificate_size != image.len - certificate_offset) return error.InvalidCertificateTable;
                certificate_start = certificate_offset;
            }
        }

        const sections = try allocator.alloc(Section, section_count);
        errdefer allocator.free(sections);
        for (sections, 0..) |*section, index| {
            const header = section_bytes[index * 40 ..][0..40];
            section.* = .{
                .offset = try read(u32, header, 20),
                .size = try read(u32, header, 16),
                .discardable = (try read(u32, header, 36)) & 0x02000000 != 0,
            };
            if (section.size == 0) continue;
            _ = try range(image, section.offset, section.size);
            if (section.offset < header_size or section.offset > certificate_start or section.size > certificate_start - section.offset) return error.InvalidPeSection;
        }
        std.mem.sort(Section, sections, {}, Section.lessThan);
        var previous_end = header_size;
        for (sections) |section| {
            if (section.size == 0) continue;
            if (section.offset < previous_end) return error.OverlappingPeSections;
            previous_end = section.offset + section.size;
        }
        return .{
            .checksum = optional_offset + 64,
            .security_directory = security_directory,
            .header_size = header_size,
            .certificate_start = certificate_start,
            .sections = sections,
        };
    }

    /// PE/COFF Authenticode Appendix A, also used by EDK2 HashPeImage:
    /// https://github.com/tianocore/edk2/blob/master/SecurityPkg/Library/DxeImageVerificationLib/DxeImageVerificationLib.c
    /// The final range starts at the sum of hashed header/section sizes, rather
    /// than the last section's end; preserve that firmware behavior for gaps.
    fn hash(pe: Pe, image: []const u8) [32]u8 {
        var state = Sha256.init(.{});
        state.update(image[0..pe.checksum]);
        if (pe.security_directory) |offset| {
            state.update(image[pe.checksum + 4 .. offset]);
            state.update(image[offset + 8 .. pe.header_size]);
        } else state.update(image[pe.checksum + 4 .. pe.header_size]);
        var sum = pe.header_size;
        for (pe.sections) |section| {
            if (section.size == 0) continue;
            state.update(image[section.offset .. section.offset + section.size]);
            sum += section.size;
        }
        state.update(image[sum..pe.certificate_start]);
        var digest: [32]u8 = undefined;
        state.final(&digest);
        return digest;
    }

    fn retainedPayload(pe: Pe, image: []const u8, payload: []const u8) !usize {
        if (payload.len == 0) return error.EmptyEmbeddedPayload;
        const start = std.mem.indexOf(u8, image, payload) orelse return error.MissingEmbeddedPayload;
        if (std.mem.indexOfPos(u8, image, start + 1, payload) != null) return error.DuplicateEmbeddedPayload;
        for (pe.sections) |section| {
            if (section.discardable or start < section.offset) continue;
            const relative = start - section.offset;
            if (relative <= section.size and payload.len <= section.size - relative) return start;
        }
        return error.PayloadOutsideRetainedSection;
    }
};

fn range(bytes: []const u8, offset: usize, size: usize) ![]const u8 {
    if (offset > bytes.len or size > bytes.len - offset) return error.TruncatedPeImage;
    return bytes[offset .. offset + size];
}

fn read(comptime T: type, bytes: []const u8, offset: usize) !T {
    const value = try range(bytes, offset, @sizeOf(T));
    return std.mem.readInt(T, value[0..@sizeOf(T)], .little);
}

fn elfEntryOffset(kernel: []const u8) !usize {
    if (kernel.len < 64 or !std.mem.eql(u8, kernel[0..4], "\x7fELF") or kernel[4] != 2 or kernel[5] != 1 or kernel[6] != 1) return error.InvalidKernelElf;
    if (try read(u16, kernel, 18) != 62 or try read(u32, kernel, 20) != 1 or try read(u16, kernel, 52) != 64) return error.InvalidKernelElf;
    const entry = try read(u64, kernel, 24);
    const table_offset = std.math.cast(usize, try read(u64, kernel, 32)) orelse return error.InvalidKernelElf;
    const record_size: usize = try read(u16, kernel, 54);
    const record_count: usize = try read(u16, kernel, 56);
    if (record_size < 56 or record_count == 0) return error.InvalidKernelElf;
    const table_size = std.math.mul(usize, record_size, record_count) catch return error.InvalidKernelElf;
    const table = range(kernel, table_offset, table_size) catch return error.InvalidKernelElf;
    for (0..record_count) |index| {
        const record = table[index * record_size ..][0..56];
        if (try read(u32, record, 0) != 1) continue; // PT_LOAD
        const file_offset = try read(u64, record, 8);
        const vaddr = try read(u64, record, 16);
        const file_size = try read(u64, record, 32);
        const memory_size = try read(u64, record, 40);
        if (file_size > memory_size or file_offset > kernel.len or file_size > kernel.len - file_offset) return error.InvalidKernelElf;
        if (entry < vaddr or entry - vaddr >= file_size) continue;
        // This addition is bounded by the full segment's checked file range.
        return @intCast(file_offset + (entry - vaddr));
    }
    return error.KernelEntryNotFileBacked;
}

fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn testImage(magic: u16) [0x500]u8 {
    var image: [0x500]u8 = @splat(0);
    @memcpy(image[0..2], "MZ");
    put(u32, &image, 60, 0x80);
    @memcpy(image[0x80..0x84], "PE\x00\x00");
    put(u16, &image, 0x86, 2);
    const optional_size: u16 = if (magic == 0x10b) 224 else 240;
    put(u16, &image, 0x94, optional_size);
    put(u16, &image, 0x98, magic);
    put(u32, &image, 0x98 + 60, 0x200);
    const directory: usize = 0x98 + @as(usize, if (magic == 0x10b) 96 else 112);
    put(u32, &image, directory - 4, 16);
    put(u32, &image, directory + 32, 0x4f0);
    put(u32, &image, directory + 36, 0x10);
    const sections = 0x98 + @as(usize, optional_size);
    // Deliberately reverse section-table order relative to raw file offsets.
    @memcpy(image[sections..][0..7], ".second");
    put(u32, &image, sections + 16, 0x100);
    put(u32, &image, sections + 20, 0x300);
    @memcpy(image[sections + 40 ..][0..6], ".first");
    put(u32, &image, sections + 40 + 16, 0x100);
    put(u32, &image, sections + 40 + 20, 0x200);
    @memset(image[0x200..0x300], 0xa3);
    @memset(image[0x300..0x400], 0xb7);
    @memset(image[0x400..0x4f0], 0xc5);
    @memset(image[0x4f0..], 0xd9);
    return image;
}

fn testKernel() [0xa0]u8 {
    var kernel: [0xa0]u8 = @splat(0);
    @memcpy(kernel[0..4], "\x7fELF");
    kernel[4] = 2;
    kernel[5] = 1;
    kernel[6] = 1;
    put(u16, &kernel, 18, 62);
    put(u32, &kernel, 20, 1);
    put(u64, &kernel, 24, 0x100004);
    put(u64, &kernel, 32, 64);
    put(u16, &kernel, 52, 64);
    put(u16, &kernel, 54, 56);
    put(u16, &kernel, 56, 1);
    put(u32, &kernel, 64, 1);
    put(u64, &kernel, 64 + 8, 0x80);
    put(u64, &kernel, 64 + 16, 0x100000);
    put(u64, &kernel, 64 + 32, 0x20);
    put(u64, &kernel, 64 + 40, 0x40);
    @memset(kernel[0x80..], 0x90);
    return kernel;
}

test "Authenticode hashes raw sections in file order, excludes checksum and certificates, and includes overlay" {
    for ([_]u16{ 0x10b, 0x20b }) |magic| {
        var image = testImage(magic);
        const pe = try Pe.parse(std.testing.allocator, &image);
        defer std.testing.allocator.free(pe.sections);
        const original = pe.hash(&image);
        // Independently assemble the expected byte stream using fixed fixture
        // offsets; this catches section ordering and all header exclusions.
        var expected_hash = Sha256.init(.{});
        expected_hash.update(image[0..0xd8]);
        const security: usize = if (magic == 0x10b) 0x118 else 0x128;
        expected_hash.update(image[0xdc..security]);
        expected_hash.update(image[security + 8 .. 0x200]);
        expected_hash.update(image[0x200..0x4f0]);
        var expected: [32]u8 = undefined;
        expected_hash.final(&expected);
        try std.testing.expectEqualSlices(u8, &expected, &original);
        image[0xd8] ^= 0xff;
        image[0x4f8] ^= 0xff;
        try std.testing.expectEqualSlices(u8, &original, &pe.hash(&image));
        for ([_]usize{ 0x40, 0x210, 0x310, 0x410 }) |offset| {
            image[offset] ^= 1;
            try std.testing.expect(!std.mem.eql(u8, &original, &pe.hash(&image)));
            image[offset] ^= 1;
        }
        // Adding a signature changes the excluded directory and appends the
        // excluded certificate bytes, leaving the Authenticode digest stable.
        put(u32, &image, security, 0);
        put(u32, &image, security + 4, 0);
        const unsigned = try Pe.parse(std.testing.allocator, image[0..0x4f0]);
        defer std.testing.allocator.free(unsigned.sections);
        try std.testing.expectEqualSlices(u8, &original, &unsigned.hash(image[0..0x4f0]));
    }
}

test "Authenticode handles missing security directory and section gaps using firmware size sum" {
    var image = testImage(0x20b);
    put(u32, &image, 0x98 + 108, 4);
    put(u32, &image, 0x188 + 40 + 16, 0x80);
    const pe = try Pe.parse(std.testing.allocator, &image);
    defer std.testing.allocator.free(pe.sections);
    var expected_hash = Sha256.init(.{});
    expected_hash.update(image[0..0xd8]);
    expected_hash.update(image[0xdc..0x200]);
    expected_hash.update(image[0x200..0x280]);
    expected_hash.update(image[0x300..0x400]);
    expected_hash.update(image[0x380..0x500]);
    var expected: [32]u8 = undefined;
    expected_hash.final(&expected);
    try std.testing.expectEqualSlices(u8, &expected, &pe.hash(&image));
}

test "unified fixture mutates the file-backed ELF entry and complete retained command line" {
    var image = testImage(0x20b);
    const kernel = testKernel();
    const cmdline = "firmware fixture";
    @memcpy(image[0x210..][0..kernel.len], &kernel);
    @memcpy(image[0x310..][0..cmdline.len], cmdline);
    const before = image;
    const fixture = try prepare(std.testing.allocator, &image, &kernel, cmdline);
    try std.testing.expectEqual(@as(usize, 0x294), fixture.offsets[0]);
    try std.testing.expectEqual(@as(usize, 0x310), fixture.offsets[1]);
    try std.testing.expectEqualSlices(u8, &before, &image);
    put(u32, &image, 0x188 + 36, 0x02000000);
    try std.testing.expectError(error.PayloadOutsideRetainedSection, prepare(std.testing.allocator, &image, &kernel, cmdline));
}

test "fixture command writes the original hash and two independent one-byte mutations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environ = std.process.Environ.Map.init(arena.allocator());
    defer environ.deinit();
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environ };
    const temporary = try ctx.tempDir("zigos-efi-fixture-test");
    defer ctx.removeTree(temporary) catch {};
    const image_path = try ctx.fmt("{s}/input.efi", .{temporary});
    const kernel_path = try ctx.fmt("{s}/kernel.elf", .{temporary});
    const cmdline_path = try ctx.fmt("{s}/cmdline", .{temporary});
    const output_path = try ctx.fmt("{s}/nested/output", .{temporary});
    var image = testImage(0x20b);
    const kernel = testKernel();
    const cmdline = "firmware fixture";
    @memcpy(image[0x210..][0..kernel.len], &kernel);
    @memcpy(image[0x310..][0..cmdline.len], cmdline);
    const fixture = try prepare(arena.allocator(), &image, &kernel, cmdline);
    try ctx.write(image_path, &image);
    try ctx.write(kernel_path, &kernel);
    try ctx.write(cmdline_path, cmdline);
    try run(&ctx, &.{ image_path, kernel_path, cmdline_path, output_path });
    try std.testing.expectEqualSlices(u8, &image, try ctx.read(try ctx.fmt("{s}/original.efi", .{output_path})));
    const digest = std.fmt.bytesToHex(fixture.digest, .lower);
    try std.testing.expectEqualStrings(try ctx.fmt("{s}\n", .{digest}), try ctx.read(try ctx.fmt("{s}/image.sha256", .{output_path})));
    for ([_][]const u8{ "kernel", "cmdline" }, fixture.offsets) |name, offset| {
        var expected = image;
        expected[offset] ^= 1;
        try std.testing.expectEqualSlices(u8, &expected, try ctx.read(try ctx.fmt("{s}/tampered-{s}.efi", .{ output_path, name })));
    }
    try std.testing.expectError(error.InvalidArguments, run(&ctx, &.{}));
    try ctx.write(cmdline_path, "");
    const rejected_output = try ctx.fmt("{s}/invalid", .{temporary});
    try std.testing.expectError(error.EmptyEmbeddedPayload, run(&ctx, &.{ image_path, kernel_path, cmdline_path, rejected_output }));
    try std.testing.expect(!ctx.exists(rejected_output));
}

test "embedded payloads must be unique, complete, nonempty and retained" {
    var image = testImage(0x20b);
    @memcpy(image[0x210..0x214], "abcd");
    const pe = try Pe.parse(std.testing.allocator, &image);
    defer std.testing.allocator.free(pe.sections);
    try std.testing.expectEqual(@as(usize, 0x210), try pe.retainedPayload(&image, "abcd"));
    try std.testing.expectError(error.EmptyEmbeddedPayload, pe.retainedPayload(&image, ""));
    try std.testing.expectError(error.MissingEmbeddedPayload, pe.retainedPayload(&image, "abcde"));
    @memcpy(image[0x310..0x314], "abcd");
    try std.testing.expectError(error.DuplicateEmbeddedPayload, pe.retainedPayload(&image, "abcd"));
    @memcpy(image[0x400..0x404], "tail");
    try std.testing.expectError(error.PayloadOutsideRetainedSection, pe.retainedPayload(&image, "tail"));
    @memcpy(image[0x2fe..0x302], "edge");
    try std.testing.expectError(error.PayloadOutsideRetainedSection, pe.retainedPayload(&image, "edge"));
}

test "malformed PE headers, sections and certificate ranges fail without out-of-bounds access" {
    var image = testImage(0x20b);
    for ([_]usize{ 0, 1, 63, 0x80, 0x97, 0x188, 0x1d7, 0x4ff }) |length| {
        const result = Pe.parse(std.testing.allocator, image[0..length]);
        if (result) |pe| {
            std.testing.allocator.free(pe.sections);
            return error.ExpectedMalformedPeRejection;
        } else |_| {}
    }
    put(u32, &image, 60, std.math.maxInt(u32));
    try std.testing.expectError(error.TruncatedPeImage, Pe.parse(std.testing.allocator, &image));
    image = testImage(0x20b);
    put(u32, &image, 0x98 + 60, 0x100);
    try std.testing.expectError(error.InvalidPeHeaderSize, Pe.parse(std.testing.allocator, &image));
    image = testImage(0x20b);
    put(u32, &image, 0x98 + 108, 17);
    try std.testing.expectError(error.TruncatedPeImage, Pe.parse(std.testing.allocator, &image));
    image = testImage(0x20b);
    put(u32, &image, 0x188 + 20, 0x280);
    try std.testing.expectError(error.OverlappingPeSections, Pe.parse(std.testing.allocator, &image));
    image = testImage(0x20b);
    put(u32, &image, 0x188 + 20, std.math.maxInt(u32));
    try std.testing.expectError(error.TruncatedPeImage, Pe.parse(std.testing.allocator, &image));
    image = testImage(0x20b);
    put(u32, &image, 0x188 + 20, 0x4e0);
    put(u32, &image, 0x188 + 16, 0x20);
    try std.testing.expectError(error.InvalidPeSection, Pe.parse(std.testing.allocator, &image));
    image = testImage(0x20b);
    put(u32, &image, 0x128, 0x4e0);
    try std.testing.expectError(error.InvalidCertificateTable, Pe.parse(std.testing.allocator, &image));
    put(u32, &image, 0x128, 0);
    try std.testing.expectError(error.InvalidCertificateTable, Pe.parse(std.testing.allocator, &image));
}

test "ELF entry mutation rejects malformed tables, segments and non-file-backed entry points" {
    var kernel = testKernel();
    try std.testing.expectEqual(@as(usize, 0x84), try elfEntryOffset(&kernel));
    try std.testing.expectError(error.InvalidKernelElf, elfEntryOffset(kernel[0..63]));
    kernel[5] = 2;
    try std.testing.expectError(error.InvalidKernelElf, elfEntryOffset(&kernel));
    kernel = testKernel();
    put(u16, &kernel, 54, 55);
    try std.testing.expectError(error.InvalidKernelElf, elfEntryOffset(&kernel));
    kernel = testKernel();
    put(u64, &kernel, 32, std.math.maxInt(u64));
    try std.testing.expectError(error.InvalidKernelElf, elfEntryOffset(&kernel));
    kernel = testKernel();
    put(u64, &kernel, 64 + 8, 0x90);
    try std.testing.expectError(error.InvalidKernelElf, elfEntryOffset(&kernel));
    kernel = testKernel();
    put(u64, &kernel, 24, 0x100020);
    try std.testing.expectError(error.KernelEntryNotFileBacked, elfEntryOffset(&kernel));
    kernel = testKernel();
    put(u64, &kernel, 64 + 16, std.math.maxInt(u64) - 2);
    try std.testing.expectError(error.KernelEntryNotFileBacked, elfEntryOffset(&kernel));
}
