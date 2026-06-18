const std = @import("std");

pub const Error = error{
    MissingFramebuffer,
    UnsupportedPixelFormat,
    InvalidResolution,
    InvalidStride,
    InvalidAddress,
    BufferTooSmall,
    CaptureTooSmall,
    ExpectedPixelMissing,
    InvalidCaptureRegion,
    InvalidExpectedPixel,
    BlankScanout,
};

pub const PixelFormat = enum {
    rgbx8888,
    bgrx8888,
    bitmask,
};

pub const PixelMask = struct {
    red: u32,
    green: u32,
    blue: u32,
    reserved: u32,
};

const RGBX8888_MASK = PixelMask{
    .red = 0x00FF_0000,
    .green = 0x0000_FF00,
    .blue = 0x0000_00FF,
    .reserved = 0xFF00_0000,
};
const FRAMEBUFFER_32BPP_BYTES: u8 = 4;
const MAX_LINEAR_DIMENSION_PIXELS: u32 = 16_384;
const TEST_FRAMEBUFFER_ADDRESS: u64 = 0x8000_0000;
const GOP_TEST_WIDTH: u32 = 1920;
const GOP_TEST_HEIGHT: u32 = 1080;
const GOP_TEST_STRIDE_PIXELS: u32 = 2048;
const SVGA_TEST_WIDTH: u32 = 1024;
const SVGA_TEST_HEIGHT: u32 = 768;
const SVGA_BAD_STRIDE_PIXELS: u32 = 1000;
const FNV64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01B3;

pub const Info = struct {
    physical_address: u64,
    width: u32,
    height: u32,
    pixels_per_scan_line: u32,
    format: PixelFormat,
    pixel_mask: PixelMask = RGBX8888_MASK,
    buffer_bytes: u64,

    pub fn bytesPerPixel(self: Info) Error!u8 {
        return switch (self.format) {
            .rgbx8888, .bgrx8888 => FRAMEBUFFER_32BPP_BYTES,
            .bitmask => if (valid32BitColorMask(self.pixel_mask)) FRAMEBUFFER_32BPP_BYTES else error.UnsupportedPixelFormat,
        };
    }

    pub fn minimumBufferBytes(self: Info) Error!u64 {
        const bpp = try self.bytesPerPixel();
        return @as(u64, self.pixels_per_scan_line) * @as(u64, self.height) * @as(u64, bpp);
    }
};

pub const ScanoutEvidenceSource = enum(u8) {
    modeled_memory_sample,
    hardware_gop_scanout,
};

pub const HardwareScanoutEvidence = struct {
    source: ScanoutEvidenceSource = .modeled_memory_sample,
    gop_mode_info_reads: u32 = 0,
    framebuffer_base_observations: u32 = 0,
    framebuffer_stride_observations: u32 = 0,
    framebuffer_memory_read_bytes: u64 = 0,
    display_scanout_observations: u32 = 0,
    expected_pixel_observations: u32 = 0,
    captured_scanline_bytes: u64 = 0,
    sink_signal_observations: u32 = 0,

    pub fn verified(self: HardwareScanoutEvidence, proof: ScanoutProof) bool {
        return self.source == .hardware_gop_scanout and
            self.gop_mode_info_reads != 0 and
            self.framebuffer_base_observations != 0 and
            self.framebuffer_stride_observations != 0 and
            self.framebuffer_memory_read_bytes >= proof.captured_bytes and
            self.display_scanout_observations != 0 and
            self.expected_pixel_observations >= proof.expected_pixel_count and
            self.captured_scanline_bytes >= proof.visible_scanline_bytes and
            self.sink_signal_observations != 0;
    }
};

pub const ScanoutProof = struct {
    info: Info,
    captured_bytes: u64,
    visible_scanline_bytes: u64,
    nonzero_bytes: u64,
    expected_pixel: u32,
    expected_pixel_count: u32,
    content_digest: u64,
    hardware_scanout: HardwareScanoutEvidence = .{},

    pub fn verified(self: ScanoutProof) bool {
        const framebuffer = validate(self.info) catch return false;
        const bpp = framebuffer.bytesPerPixel() catch return false;
        const minimum_scanline = @as(u64, framebuffer.width) * @as(u64, bpp);
        const minimum_buffer = framebuffer.minimumBufferBytes() catch return false;
        return self.expected_pixel != 0 and
            self.visible_scanline_bytes == minimum_scanline and
            self.captured_bytes >= minimum_scanline and
            self.captured_bytes <= minimum_buffer and
            self.captured_bytes % @as(u64, bpp) == 0 and
            self.nonzero_bytes > 0 and
            self.expected_pixel_count > 0 and
            self.content_digest != 0;
    }

    pub fn productionHardwareVerified(self: ScanoutProof) bool {
        return self.verified() and self.hardware_scanout.verified(self);
    }
};

pub fn validate(info: ?Info) Error!Info {
    const framebuffer = info orelse return error.MissingFramebuffer;
    if (framebuffer.physical_address == 0) return error.InvalidAddress;
    if (framebuffer.width == 0 or framebuffer.height == 0) return error.InvalidResolution;
    if (framebuffer.width > MAX_LINEAR_DIMENSION_PIXELS or framebuffer.height > MAX_LINEAR_DIMENSION_PIXELS) return error.InvalidResolution;
    if (framebuffer.pixels_per_scan_line < framebuffer.width) return error.InvalidStride;

    const minimum_bytes = try framebuffer.minimumBufferBytes();
    if (framebuffer.buffer_bytes < minimum_bytes) return error.BufferTooSmall;
    return framebuffer;
}

pub fn proveScanout(info: Info, sample: []const u8, expected_pixel: u32) Error!ScanoutProof {
    const framebuffer = try validate(info);
    if (expected_pixel == 0) return error.InvalidExpectedPixel;
    const bpp = try framebuffer.bytesPerPixel();
    const minimum_scanline = @as(u64, framebuffer.width) * @as(u64, bpp);
    const minimum_buffer = try framebuffer.minimumBufferBytes();
    if (sample.len < minimum_scanline) return error.CaptureTooSmall;
    if (sample.len > minimum_buffer or sample.len % bpp != 0) return error.InvalidCaptureRegion;

    var nonzero_bytes: u64 = 0;
    var expected_pixel_count: u32 = 0;
    var pixel_offset: usize = 0;
    while (pixel_offset < sample.len) : (pixel_offset += bpp) {
        const pixel = std.mem.readInt(u32, sample[pixel_offset..][0..4], .little);
        if (pixel == expected_pixel) expected_pixel_count += 1;
    }
    for (sample) |byte| {
        if (byte != 0) nonzero_bytes += 1;
    }
    if (nonzero_bytes == 0) return error.BlankScanout;
    if (expected_pixel_count == 0) return error.ExpectedPixelMissing;

    const proof = ScanoutProof{
        .info = framebuffer,
        .captured_bytes = sample.len,
        .visible_scanline_bytes = minimum_scanline,
        .nonzero_bytes = nonzero_bytes,
        .expected_pixel = expected_pixel,
        .expected_pixel_count = expected_pixel_count,
        .content_digest = scanoutDigest(framebuffer, sample),
    };
    if (!proof.verified()) return error.InvalidCaptureRegion;
    return proof;
}

pub fn textGrid(info: Info, glyph_width: u32, glyph_height: u32) Error!struct { columns: u32, rows: u32 } {
    _ = try validate(info);
    if (glyph_width == 0 or glyph_height == 0) return error.InvalidResolution;
    return .{
        .columns = info.width / glyph_width,
        .rows = info.height / glyph_height,
    };
}

pub fn withHardwareScanoutEvidence(
    proof: ScanoutProof,
    evidence: HardwareScanoutEvidence,
) ScanoutProof {
    var upgraded = proof;
    upgraded.hardware_scanout = evidence;
    return upgraded;
}

fn valid32BitColorMask(mask: PixelMask) bool {
    const combined = mask.red | mask.green | mask.blue | mask.reserved;
    const overlaps = ((mask.red & mask.green) |
        (mask.red & mask.blue) |
        (mask.red & mask.reserved) |
        (mask.green & mask.blue) |
        (mask.green & mask.reserved) |
        (mask.blue & mask.reserved)) != 0;
    return combined != 0 and !overlaps;
}

fn scanoutDigest(info: Info, sample: []const u8) u64 {
    var digest = FNV64_OFFSET;
    digest = hashU64(digest, info.physical_address);
    digest = hashU64(digest, info.width);
    digest = hashU64(digest, info.height);
    digest = hashU64(digest, info.pixels_per_scan_line);
    digest = hashU64(digest, sample.len);
    for (sample) |byte| {
        digest ^= byte;
        digest *%= FNV64_PRIME;
    }
    return digest;
}

fn hashU64(digest: u64, value: anytype) u64 {
    var out = digest;
    var remaining: u64 = @intCast(value);
    var index: u8 = 0;
    while (index < 8) : (index += 1) {
        out ^= @as(u8, @truncate(remaining));
        out *%= FNV64_PRIME;
        remaining >>= 8;
    }
    return out;
}

test "framebuffer validation accepts UEFI GOP-style linear modes" {
    const info = try validate(.{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = GOP_TEST_WIDTH,
        .height = GOP_TEST_HEIGHT,
        .pixels_per_scan_line = GOP_TEST_STRIDE_PIXELS,
        .format = .bgrx8888,
        .buffer_bytes = testLinearBufferBytes(GOP_TEST_STRIDE_PIXELS, GOP_TEST_HEIGHT),
    });
    try std.testing.expectEqual(FRAMEBUFFER_32BPP_BYTES, try info.bytesPerPixel());
    try std.testing.expectEqual(testLinearBufferBytes(GOP_TEST_STRIDE_PIXELS, GOP_TEST_HEIGHT), try info.minimumBufferBytes());
}

test "framebuffer scanout proof requires nonblank expected pixels" {
    const info = try validate(.{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = 64,
        .height = 16,
        .pixels_per_scan_line = 64,
        .format = .bgrx8888,
        .buffer_bytes = testLinearBufferBytes(64, 16),
    });
    const expected_pixel: u32 = 0x00FF_00FF;
    var scanline = [_]u8{0} ** (64 * @as(usize, FRAMEBUFFER_32BPP_BYTES));
    std.mem.writeInt(u32, scanline[0..4], expected_pixel, .little);

    const proof = try proveScanout(info, scanline[0..], expected_pixel);
    try std.testing.expect(proof.verified());
    try std.testing.expect(!proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u64, scanline.len), proof.captured_bytes);
    try std.testing.expectEqual(@as(u32, 1), proof.expected_pixel_count);

    const hardware_proof = withHardwareScanoutEvidence(proof, .{
        .source = .hardware_gop_scanout,
        .gop_mode_info_reads = 1,
        .framebuffer_base_observations = 1,
        .framebuffer_stride_observations = 1,
        .framebuffer_memory_read_bytes = scanline.len,
        .display_scanout_observations = 1,
        .expected_pixel_observations = 1,
        .captured_scanline_bytes = scanline.len,
        .sink_signal_observations = 1,
    });
    try std.testing.expect(hardware_proof.productionHardwareVerified());

    var missing_display_scanout = hardware_proof;
    missing_display_scanout.hardware_scanout.display_scanout_observations = 0;
    try std.testing.expect(!missing_display_scanout.productionHardwareVerified());

    var blank = [_]u8{0} ** (64 * @as(usize, FRAMEBUFFER_32BPP_BYTES));
    try std.testing.expectError(error.BlankScanout, proveScanout(info, blank[0..], expected_pixel));
    std.mem.writeInt(u32, blank[0..4], 0x0000_00FF, .little);
    try std.testing.expectError(error.ExpectedPixelMissing, proveScanout(info, blank[0..], expected_pixel));
    try std.testing.expectError(error.CaptureTooSmall, proveScanout(info, scanline[0 .. scanline.len - 4], expected_pixel));
    try std.testing.expectError(error.InvalidExpectedPixel, proveScanout(info, scanline[0..], 0));
}

test "framebuffer validation rejects undersized buffers and bad stride" {
    try std.testing.expectError(error.InvalidStride, validate(.{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = SVGA_TEST_WIDTH,
        .height = SVGA_TEST_HEIGHT,
        .pixels_per_scan_line = SVGA_BAD_STRIDE_PIXELS,
        .format = .rgbx8888,
        .buffer_bytes = testLinearBufferBytes(SVGA_TEST_WIDTH, SVGA_TEST_HEIGHT),
    }));

    try std.testing.expectError(error.BufferTooSmall, validate(.{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = SVGA_TEST_WIDTH,
        .height = SVGA_TEST_HEIGHT,
        .pixels_per_scan_line = SVGA_TEST_WIDTH,
        .format = .rgbx8888,
        .buffer_bytes = testLinearBufferBytes(SVGA_TEST_WIDTH, SVGA_TEST_HEIGHT) - 1,
    }));
}

fn testLinearBufferBytes(pixels_per_scan_line: u32, height: u32) u64 {
    return @as(u64, pixels_per_scan_line) * @as(u64, height) * @as(u64, FRAMEBUFFER_32BPP_BYTES);
}

test "framebuffer validation rejects overlapping bitmasks" {
    try std.testing.expectError(error.UnsupportedPixelFormat, validate(.{
        .physical_address = 0x8000_0000,
        .width = 800,
        .height = 600,
        .pixels_per_scan_line = 800,
        .format = .bitmask,
        .pixel_mask = .{
            .red = 0x0000_00FF,
            .green = 0x0000_00F0,
            .blue = 0x0000_FF00,
            .reserved = 0xFF00_0000,
        },
        .buffer_bytes = 800 * 600 * 4,
    }));
}

test "framebuffer validation derives text grid geometry" {
    const grid = try textGrid(.{
        .physical_address = 0x9000_0000,
        .width = 1280,
        .height = 720,
        .pixels_per_scan_line = 1280,
        .format = .rgbx8888,
        .buffer_bytes = 1280 * 720 * 4,
    }, 8, 16);
    try std.testing.expectEqual(@as(u32, 160), grid.columns);
    try std.testing.expectEqual(@as(u32, 45), grid.rows);
}
