const std = @import("std");

pub const Error = error{
    UnsupportedPixelFormat,
    InvalidResolution,
    InvalidStride,
    InvalidAddress,
    BufferTooSmall,
};

pub const PixelMask = struct {
    red: u32,
    green: u32,
    blue: u32,
    reserved: u32,
};

pub const RGBX8888_MASK = PixelMask{
    .red = 0x0000_00FF,
    .green = 0x0000_FF00,
    .blue = 0x00FF_0000,
    .reserved = 0xFF00_0000,
};
pub const BGRX8888_MASK = PixelMask{
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

// The UEFI handoff always describes a 32-bit pixel by its channel bitmasks.
pub const Info = struct {
    physical_address: u64,
    width: u32,
    height: u32,
    pixels_per_scan_line: u32,
    pixel_mask: PixelMask,
    buffer_bytes: u64,

    // Input is 0xRRGGBB; reserved bits stay zero. Call after validate().
    pub fn encodeColor(self: Info, rgb: u24) u32 {
        const mask = self.pixel_mask;
        return encodeChannel(@truncate(rgb >> 16), mask.red) |
            encodeChannel(@truncate(rgb >> 8), mask.green) |
            encodeChannel(@truncate(rgb), mask.blue);
    }

    pub fn minimumBufferBytes(self: Info) Error!u64 {
        if (!valid32BitColorMask(self.pixel_mask)) return error.UnsupportedPixelFormat;
        return @as(u64, self.pixels_per_scan_line) * @as(u64, self.height) * FRAMEBUFFER_32BPP_BYTES;
    }
};

pub fn validate(framebuffer: Info) Error!void {
    if (framebuffer.physical_address == 0) return error.InvalidAddress;
    if (framebuffer.physical_address % 4 != 0) return error.InvalidAddress;
    if (framebuffer.width == 0 or framebuffer.height == 0) return error.InvalidResolution;
    if (framebuffer.width > MAX_LINEAR_DIMENSION_PIXELS or framebuffer.height > MAX_LINEAR_DIMENSION_PIXELS) return error.InvalidResolution;
    if (framebuffer.pixels_per_scan_line < framebuffer.width) return error.InvalidStride;

    const minimum_bytes = try framebuffer.minimumBufferBytes();
    if (framebuffer.buffer_bytes < minimum_bytes) return error.BufferTooSmall;
    _ = std.math.add(u64, framebuffer.physical_address, framebuffer.buffer_bytes) catch return error.InvalidAddress;
}

fn valid32BitColorMask(mask: PixelMask) bool {
    const overlaps = ((mask.red & mask.green) |
        (mask.red & mask.blue) |
        (mask.red & mask.reserved) |
        (mask.green & mask.blue) |
        (mask.green & mask.reserved) |
        (mask.blue & mask.reserved)) != 0;
    return contiguousChannel(mask.red) and contiguousChannel(mask.green) and contiguousChannel(mask.blue) and !overlaps;
}

fn contiguousChannel(mask: u32) bool {
    if (mask == 0) return false;
    const shifted = mask >> @intCast(@ctz(mask));
    return shifted & (shifted +% 1) == 0;
}

fn encodeChannel(value: u8, mask: u32) u32 {
    const shift: u5 = @intCast(@ctz(mask));
    const maximum = mask >> shift;
    return @as(u32, @intCast((@as(u64, value) * maximum + 127) / 255)) << shift;
}

test "framebuffer validation accepts UEFI GOP-style linear modes" {
    const info = Info{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = GOP_TEST_WIDTH,
        .height = GOP_TEST_HEIGHT,
        .pixels_per_scan_line = GOP_TEST_STRIDE_PIXELS,
        .pixel_mask = BGRX8888_MASK,
        .buffer_bytes = testLinearBufferBytes(GOP_TEST_STRIDE_PIXELS, GOP_TEST_HEIGHT),
    };
    try validate(info);
    try std.testing.expectEqual(testLinearBufferBytes(GOP_TEST_STRIDE_PIXELS, GOP_TEST_HEIGHT), try info.minimumBufferBytes());
}

test "framebuffer validation rejects undersized buffers and bad stride" {
    try std.testing.expectError(error.InvalidStride, validate(.{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = SVGA_TEST_WIDTH,
        .height = SVGA_TEST_HEIGHT,
        .pixels_per_scan_line = SVGA_BAD_STRIDE_PIXELS,
        .pixel_mask = RGBX8888_MASK,
        .buffer_bytes = testLinearBufferBytes(SVGA_TEST_WIDTH, SVGA_TEST_HEIGHT),
    }));

    try std.testing.expectError(error.BufferTooSmall, validate(.{
        .physical_address = TEST_FRAMEBUFFER_ADDRESS,
        .width = SVGA_TEST_WIDTH,
        .height = SVGA_TEST_HEIGHT,
        .pixels_per_scan_line = SVGA_TEST_WIDTH,
        .pixel_mask = RGBX8888_MASK,
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
        .pixel_mask = .{
            .red = 0x0000_00FF,
            .green = 0x0000_00F0,
            .blue = 0x0000_FF00,
            .reserved = 0xFF00_0000,
        },
        .buffer_bytes = 800 * 600 * 4,
    }));
}
