const std = @import("std");

pub const Error = error{
    MissingFramebuffer,
    UnsupportedPixelFormat,
    InvalidResolution,
    InvalidStride,
    InvalidAddress,
    BufferTooSmall,
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

pub fn textGrid(info: Info, glyph_width: u32, glyph_height: u32) Error!struct { columns: u32, rows: u32 } {
    _ = try validate(info);
    if (glyph_width == 0 or glyph_height == 0) return error.InvalidResolution;
    return .{
        .columns = info.width / glyph_width,
        .rows = info.height / glyph_height,
    };
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
