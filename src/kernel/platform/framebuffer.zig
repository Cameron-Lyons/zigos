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

pub const Info = struct {
    physical_address: u64,
    width: u32,
    height: u32,
    pixels_per_scan_line: u32,
    format: PixelFormat,
    pixel_mask: PixelMask = .{
        .red = 0x00FF_0000,
        .green = 0x0000_FF00,
        .blue = 0x0000_00FF,
        .reserved = 0xFF00_0000,
    },
    buffer_bytes: u64,

    pub fn bytesPerPixel(self: Info) Error!u8 {
        return switch (self.format) {
            .rgbx8888, .bgrx8888 => 4,
            .bitmask => if (valid32BitColorMask(self.pixel_mask)) 4 else error.UnsupportedPixelFormat,
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
    if (framebuffer.width > 16384 or framebuffer.height > 16384) return error.InvalidResolution;
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
        .physical_address = 0x8000_0000,
        .width = 1920,
        .height = 1080,
        .pixels_per_scan_line = 2048,
        .format = .bgrx8888,
        .buffer_bytes = 2048 * 1080 * 4,
    });
    try std.testing.expectEqual(@as(u8, 4), try info.bytesPerPixel());
    try std.testing.expectEqual(@as(u64, 2048 * 1080 * 4), try info.minimumBufferBytes());
}

test "framebuffer validation rejects undersized buffers and bad stride" {
    try std.testing.expectError(error.InvalidStride, validate(.{
        .physical_address = 0x8000_0000,
        .width = 1024,
        .height = 768,
        .pixels_per_scan_line = 1000,
        .format = .rgbx8888,
        .buffer_bytes = 1024 * 768 * 4,
    }));

    try std.testing.expectError(error.BufferTooSmall, validate(.{
        .physical_address = 0x8000_0000,
        .width = 1024,
        .height = 768,
        .pixels_per_scan_line = 1024,
        .format = .rgbx8888,
        .buffer_bytes = (1024 * 768 * 4) - 1,
    }));
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
