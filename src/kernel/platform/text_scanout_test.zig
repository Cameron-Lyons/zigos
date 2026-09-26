const std = @import("std");
const framebuffer = @import("framebuffer.zig");
const hardware = @import("framebuffer_hw.zig");
const scanout = @import("text_scanout.zig");

fn testInfo() framebuffer.Info {
    return .{
        .physical_address = 0x9000_0080,
        .width = 288,
        .height = 240,
        .pixels_per_scan_line = 293,
        .format = .bgrx8888,
        .buffer_bytes = 293 * 240 * 4,
    };
}

test "scanout preserves padding and guards and writes only damaged cells" {
    const info = testInfo();
    const count = info.pixels_per_scan_line * info.height;
    const storage = try std.testing.allocator.alloc(u32, count + 2);
    defer std.testing.allocator.free(storage);
    @memset(storage, 0xbad0cafe);
    const pixels = storage[1 .. count + 1];
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    frame.put(0, 0, "A", .accent);
    const first = try renderer.present(&frame);
    try std.testing.expectEqual(@as(usize, 1), first.changed_cells);
    const top_left = renderer.origin_y * info.pixels_per_scan_line + renderer.origin_x;
    try std.testing.expectEqual(info.encodeColor(scanout.BACKGROUND), pixels[top_left + 2 * info.pixels_per_scan_line]);
    try std.testing.expectEqual(info.encodeColor(0x72d5bb), pixels[top_left + 2 * info.pixels_per_scan_line + 2]);
    try std.testing.expectEqual(@as(u32, 0xbad0cafe), storage[0]);
    try std.testing.expectEqual(@as(u32, 0xbad0cafe), storage[storage.len - 1]);
    for (0..info.height) |row| {
        for (pixels[row * info.pixels_per_scan_line + info.width ..][0 .. info.pixels_per_scan_line - info.width]) |pixel| {
            try std.testing.expectEqual(@as(u32, 0xbad0cafe), pixel);
        }
    }

    pixels[0] = 123;
    try std.testing.expectEqual(scanout.PresentStats{}, try renderer.present(&frame));
    try std.testing.expectEqual(@as(u32, 123), pixels[0]);
    frame.cells[0].cursor = true;
    const cursor = try renderer.present(&frame);
    try std.testing.expectEqual(@as(usize, 1), cursor.changed_cells);
    try std.testing.expectEqual(@as(usize, scanout.CELL_WIDTH * scanout.CELL_HEIGHT), cursor.pixels_written);
    try std.testing.expectEqual(info.encodeColor(0x72d5bb), pixels[top_left + 19 * info.pixels_per_scan_line]);
    frame.clear();
    try std.testing.expectEqual(@as(usize, 1), (try renderer.present(&frame)).changed_cells);
    for (0..scanout.CELL_HEIGHT) |y| {
        for (pixels[top_left + y * info.pixels_per_scan_line ..][0..scanout.CELL_WIDTH]) |pixel| {
            try std.testing.expectEqual(info.encodeColor(scanout.BACKGROUND), pixel);
        }
    }
}

test "incremental scanout matches fresh rendering across text and style changes" {
    const info = testInfo();
    const count = info.pixels_per_scan_line * info.height;
    const incremental = try std.testing.allocator.alloc(u32, count);
    defer std.testing.allocator.free(incremental);
    const complete = try std.testing.allocator.alloc(u32, count);
    defer std.testing.allocator.free(complete);
    @memset(incremental, 0);
    @memset(complete, 0);
    var renderer = try scanout.Renderer.init(info, incremental);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    var rng = std.Random.DefaultPrng.init(0x51ca_2026);
    const random = rng.random();
    for (0..40) |_| {
        for (0..8) |_| {
            const index = random.uintLessThan(usize, frame.columns * frame.rows);
            frame.cells[index] = .{
                .character = random.intRangeAtMost(u8, ' ', '~'),
                .style = @enumFromInt(random.uintLessThan(u3, 5)),
                .cursor = random.boolean(),
            };
        }
        _ = try renderer.present(&frame);
        var fresh = try scanout.Renderer.init(info, complete);
        _ = try fresh.present(&frame);
        try std.testing.expectEqualSlices(u32, complete, incremental);
    }
}

test "scanout rejects invalid storage and frame dimensions before writing" {
    var pixels = [_]u32{123} ** 4;
    try std.testing.expectError(error.BufferTooSmall, scanout.Renderer.init(testInfo(), &pixels));
    try std.testing.expectEqualSlices(u32, &.{ 123, 123, 123, 123 }, &pixels);
    try std.testing.expectError(error.InvalidFrame, scanout.Frame.init(std.math.maxInt(usize), 1));
    try std.testing.expectError(error.InvalidFrame, scanout.Frame.init(1, 0));
    const info = testInfo();
    const storage = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(storage);
    @memset(storage, 123);
    var renderer = try scanout.Renderer.init(info, storage);
    var wrong = try scanout.Frame.init(renderer.columns - 1, renderer.rows);
    try std.testing.expectError(error.InvalidFrame, renderer.present(&wrong));
    for (storage) |pixel| try std.testing.expectEqual(@as(u32, 123), pixel);
}

test "framebuffer mapping covers page offsets without exceeding its aperture" {
    var info = testInfo();
    const mapping = try hardware.mappingFor(info);
    try std.testing.expectEqual(@as(usize, 0x9000_0000), mapping.physical_base);
    try std.testing.expectEqual(@as(usize, 128), mapping.pixel_offset);
    try std.testing.expectEqual(@as(usize, 293 * 240), mapping.pixel_count);
    try std.testing.expectEqual(@as(usize, 0), mapping.page_bytes % 4096);
    try std.testing.expect(mapping.page_bytes >= mapping.pixel_offset + info.buffer_bytes);

    info.physical_address = 0x9000_0000;
    info.width = 4096;
    info.height = 4096;
    info.pixels_per_scan_line = 4096;
    info.buffer_bytes = 64 * 1024 * 1024;
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024), (try hardware.mappingFor(info)).page_bytes);
    info.physical_address += 4;
    try std.testing.expectError(error.BufferTooLarge, hardware.mappingFor(info));
    info.physical_address = 0x000f_ffff_ffff_f000;
    try std.testing.expectError(error.InvalidAddress, hardware.mappingFor(info));
}

test "framebuffer colors use exact byte order and scale contiguous bitmasks" {
    var info = testInfo();
    try std.testing.expectEqual(@as(u32, 0x123456), info.encodeColor(0x123456));
    info.format = .rgbx8888;
    try std.testing.expectEqual(@as(u32, 0x563412), info.encodeColor(0x123456));
    info.format = .bitmask;
    info.pixel_mask = .{ .red = 0x3ff0_0000, .green = 0x000f_fc00, .blue = 0x0000_03ff, .reserved = 0xc000_0000 };
    _ = try framebuffer.validate(info);
    try std.testing.expectEqual(@as(u32, 0x3fff_ffff), info.encodeColor(0xffffff));
    try std.testing.expectEqual(@as(u32, 0x2020_0000), info.encodeColor(0x800000));
    info.pixel_mask.red = 0;
    try std.testing.expectError(error.UnsupportedPixelFormat, framebuffer.validate(info));
    info.pixel_mask.red = 0x3010_0000;
    try std.testing.expectError(error.UnsupportedPixelFormat, framebuffer.validate(info));
    info.format = .bgrx8888;
    info.physical_address += 1;
    try std.testing.expectError(error.InvalidAddress, framebuffer.validate(info));
    info.physical_address = std.math.maxInt(u64) - 3;
    try std.testing.expectError(error.InvalidAddress, framebuffer.validate(info));
}
