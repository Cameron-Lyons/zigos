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
    try std.testing.expect(renderer.matchesCell(0, 0, frame.cells[0]));
    pixels[top_left + 2 * info.pixels_per_scan_line + 2] = 0;
    try std.testing.expect(!renderer.matchesCell(0, 0, frame.cells[0]));
    pixels[top_left + 2 * info.pixels_per_scan_line + 2] = info.encodeColor(0x72d5bb);
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
    frame.cells[0].cursor_trailing = true;
    try std.testing.expectEqual(@as(usize, 1), (try renderer.present(&frame)).changed_cells);
    try std.testing.expectEqual(info.encodeColor(0x72d5bb), pixels[top_left + 2 * info.pixels_per_scan_line + 11]);
    try std.testing.expectEqual(info.encodeColor(scanout.BACKGROUND), pixels[top_left + 19 * info.pixels_per_scan_line]);
    try std.testing.expect(renderer.matchesCell(0, 0, frame.cells[0]));
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
                .style = @fromBackingInt(@intCast(random.uintLessThan(u3, 5))),
                .cursor = random.boolean(),
                .cursor_trailing = random.boolean(),
            };
        }
        _ = try renderer.present(&frame);
        var fresh = try scanout.Renderer.init(info, complete);
        _ = try fresh.present(&frame);
        try std.testing.expectEqualSlices(u32, complete, incremental);
    }
}

test "scanout rejects invalid storage and frame dimensions before writing" {
    var pixels = @as([4]u32, @splat(123));
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

test "scanout paints UTF-8 glyphs wide cells and exact combining cluster changes" {
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    frame.put(0, 0, "ée\u{301}界", .body);
    _ = try renderer.present(&frame);
    try std.testing.expectEqual(@as(u21, 'é'), frame.cells[0].character);
    try std.testing.expectEqual(@as(u21, 'e'), frame.cells[1].character);
    try std.testing.expectEqual(.left, frame.cells[2].part);
    try std.testing.expectEqual(.right, frame.cells[3].part);
    for (0..4) |x| try std.testing.expect(renderer.matchesCell(x, 0, frame.cells[x]));
    try std.testing.expectEqual(scanout.PresentStats{}, try renderer.present(&frame));
    // Identical cell metadata and pool offsets must not hide changed accents.
    frame.clear();
    frame.put(0, 0, "ée\u{300}界", .body);
    try std.testing.expectEqual(@as(usize, 1), (try renderer.present(&frame)).changed_cells);
    const fresh_pixels = try std.testing.allocator.alloc(u32, pixels.len);
    defer std.testing.allocator.free(fresh_pixels);
    @memset(fresh_pixels, 0);
    // Padding is not part of rendering; initialize it identically for comparison.
    for (0..info.height) |y| @memset(pixels[y * info.pixels_per_scan_line + info.width ..][0 .. info.pixels_per_scan_line - info.width], 0);
    var fresh = try scanout.Renderer.init(info, fresh_pixels);
    _ = try fresh.present(&frame);
    try std.testing.expectEqualSlices(u32, fresh_pixels, pixels);
    const retained_bytes = frame.cluster_length;
    frame.clear();
    try std.testing.expect(std.mem.allEqual(u8, frame.clusters[0..retained_bytes], 0));
    _ = try renderer.present(&frame);
    try std.testing.expect(std.mem.allEqual(u8, renderer.previous_clusters[0..retained_bytes], 0));
    for (0..4) |x| try std.testing.expect(renderer.matchesCell(x, 0, .{}));
}

test "scanout fits ambiguous-width source glyphs into a single cell" {
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    frame.put(0, 0, "☃", .body);
    _ = try renderer.present(&frame);
    try std.testing.expectEqual(.single, frame.cells[0].part);
    const source = @import("unicode_font.zig").glyph('☃');
    try std.testing.expectEqual(@as(u5, 16), source.width);
    var foreground: usize = 0;
    for (0..16) |y| {
        for (0..10) |x| {
            const ink = source.rows[y] & (@as(u16, 1) << @intCast(15 - x * 16 / 10)) != 0;
            const pixel = pixels[(renderer.origin_y + 2 + y) * info.pixels_per_scan_line + renderer.origin_x + 1 + x];
            try std.testing.expectEqual(info.encodeColor(if (ink) 0xe5ebf2 else scanout.BACKGROUND), pixel);
            foreground += @intFromBool(ink);
        }
    }
    try std.testing.expect(foreground != 0);
}

test "scanout shared projection preserves narrow wide and combining source pixels" {
    const font = @import("unicode_font.zig");
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    @memset(pixels, 0);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    for ([_][]const u8{ "é", "☃", "界", "e\u{301}", "界\u{301}", "界\u{732}" }) |text| {
        frame.clear();
        frame.put(0, 0, text, .body);
        _ = try renderer.present(&frame);
        const source = font.cluster(text);
        const span: usize = if (frame.cells[0].part == .single) scanout.CELL_WIDTH else scanout.CELL_WIDTH * 2;
        // Keep the pre-projection Raster formula as an independent pixel oracle.
        const ink_width = @min(@as(usize, source.width), span - 2);
        const left = (span - ink_width) / 2;
        for (0..scanout.CELL_HEIGHT) |y| {
            for (0..span) |x| {
                const ink = y >= 2 and y < 18 and x >= left and x < left + ink_width and
                    source.rows[y - 2] & (@as(u16, 1) << @intCast(@as(usize, source.width) - 1 - (x - left) * source.width / ink_width)) != 0;
                const pixel = pixels[(renderer.origin_y + y) * info.pixels_per_scan_line + renderer.origin_x + x];
                try std.testing.expectEqual(info.encodeColor(if (ink) 0xe5ebf2 else scanout.BACKGROUND), pixel);
            }
        }
    }
}

test "scanout dropped mark and promoted base pixel aliases fail exact cluster admission" {
    const font = @import("unicode_font.zig");
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    const previous = try std.testing.allocator.alloc(u32, pixels.len);
    defer std.testing.allocator.free(previous);
    @memset(pixels, 0);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    for ([_][2][]const u8{
        .{ "e\u{732}", "e\u{738}" },
        .{ "\u{1c0}\u{730}", "\u{16c1}\u{730}" },
    }) |pair| {
        frame.clear();
        frame.put(0, 0, pair[0], .body);
        _ = try renderer.present(&frame);
        @memcpy(previous, pixels);
        frame.clear();
        frame.put(0, 0, pair[1], .body);
        _ = try renderer.present(&frame);
        try std.testing.expectEqualSlices(u32, previous, pixels);
        try std.testing.expect(!font.supportsCluster(pair[0]));
        try std.testing.expect(!font.supportsCluster(pair[1]));
    }
    // The same source mark remains admissible when a wide cell retains its ink.
    try std.testing.expect(font.supportsCluster("界\u{732}"));
}

test "scanout ignores grapheme pool placement and retains the newest cache" {
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    frame.put(0, 0, "e\u{301}", .body);
    frame.put(5, 0, "界\u{301}", .accent);
    _ = try renderer.present(&frame);
    const original_offset = frame.cells[5].cluster_offset;

    // Build identical pixels in a different order, moving both cluster offsets.
    frame.clear();
    frame.put(5, 0, "界\u{301}", .accent);
    frame.put(0, 0, "e\u{301}", .body);
    try std.testing.expect(original_offset != frame.cells[5].cluster_offset);
    try std.testing.expectEqual(scanout.PresentStats{}, try renderer.present(&frame));
    try std.testing.expectEqualDeep(frame.cells[0], renderer.previous[0]);
    try std.testing.expectEqualDeep(frame.cells[5], renderer.previous[5]);
    try std.testing.expectEqualSlices(u8, frame.clusters[0..frame.cluster_length], renderer.previous_clusters[0..renderer.previous_cluster_length]);
    for ([_]usize{ 0, 5, 6 }) |column| try std.testing.expect(renderer.matchesCell(column, 0, frame.cells[column]));

    // Equal metadata and byte counts still damage a genuinely changed accent.
    frame.clear();
    frame.put(5, 0, "界\u{301}", .accent);
    frame.put(0, 0, "e\u{300}", .body);
    try std.testing.expectEqual(@as(usize, 1), (try renderer.present(&frame)).changed_cells);
    try std.testing.expect(renderer.matchesCell(0, 0, frame.cells[0]));

    // A shorter earlier cluster also leaves the wide cluster's pixels intact.
    frame.clear();
    frame.put(0, 0, "é", .body);
    frame.put(5, 0, "界\u{301}", .accent);
    try std.testing.expectEqual(@as(usize, 1), (try renderer.present(&frame)).changed_cells);
    try std.testing.expectEqual(scanout.PresentStats{}, try renderer.present(&frame));
    for ([_]usize{ 0, 5, 6 }) |column| try std.testing.expect(renderer.matchesCell(column, 0, frame.cells[column]));
}

test "scanout row masks preserve every ASCII glyph and both cursor shapes" {
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    const foreground = info.encodeColor(0x72d5bb);
    const background = info.encodeColor(scanout.BACKGROUND);
    for (' '..0x7f) |character| {
        const glyph = @import("bitmap_font.zig").glyph(@intCast(character));
        for (0..3) |cursor_shape| {
            frame.cells[0] = .{ .character = @intCast(character), .style = .accent, .cursor = cursor_shape != 0, .cursor_trailing = cursor_shape == 2 };
            _ = try renderer.present(&frame);
            for (0..scanout.CELL_HEIGHT) |y| {
                for (0..scanout.CELL_WIDTH) |x| {
                    const glyph_ink = y >= 2 and y < 16 and x < 10 and
                        glyph[(y - 2) / 2] & (@as(u5, 16) >> @intCast(x / 2)) != 0;
                    const cursor_ink = if (cursor_shape == 1) y >= 18 else cursor_shape == 2 and x >= 10 and y >= 2 and y < 18;
                    const pixel = pixels[(renderer.origin_y + y) * info.pixels_per_scan_line + renderer.origin_x + x];
                    try std.testing.expectEqual(if (glyph_ink or cursor_ink) foreground else background, pixel);
                }
            }
        }
    }
}

test "scanout row masks preserve narrow wide and combining Unicode source pixels" {
    const info = testInfo();
    const pixels = try std.testing.allocator.alloc(u32, info.pixels_per_scan_line * info.height);
    defer std.testing.allocator.free(pixels);
    var renderer = try scanout.Renderer.init(info, pixels);
    var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    const foreground = info.encodeColor(0xe5ebf2);
    const background = info.encodeColor(scanout.BACKGROUND);
    for ([_][]const u8{ "é", "界", "☃", "e\u{301}", "界\u{301}", "👩‍💻" }) |text| {
        frame.clear();
        frame.put(0, 0, text, .body);
        _ = try renderer.present(&frame);
        const glyph = @import("unicode_font.zig").cluster(text);
        const span: usize = if (frame.cells[0].part == .left) 24 else 12;
        const ink_width = @min(@as(usize, glyph.width), span - 2);
        const left = (span - ink_width) / 2;
        for (0..scanout.CELL_HEIGHT) |y| {
            for (0..span) |x| {
                const ink = y >= 2 and y < 18 and x >= left and x < left + ink_width and
                    glyph.rows[y - 2] & (@as(u16, 1) << @intCast(glyph.width - 1 - (if (ink_width == glyph.width) x - left else (x - left) * 16 / 10))) != 0;
                const pixel = pixels[(renderer.origin_y + y) * info.pixels_per_scan_line + renderer.origin_x + x];
                try std.testing.expectEqual(if (ink) foreground else background, pixel);
            }
        }
    }
}
