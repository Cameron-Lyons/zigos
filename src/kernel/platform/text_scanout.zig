const std = @import("std");
const framebuffer = @import("framebuffer.zig");
const unicode = @import("../../native/core/unicode.zig");
const unicode_font = @import("unicode_font.zig");
const font = @import("bitmap_font.zig");

pub const MAX_COLUMNS = 120;
pub const MAX_ROWS = 48;
pub const MAX_CELLS = MAX_COLUMNS * MAX_ROWS;
pub const CELL_WIDTH = 12;
pub const CELL_HEIGHT = 20;
pub const BACKGROUND: u24 = 0x111923;

pub const Style = enum(u3) { body, muted, accent, selected, warning };
pub const CLUSTER_BYTES = 4096;
pub const Cell = packed struct(u64) {
    character: u21 = ' ',
    cluster_offset: u12 = 0,
    cluster_length: u10 = 0,
    part: enum(u2) { single, left, right } = .single,
    style: Style = .body,
    cursor: bool = false,
    cursor_trailing: bool = false,
    reserved: u14 = 0,
};
const palette = [_]struct { foreground: u24, background: u24 }{
    .{ .foreground = 0xe5ebf2, .background = BACKGROUND },
    .{ .foreground = 0x96a8bb, .background = BACKGROUND },
    .{ .foreground = 0x72d5bb, .background = BACKGROUND },
    .{ .foreground = 0xffffff, .background = 0x294453 },
    .{ .foreground = 0xf4c77e, .background = BACKGROUND },
};

pub const Frame = struct {
    columns: usize,
    rows: usize,
    cells: [MAX_CELLS]Cell = undefined,
    clusters: [CLUSTER_BYTES]u8 = undefined,
    cluster_length: usize = 0,

    pub fn init(columns: usize, rows: usize) error{InvalidFrame}!Frame {
        if (columns == 0 or columns > MAX_COLUMNS or rows == 0 or rows > MAX_ROWS) return error.InvalidFrame;
        var frame = Frame{ .columns = columns, .rows = rows };
        frame.clear();
        return frame;
    }

    pub fn clear(self: *Frame) void {
        @memset(self.clusters[0..self.cluster_length], 0);
        self.cluster_length = 0;
        @memset(self.cells[0 .. self.columns * self.rows], .{});
    }

    pub fn put(self: *Frame, column: usize, row: usize, text: []const u8, style: Style) void {
        if (column >= self.columns or row >= self.rows) return;
        var iterator = unicode.Iterator{ .text = text };
        var x = column;
        while (iterator.next()) |cluster| {
            if (cluster.newline or x >= self.columns) break;
            const width = @min(cluster.columns(x), self.columns - x);
            self.putCluster(x, row, text[cluster.start..cluster.end], width, style);
            x += width;
        }
    }

    pub fn putCluster(self: *Frame, column: usize, row: usize, bytes: []const u8, width: usize, style: Style) void {
        if (column >= self.columns or row >= self.rows or width == 0 or width > self.columns - column) return;
        const scalar = unicode.decode(bytes, 0) orelse unicode.Scalar{ .point = 0xfffd, .end = bytes.len };
        var cell = Cell{ .character = scalar.point, .style = style };
        if (scalar.point == '\t') {
            @memset(self.cells[row * self.columns + column ..][0..width], .{ .style = style });
            return;
        }
        if (scalar.end != bytes.len) {
            if (bytes.len <= std.math.maxInt(u10) and bytes.len <= CLUSTER_BYTES - self.cluster_length) {
                cell.cluster_offset = @intCast(self.cluster_length);
                cell.cluster_length = @intCast(bytes.len);
                @memcpy(self.clusters[self.cluster_length..][0..bytes.len], bytes);
                self.cluster_length += bytes.len;
            } else cell.character = 0xfffd;
        }
        if (width == 2) cell.part = .left;
        self.cells[row * self.columns + column] = cell;
        if (width == 2) {
            cell.part = .right;
            self.cells[row * self.columns + column + 1] = cell;
        }
    }

    pub fn fillRow(self: *Frame, row: usize, style: Style) void {
        if (row >= self.rows) return;
        @memset(self.cells[row * self.columns ..][0..self.columns], .{ .style = style });
    }
};

pub const PresentStats = struct {
    changed_cells: usize = 0,
    pixels_written: usize = 0,
};

// The caller owns an exclusive mapped 32-bit framebuffer and serializes present.
// No framebuffer reads, allocation, timer polling, or full-frame shadow copies
// are needed. The first frame clears visible pixels; later frames damage cells.
pub const Renderer = struct {
    info: framebuffer.Info,
    pixels: []volatile u32,
    columns: usize,
    rows: usize,
    origin_x: usize,
    origin_y: usize,
    foregrounds: [palette.len]u32,
    backgrounds: [palette.len]u32,
    previous: [MAX_CELLS]Cell = undefined,
    previous_clusters: [CLUSTER_BYTES]u8 = undefined,
    previous_cluster_length: usize = 0,
    painted: bool = false,

    pub fn init(info: framebuffer.Info, pixels: []volatile u32) !Renderer {
        _ = try framebuffer.validate(info);
        const count: usize = @intCast((try info.minimumBufferBytes()) / 4);
        if (pixels.len < count) return error.BufferTooSmall;
        const columns: usize = @min(MAX_COLUMNS, (info.width -| 48) / CELL_WIDTH);
        const rows: usize = @min(MAX_ROWS, (info.height -| 40) / CELL_HEIGHT);
        if (columns < 20 or rows < 10) return error.DisplayTooSmall;
        var renderer = Renderer{
            .info = info,
            .pixels = pixels[0..count],
            .columns = columns,
            .rows = rows,
            .origin_x = (info.width - columns * CELL_WIDTH) / 2,
            .origin_y = (info.height - rows * CELL_HEIGHT) / 2,
            .foregrounds = undefined,
            .backgrounds = undefined,
        };
        for (palette, 0..) |colors, index| {
            renderer.foregrounds[index] = info.encodeColor(colors.foreground);
            renderer.backgrounds[index] = info.encodeColor(colors.background);
        }
        return renderer;
    }

    pub fn present(self: *Renderer, frame: *const Frame) error{InvalidFrame}!PresentStats {
        if (frame.columns != self.columns or frame.rows != self.rows) return error.InvalidFrame;
        var stats = PresentStats{};
        if (!self.painted) {
            for (0..self.info.height) |y| {
                for (0..self.info.width) |x| self.pixels[y * self.info.pixels_per_scan_line + x] = self.backgrounds[0];
            }
            stats.pixels_written = @as(usize, self.info.width) * self.info.height;
        }
        for (frame.cells[0 .. self.columns * self.rows], 0..) |cell, index| {
            const old: u64 = if (self.painted) @bitCast(self.previous[index]) else @bitCast(Cell{});
            if (old != @as(u64, @bitCast(cell)) or (cell.cluster_length != 0 and !std.mem.eql(u8, clusterBytes(cell, frame.clusters[0..frame.cluster_length]), clusterBytes(self.previous[index], self.previous_clusters[0..self.previous_cluster_length])))) {
                self.drawCell(index % self.columns, index / self.columns, cell, frame.clusters[0..frame.cluster_length]);
                stats.changed_cells += 1;
                stats.pixels_written += CELL_WIDTH * CELL_HEIGHT;
            }
            self.previous[index] = cell;
        }
        @memcpy(self.previous_clusters[0..frame.cluster_length], frame.clusters[0..frame.cluster_length]);
        if (frame.cluster_length < self.previous_cluster_length) @memset(self.previous_clusters[frame.cluster_length..self.previous_cluster_length], 0);
        self.previous_cluster_length = frame.cluster_length;
        self.painted = true;
        return stats;
    }

    fn cursorPixel(cell: Cell, x: usize, y: usize) bool {
        return cell.cursor and (if (cell.cursor_trailing) x >= 10 and y >= 2 and y < 18 else y >= 18);
    }

    fn drawCell(self: *Renderer, column: usize, row: usize, cell: Cell, pool: []const u8) void {
        const raster = Raster.init(cell, pool);
        const foreground = self.foregrounds[@intFromEnum(cell.style)];
        const background = self.backgrounds[@intFromEnum(cell.style)];
        const left = self.origin_x + column * CELL_WIDTH;
        const top = self.origin_y + row * CELL_HEIGHT;
        for (0..CELL_HEIGHT) |y| {
            for (0..CELL_WIDTH) |x| {
                const ink = raster.ink(cell, x, y);
                const cursor = cursorPixel(cell, x, y);
                self.pixels[(top + y) * self.info.pixels_per_scan_line + left + x] = if (ink or cursor) foreground else background;
            }
        }
    }

    // Verification reads the mapped device pixels, not the retained cell cache.
    pub fn matchesCell(self: *const Renderer, column: usize, row: usize, cell: Cell) bool {
        if (!self.painted or column >= self.columns or row >= self.rows) return false;
        const raster = Raster.init(cell, self.previous_clusters[0..self.previous_cluster_length]);
        const foreground = self.foregrounds[@intFromEnum(cell.style)];
        const background = self.backgrounds[@intFromEnum(cell.style)];
        const left = self.origin_x + column * CELL_WIDTH;
        const top = self.origin_y + row * CELL_HEIGHT;
        for (0..CELL_HEIGHT) |y| {
            for (0..CELL_WIDTH) |x| {
                const ink = raster.ink(cell, x, y);
                const expected = if (ink or cursorPixel(cell, x, y)) foreground else background;
                if (self.pixels[(top + y) * self.info.pixels_per_scan_line + left + x] != expected) return false;
            }
        }
        return true;
    }
};

fn clusterBytes(cell: Cell, pool: []const u8) []const u8 {
    const offset: usize = cell.cluster_offset;
    const length: usize = cell.cluster_length;
    if (offset > pool.len or length > pool.len - offset) return "";
    return pool[offset..][0..length];
}

const Raster = union(enum) {
    ascii: [7]u5,
    unicode: unicode_font.Glyph,

    fn init(cell: Cell, pool: []const u8) Raster {
        if (cell.character < 0x80 and cell.cluster_length == 0) return .{ .ascii = font.glyph(@intCast(cell.character)) };
        const glyph = if (cell.cluster_length == 0) unicode_font.glyph(cell.character) else unicode_font.cluster(clusterBytes(cell, pool));
        return .{ .unicode = glyph };
    }
    fn ink(self: Raster, cell: Cell, x: usize, y: usize) bool {
        return switch (self) {
            .ascii => |glyph| y >= 2 and y < 16 and x < 10 and (glyph[(y - 2) / 2] & (@as(u5, 16) >> @intCast(x / 2))) != 0,
            .unicode => |glyph| blk: {
                if (y < 2 or y >= 18) break :blk false;
                const span: usize = if (cell.part == .single) CELL_WIDTH else CELL_WIDTH * 2;
                // Ambiguous-width symbols can have a 16-pixel source glyph
                // in a one-column layout. Fit their ink instead of discarding
                // a supported character; normal wide glyphs keep every pixel.
                const ink_width = @min(@as(usize, glyph.width), span - 2);
                const left = (span - ink_width) / 2;
                const gx = x + @as(usize, if (cell.part == .right) CELL_WIDTH else 0);
                if (gx < left or gx >= left + ink_width) break :blk false;
                break :blk glyph.rows[y - 2] & (@as(u16, 1) << @intCast(glyph.width - 1 - (if (ink_width == glyph.width) gx - left else (gx - left) * 16 / 10))) != 0;
            },
        };
    }
};
