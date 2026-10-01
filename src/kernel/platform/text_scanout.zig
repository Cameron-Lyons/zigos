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
            const previous = if (self.painted) self.previous[index] else Cell{};
            // Equal scalar cells never need to load either grapheme pool.
            const same_scalar = @as(u64, @bitCast(cell)) == @as(u64, @bitCast(previous)) and cell.cluster_length == 0;
            if (!same_scalar and !sameCell(cell, frame.clusters[0..frame.cluster_length], previous, self.previous_clusters[0..self.previous_cluster_length])) {
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

    fn drawCell(self: *Renderer, column: usize, row: usize, cell: Cell, pool: []const u8) void {
        const raster = Raster.init(cell, pool);
        const foreground = self.foregrounds[@intFromEnum(cell.style)];
        const background = self.backgrounds[@intFromEnum(cell.style)];
        const left = self.origin_x + column * CELL_WIDTH;
        const top = self.origin_y + row * CELL_HEIGHT;
        for (0..CELL_HEIGHT) |y| {
            const pixels = self.pixels[(top + y) * self.info.pixels_per_scan_line + left ..][0..CELL_WIDTH];
            var ink = raster.rows[y];
            for (pixels) |*pixel| {
                pixel.* = if (ink & 1 != 0) foreground else background;
                ink >>= 1;
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
            const pixels = self.pixels[(top + y) * self.info.pixels_per_scan_line + left ..][0..CELL_WIDTH];
            var ink = raster.rows[y];
            for (pixels) |pixel| {
                const expected = if (ink & 1 != 0) foreground else background;
                if (pixel != expected) return false;
                ink >>= 1;
            }
        }
        return true;
    }
};

// Pool offsets describe storage, not visible content. Recomposition can move an
// unchanged grapheme within the pool without damaging its rendered cell.
fn sameCell(current: Cell, current_pool: []const u8, previous: Cell, previous_pool: []const u8) bool {
    var current_content = current;
    current_content.cluster_offset = 0;
    current_content.reserved = 0;
    var previous_content = previous;
    previous_content.cluster_offset = 0;
    previous_content.reserved = 0;
    return @as(u64, @bitCast(current_content)) == @as(u64, @bitCast(previous_content)) and
        (current.cluster_length == 0 or std.mem.eql(u8, clusterBytes(current, current_pool), clusterBytes(previous, previous_pool)));
}

fn clusterBytes(cell: Cell, pool: []const u8) []const u8 {
    const offset: usize = cell.cluster_offset;
    const length: usize = cell.cluster_length;
    if (offset > pool.len or length > pool.len - offset) return "";
    return pool[offset..][0..length];
}

const Raster = struct {
    rows: [CELL_HEIGHT]u12 = @splat(0),

    fn init(cell: Cell, pool: []const u8) Raster {
        var raster = Raster{};
        if (cell.character < 0x80 and cell.cluster_length == 0) {
            const glyph = font.glyph(@intCast(cell.character));
            for (glyph, 0..) |source, y| {
                var ink: u12 = 0;
                for (0..5) |x| {
                    if (source & (@as(u5, 16) >> @intCast(x)) != 0) ink |= @as(u12, 3) << @intCast(x * 2);
                }
                raster.rows[2 + y * 2] = ink;
                raster.rows[3 + y * 2] = ink;
            }
        } else {
            const glyph = if (cell.cluster_length == 0) unicode_font.glyph(cell.character) else unicode_font.cluster(clusterBytes(cell, pool));
            const span: usize = if (cell.part == .single) CELL_WIDTH else CELL_WIDTH * 2;
            // Fit ambiguous-width source glyphs to one cell. Compute the
            // horizontal sampling once, rather than once per device pixel.
            const ink_width = @min(@as(usize, glyph.width), span - 2);
            const left = (span - ink_width) / 2;
            for (0..CELL_WIDTH) |x| {
                const gx = x + @as(usize, if (cell.part == .right) CELL_WIDTH else 0);
                if (gx < left or gx >= left + ink_width) continue;
                const source_x = (gx - left) * glyph.width / ink_width;
                const source_bit = @as(u16, 1) << @intCast(glyph.width - 1 - source_x);
                const target_bit = @as(u12, 1) << @intCast(x);
                for (glyph.rows, 0..) |source, y| {
                    if (source & source_bit != 0) raster.rows[2 + y] |= target_bit;
                }
            }
        }
        if (cell.cursor) {
            if (cell.cursor_trailing) {
                for (raster.rows[2..18]) |*row| row.* |= 0xc00;
            } else {
                raster.rows[18] = 0xfff;
                raster.rows[19] = 0xfff;
            }
        }
        return raster;
    }
};
