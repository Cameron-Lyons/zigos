const std = @import("std");
const framebuffer = @import("framebuffer.zig");
const font = @import("bitmap_font.zig");

pub const MAX_COLUMNS = 120;
pub const MAX_ROWS = 48;
pub const MAX_CELLS = MAX_COLUMNS * MAX_ROWS;
pub const CELL_WIDTH = 12;
pub const CELL_HEIGHT = 20;
pub const BACKGROUND: u24 = 0x111923;

pub const Style = enum(u3) { body, muted, accent, selected, warning };
pub const Cell = packed struct(u16) {
    character: u8 = ' ',
    style: Style = .body,
    cursor: bool = false,
    reserved: u4 = 0,
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

    pub fn init(columns: usize, rows: usize) error{InvalidFrame}!Frame {
        if (columns == 0 or columns > MAX_COLUMNS or rows == 0 or rows > MAX_ROWS) return error.InvalidFrame;
        var frame = Frame{ .columns = columns, .rows = rows };
        frame.clear();
        return frame;
    }

    pub fn clear(self: *Frame) void {
        @memset(self.cells[0 .. self.columns * self.rows], .{});
    }

    pub fn put(self: *Frame, column: usize, row: usize, text: []const u8, style: Style) void {
        if (column >= self.columns or row >= self.rows) return;
        for (text[0..@min(text.len, self.columns - column)], column..) |byte, x| {
            self.cells[row * self.columns + x] = .{ .character = byte, .style = style };
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
            const old: u16 = if (self.painted) @bitCast(self.previous[index]) else @bitCast(Cell{});
            if (old != @as(u16, @bitCast(cell))) {
                self.drawCell(index % self.columns, index / self.columns, cell);
                stats.changed_cells += 1;
                stats.pixels_written += CELL_WIDTH * CELL_HEIGHT;
            }
            self.previous[index] = cell;
        }
        self.painted = true;
        return stats;
    }

    fn drawCell(self: *Renderer, column: usize, row: usize, cell: Cell) void {
        const glyph = font.glyph(cell.character);
        const foreground = self.foregrounds[@intFromEnum(cell.style)];
        const background = self.backgrounds[@intFromEnum(cell.style)];
        const left = self.origin_x + column * CELL_WIDTH;
        const top = self.origin_y + row * CELL_HEIGHT;
        for (0..CELL_HEIGHT) |y| {
            for (0..CELL_WIDTH) |x| {
                const ink = y >= 2 and y < 16 and x < 10 and
                    (glyph[(y - 2) / 2] & (@as(u5, 16) >> @intCast(x / 2))) != 0;
                const cursor = cell.cursor and y >= 18;
                self.pixels[(top + y) * self.info.pixels_per_scan_line + left + x] = if (ink or cursor) foreground else background;
            }
        }
    }

    // Verification reads the mapped device pixels, not the retained cell cache.
    pub fn matchesCell(self: *const Renderer, column: usize, row: usize, cell: Cell) bool {
        if (!self.painted or column >= self.columns or row >= self.rows) return false;
        const glyph = font.glyph(cell.character);
        const foreground = self.foregrounds[@intFromEnum(cell.style)];
        const background = self.backgrounds[@intFromEnum(cell.style)];
        const left = self.origin_x + column * CELL_WIDTH;
        const top = self.origin_y + row * CELL_HEIGHT;
        for (0..CELL_HEIGHT) |y| {
            for (0..CELL_WIDTH) |x| {
                const ink = y >= 2 and y < 16 and x < 10 and
                    (glyph[(y - 2) / 2] & (@as(u5, 16) >> @intCast(x / 2))) != 0;
                const expected = if (ink or (cell.cursor and y >= 18)) foreground else background;
                if (self.pixels[(top + y) * self.info.pixels_per_scan_line + left + x] != expected) return false;
            }
        }
        return true;
    }
};
