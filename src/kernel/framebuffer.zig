const std = @import("std");
const vga = @import("vga.zig");
const memory = @import("memory.zig");
const paging = @import("paging.zig");
const boot = @import("../boot/boot.zig");

pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,
    a: u8 = 255,

    pub const BLACK = Color{ .r = 0, .g = 0, .b = 0 };
    pub const WHITE = Color{ .r = 255, .g = 255, .b = 255 };
    pub const RED = Color{ .r = 255, .g = 0, .b = 0 };
    pub const GREEN = Color{ .r = 0, .g = 255, .b = 0 };
    pub const BLUE = Color{ .r = 0, .g = 0, .b = 255 };
    pub const YELLOW = Color{ .r = 255, .g = 255, .b = 0 };
    pub const CYAN = Color{ .r = 0, .g = 255, .b = 255 };
    pub const MAGENTA = Color{ .r = 255, .g = 0, .b = 255 };
    pub const GRAY = Color{ .r = 128, .g = 128, .b = 128 };

    pub fn toRGB565(self: Color) u16 {
        const r5 = (self.r >> 3) & 0x1F;
        const g6 = (self.g >> 2) & 0x3F;
        const b5 = (self.b >> 3) & 0x1F;
        return (@as(u16, r5) << 11) | (@as(u16, g6) << 5) | b5;
    }

    pub fn toRGB888(self: Color) u32 {
        return (@as(u32, self.r) << 16) | (@as(u32, self.g) << 8) | self.b;
    }

    pub fn toARGB8888(self: Color) u32 {
        return (@as(u32, self.a) << 24) | (@as(u32, self.r) << 16) | (@as(u32, self.g) << 8) | self.b;
    }
};

pub const FramebufferInfo = struct {
    address: usize,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u8,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
    red_mask_size: u8,
    green_mask_size: u8,
    blue_mask_size: u8,
};

pub const Font = struct {
    data: [*]const u8,
    width: u8,
    height: u8,
    bytes_per_glyph: u16,

    pub fn getGlyph(self: Font, char: u8) []const u8 {
        const offset = @as(u16, char) * self.bytes_per_glyph;
        return self.data[offset..offset + self.bytes_per_glyph];
    }
};

const PSF2Header = extern struct {
    magic: [4]u8,
    version: u32,
    header_size: u32,
    flags: u32,
    num_glyphs: u32,
    bytes_per_glyph: u32,
    height: u32,
    width: u32,
};

var framebuffer: ?FramebufferInfo = null;
var back_buffer: ?[*]u8 = null;
var cursor_x: u32 = 0;
var cursor_y: u32 = 0;
var text_color: Color = Color.WHITE;
var bg_color: Color = Color.BLACK;
var default_font: ?Font = null;

pub fn init(fb_info: FramebufferInfo) void {
    framebuffer = fb_info;

    const num_pages = ((fb_info.height * fb_info.pitch) + 0xFFF) / 0x1000;
    var i: usize = 0;
    while (i < num_pages) : (i += 1) {
        const virt_addr = fb_info.address + (i * 0x1000);
        const phys_addr = fb_info.address + (i * 0x1000);
        paging.mapPage(virt_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_WRITE_THROUGH) catch {};
    }

    const buffer_size = fb_info.height * fb_info.pitch;
    const buffer_mem = memory.kmalloc(buffer_size) orelse {
        vga.print("Failed to allocate back buffer\n");
        return;
    };
    back_buffer = @as([*]u8, @ptrCast(buffer_mem));

    initDefaultFont();

    clear(Color.BLACK);

    vga.print("Framebuffer initialized: ");
    printNumber(fb_info.width);
    vga.print("x");
    printNumber(fb_info.height);
    vga.print("x");
    printNumber(fb_info.bpp);
    vga.print("bpp\n");
}

fn initDefaultFont() void {
    const font_data = @embedFile("font8x16.psf");

    if (font_data.len >= @sizeOf(PSF2Header)) {
        const header = @as(*const PSF2Header, @ptrCast(@alignCast(font_data.ptr)));
        if (std.mem.eql(u8, &header.magic, "\x72\xB5\x4A\x86")) {
            default_font = Font{
                .data = font_data.ptr + header.header_size,
                .width = @as(u8, @intCast(header.width)),
                .height = @as(u8, @intCast(header.height)),
                .bytes_per_glyph = @as(u16, @intCast(header.bytes_per_glyph)),
            };
            return;
        }
    }

    default_font = Font{
        .data = @as([*]const u8, @ptrCast(&BUILTIN_FONT)),
        .width = 8,
        .height = 16,
        .bytes_per_glyph = 16,
    };
}

const BUILTIN_FONT = [256 * 16]u8{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x7E, 0x81, 0xA5, 0x81, 0x81, 0xBD, 0x99, 0x81, 0x81, 0x7E, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
} ++ ([_]u8{0} ** (256 * 16 - 48));

pub fn clear(color: Color) void {
    const fb = framebuffer orelse return;

    if (fb.bpp == 32) {
        const pixels = @as([*]u32, @ptrCast(@alignCast(back_buffer orelse return)));
        const pixel_count = fb.width * fb.height;
        const color_value = color.toARGB8888();
        for (0..pixel_count) |i| {
            pixels[i] = color_value;
        }
    } else if (fb.bpp == 24) {
        const pixels = back_buffer orelse return;
        const pixel_count = fb.width * fb.height;
        for (0..pixel_count) |i| {
            const offset = i * 3;
            pixels[offset] = color.b;
            pixels[offset + 1] = color.g;
            pixels[offset + 2] = color.r;
        }
    } else if (fb.bpp == 16) {
        const pixels = @as([*]u16, @ptrCast(@alignCast(back_buffer orelse return)));
        const pixel_count = fb.width * fb.height;
        const color_value = color.toRGB565();
        for (0..pixel_count) |i| {
            pixels[i] = color_value;
        }
    }

    cursor_x = 0;
    cursor_y = 0;
}

pub fn putPixel(x: u32, y: u32, color: Color) void {
    const fb = framebuffer orelse return;
    const buffer = back_buffer orelse return;

    if (x >= fb.width or y >= fb.height) return;

    const offset = y * fb.pitch + x * (fb.bpp / 8);

    if (fb.bpp == 32) {
        const pixel = @as(*u32, @ptrCast(@alignCast(&buffer[offset])));
        pixel.* = color.toARGB8888();
    } else if (fb.bpp == 24) {
        buffer[offset] = color.b;
        buffer[offset + 1] = color.g;
        buffer[offset + 2] = color.r;
    } else if (fb.bpp == 16) {
        const pixel = @as(*u16, @ptrCast(@alignCast(&buffer[offset])));
        pixel.* = color.toRGB565();
    }
}

pub fn drawLine(x0: i32, y0: i32, x1: i32, y1: i32, color: Color) void {
    var x = x0;
    var y = y0;
    const dx = if (x1 > x0) x1 - x0 else x0 - x1;
    const dy = if (y1 > y0) y1 - y0 else y0 - y1;
    const sx: i32 = if (x0 < x1) 1 else -1;
    const sy: i32 = if (y0 < y1) 1 else -1;
    var err = dx - dy;

    while (true) {
        if (x >= 0 and y >= 0) {
            putPixel(@as(u32, @intCast(x)), @as(u32, @intCast(y)), color);
        }

        if (x == x1 and y == y1) break;

        const e2 = 2 * err;
        if (e2 > -dy) {
            err -= dy;
            x += sx;
        }
        if (e2 < dx) {
            err += dx;
            y += sy;
        }
    }
}

pub fn drawRect(x: u32, y: u32, width: u32, height: u32, color: Color) void {
    drawLine(@as(i32, @intCast(x)), @as(i32, @intCast(y)), @as(i32, @intCast(x + width - 1)), @as(i32, @intCast(y)), color);
    drawLine(@as(i32, @intCast(x)), @as(i32, @intCast(y + height - 1)), @as(i32, @intCast(x + width - 1)), @as(i32, @intCast(y + height - 1)), color);
    drawLine(@as(i32, @intCast(x)), @as(i32, @intCast(y)), @as(i32, @intCast(x)), @as(i32, @intCast(y + height - 1)), color);
    drawLine(@as(i32, @intCast(x + width - 1)), @as(i32, @intCast(y)), @as(i32, @intCast(x + width - 1)), @as(i32, @intCast(y + height - 1)), color);
}

pub fn fillRect(x: u32, y: u32, width: u32, height: u32, color: Color) void {
    const fb = framebuffer orelse return;

    const x_end = @min(x + width, fb.width);
    const y_end = @min(y + height, fb.height);

    var py = y;
    while (py < y_end) : (py += 1) {
        var px = x;
        while (px < x_end) : (px += 1) {
            putPixel(px, py, color);
        }
    }
}

pub fn drawCircle(cx: i32, cy: i32, radius: i32, color: Color) void {
    var x = radius;
    var y: i32 = 0;
    var err: i32 = 0;

    while (x >= y) {
        putPixel(@as(u32, @intCast(cx + x)), @as(u32, @intCast(cy + y)), color);
        putPixel(@as(u32, @intCast(cx + y)), @as(u32, @intCast(cy + x)), color);
        putPixel(@as(u32, @intCast(cx - y)), @as(u32, @intCast(cy + x)), color);
        putPixel(@as(u32, @intCast(cx - x)), @as(u32, @intCast(cy + y)), color);
        putPixel(@as(u32, @intCast(cx - x)), @as(u32, @intCast(cy - y)), color);
        putPixel(@as(u32, @intCast(cx - y)), @as(u32, @intCast(cy - x)), color);
        putPixel(@as(u32, @intCast(cx + y)), @as(u32, @intCast(cy - x)), color);
        putPixel(@as(u32, @intCast(cx + x)), @as(u32, @intCast(cy - y)), color);

        if (err <= 0) {
            y += 1;
            err += 2 * y + 1;
        }
        if (err > 0) {
            x -= 1;
            err -= 2 * x + 1;
        }
    }
}

pub fn drawChar(x: u32, y: u32, char: u8, color: Color) void {
    const font = default_font orelse return;
    const fb = framebuffer orelse return;

    const glyph = font.getGlyph(char);

    var py: u32 = 0;
    while (py < font.height) : (py += 1) {
        if (y + py >= fb.height) break;

        var px: u32 = 0;
        while (px < font.width) : (px += 1) {
            if (x + px >= fb.width) break;

            const byte_index = py * ((font.width + 7) / 8) + (px / 8);
            const bit_index = @as(u3, @intCast(7 - (px % 8)));

            if (byte_index < font.bytes_per_glyph) {
                if ((glyph[byte_index] >> bit_index) & 1 != 0) {
                    putPixel(x + px, y + py, color);
                }
            }
        }
    }
}

pub fn drawString(x: u32, y: u32, str: []const u8, color: Color) void {
    const font = default_font orelse return;
    var cx = x;
    var cy = y;

    for (str) |char| {
        if (char == '\n') {
            cx = x;
            cy += font.height;
        } else {
            drawChar(cx, cy, char, color);
            cx += font.width;
        }
    }
}

pub fn printChar(char: u8) void {
    const fb = framebuffer orelse return;
    const font = default_font orelse return;

    if (char == '\n') {
        cursor_x = 0;
        cursor_y += font.height;
        if (cursor_y + font.height > fb.height) {
            scrollUp();
            cursor_y -= font.height;
        }
    } else if (char == '\r') {
        cursor_x = 0;
    } else if (char == '\t') {
        cursor_x = ((cursor_x / (font.width * 4)) + 1) * (font.width * 4);
        if (cursor_x >= fb.width) {
            cursor_x = 0;
            cursor_y += font.height;
        }
    } else {
        drawChar(cursor_x, cursor_y, char, text_color);
        cursor_x += font.width;

        if (cursor_x + font.width > fb.width) {
            cursor_x = 0;
            cursor_y += font.height;
            if (cursor_y + font.height > fb.height) {
                scrollUp();
                cursor_y -= font.height;
            }
        }
    }
}

pub fn print(str: []const u8) void {
    for (str) |char| {
        printChar(char);
    }
    flip();
}

fn scrollUp() void {
    const fb = framebuffer orelse return;
    const buffer = back_buffer orelse return;
    const font = default_font orelse return;

    const scroll_lines = font.height;
    const bytes_to_move = fb.pitch * (fb.height - scroll_lines);
    const bytes_to_clear = fb.pitch * scroll_lines;

    @memcpy(buffer[0..bytes_to_move], buffer[fb.pitch * scroll_lines..fb.pitch * scroll_lines + bytes_to_move]);

    if (fb.bpp == 32) {
        const clear_start = @as([*]u32, @ptrCast(@alignCast(&buffer[bytes_to_move])));
        const clear_count = bytes_to_clear / 4;
        const bg_value = bg_color.toARGB8888();
        for (0..clear_count) |i| {
            clear_start[i] = bg_value;
        }
    } else {
        @memset(buffer[bytes_to_move..bytes_to_move + bytes_to_clear], 0);
    }
}

pub fn flip() void {
    const fb = framebuffer orelse return;
    const buffer = back_buffer orelse return;

    const fb_mem = @as([*]u8, @ptrFromInt(fb.address));
    const size = fb.height * fb.pitch;
    @memcpy(fb_mem[0..size], buffer[0..size]);
}

pub fn setTextColor(color: Color) void {
    text_color = color;
}

pub fn setBackgroundColor(color: Color) void {
    bg_color = color;
}

pub fn getWidth() u32 {
    const fb = framebuffer orelse return 0;
    return fb.width;
}

pub fn getHeight() u32 {
    const fb = framebuffer orelse return 0;
    return fb.height;
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.printChar('0');
        return;
    }

    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @as(u8, @intCast('0' + (n % 10)));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.printChar(digits[i]);
    }
}

pub fn drawBitmap(x: u32, y: u32, width: u32, height: u32, data: []const u8) void {
    const fb = framebuffer orelse return;

    var py: u32 = 0;
    while (py < height) : (py += 1) {
        if (y + py >= fb.height) break;

        var px: u32 = 0;
        while (px < width) : (px += 1) {
            if (x + px >= fb.width) break;

            const pixel_index = (py * width + px) * 3;
            if (pixel_index + 2 < data.len) {
                const color = Color{
                    .r = data[pixel_index + 2],
                    .g = data[pixel_index + 1],
                    .b = data[pixel_index],
                };
                putPixel(x + px, y + py, color);
            }
        }
    }
}

pub fn isInitialized() bool {
    return framebuffer != null;
}