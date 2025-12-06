const VGA_WIDTH = 80;
const VGA_HEIGHT = 25;
const VGA_BUFFER = 0xB8000;

const Color = enum(u8) {
    black = 0,
    blue = 1,
    green = 2,
    cyan = 3,
    red = 4,
    magenta = 5,
    brown = 6,
    light_grey = 7,
    dark_grey = 8,
    light_blue = 9,
    light_green = 10,
    light_cyan = 11,
    light_red = 12,
    light_magenta = 13,
    light_brown = 14,
    white = 15,
};

var row: usize = 0;
var column: usize = 0;
var color: u8 = vga_entry_color(Color.light_grey, Color.black);
var buffer: [*]volatile u16 = @ptrFromInt(VGA_BUFFER);

fn vga_entry_color(fg: Color, bg: Color) u8 {
    return @intFromEnum(fg) | (@intFromEnum(bg) << 4);
}

fn vga_entry(char: u8, entry_color: u8) u16 {
    return char | (@as(u16, entry_color) << 8);
}

pub fn init() void {
    row = 0;
    column = 0;
    color = vga_entry_color(Color.light_grey, Color.black);
}

pub fn clear() void {
    for (0..VGA_HEIGHT) |y| {
        for (0..VGA_WIDTH) |x| {
            const index = y * VGA_WIDTH + x;
            buffer[index] = vga_entry(' ', color);
        }
    }
    row = 0;
    column = 0;
}

pub fn clearWithColor(new_color: u8) void {
    for (0..VGA_HEIGHT) |y| {
        for (0..VGA_WIDTH) |x| {
            const index = y * VGA_WIDTH + x;
            buffer[index] = vga_entry(' ', new_color);
        }
    }
    row = 0;
    column = 0;
    color = new_color;
}

pub fn put_char(c: u8) void {
    if (c == '\n') {
        column = 0;
        row += 1;
        if (row == VGA_HEIGHT) {
            scroll();
            row = VGA_HEIGHT - 1;
        }
        return;
    }

    if (c == '\x08') {
        if (column > 0) {
            column -= 1;
        } else if (row > 0) {
            row -= 1;
            column = VGA_WIDTH - 1;
        }
        return;
    }

    const index = row * VGA_WIDTH + column;
    buffer[index] = vga_entry(c, color);

    column += 1;
    if (column == VGA_WIDTH) {
        column = 0;
        row += 1;
        if (row == VGA_HEIGHT) {
            scroll();
            row = VGA_HEIGHT - 1;
        }
    }
}

pub fn printChar(c: u8) void {
    put_char(c);
}

pub fn print(str: []const u8) void {
    for (str) |c| {
        put_char(c);
    }
}

pub fn printWithColor(str: []const u8, new_color: u8) void {
    const old_color = color;
    color = new_color;
    for (str) |c| {
        put_char(c);
    }
    color = old_color;
}

fn scroll() void {
    for (0..VGA_HEIGHT - 1) |y| {
        for (0..VGA_WIDTH) |x| {
            const dst_index = y * VGA_WIDTH + x;
            const src_index = (y + 1) * VGA_WIDTH + x;
            buffer[dst_index] = buffer[src_index];
        }
    }

    for (0..VGA_WIDTH) |x| {
        const index = (VGA_HEIGHT - 1) * VGA_WIDTH + x;
        buffer[index] = vga_entry(' ', color);
    }
}