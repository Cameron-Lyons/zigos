const std = @import("std");
const vga = @import("vga.zig");
const keyboard = @import("keyboard.zig");
const framebuffer = @import("framebuffer.zig");
const memory = @import("memory.zig");
const process = @import("process.zig");
const signal = @import("signal.zig");

const NUM_VIRTUAL_TERMINALS = 6;
const SCREEN_WIDTH = 80;
const SCREEN_HEIGHT = 25;
const BUFFER_SIZE = SCREEN_WIDTH * SCREEN_HEIGHT;
const SCROLLBACK_SIZE = 1000;

pub const Color = enum(u4) {
    Black = 0,
    Red = 1,
    Green = 2,
    Yellow = 3,
    Blue = 4,
    Magenta = 5,
    Cyan = 6,
    White = 7,
    BrightBlack = 8,
    BrightRed = 9,
    BrightGreen = 10,
    BrightYellow = 11,
    BrightBlue = 12,
    BrightMagenta = 13,
    BrightCyan = 14,
    BrightWhite = 15,
};

pub const Attribute = packed struct {
    fg: Color,
    bg: Color,
    bold: bool = false,
    underline: bool = false,
    blink: bool = false,
    reverse: bool = false,
    _padding: u2 = 0,
};

const Cell = struct {
    char: u8,
    attr: Attribute,
};

const CursorShape = enum {
    Block,
    Underline,
    Bar,
};

const InputMode = struct {
    echo: bool = true,
    canonical: bool = true,
    signal: bool = true,
    raw: bool = false,
};

const AnsiState = enum {
    Normal,
    Escape,
    CSI,
    OSC,
};

pub const VirtualTerminal = struct {
    id: u8,
    active: bool,
    buffer: [BUFFER_SIZE]Cell,
    scrollback: [SCROLLBACK_SIZE][SCREEN_WIDTH]Cell,
    scrollback_pos: u32,
    cursor_x: u8,
    cursor_y: u8,
    cursor_visible: bool,
    cursor_shape: CursorShape,
    saved_cursor_x: u8,
    saved_cursor_y: u8,
    current_attr: Attribute,
    saved_attr: Attribute,
    input_buffer: [256]u8,
    input_pos: u16,
    input_mode: InputMode,
    ansi_state: AnsiState,
    ansi_params: [16]u32,
    ansi_param_count: u8,
    ansi_intermediate: u8,
    controlling_process: ?*process.Process,

    pub fn init(id: u8) VirtualTerminal {
        var vt = VirtualTerminal{
            .id = id,
            .active = false,
            .buffer = undefined,
            .scrollback = undefined,
            .scrollback_pos = 0,
            .cursor_x = 0,
            .cursor_y = 0,
            .cursor_visible = true,
            .cursor_shape = .Block,
            .saved_cursor_x = 0,
            .saved_cursor_y = 0,
            .current_attr = Attribute{
                .fg = .White,
                .bg = .Black,
            },
            .saved_attr = Attribute{
                .fg = .White,
                .bg = .Black,
            },
            .input_buffer = undefined,
            .input_pos = 0,
            .input_mode = InputMode{},
            .ansi_state = .Normal,
            .ansi_params = [_]u32{0} ** 16,
            .ansi_param_count = 0,
            .ansi_intermediate = 0,
            .controlling_process = null,
        };

        vt.clear();
        return vt;
    }

    pub fn clear(self: *VirtualTerminal) void {
        for (&self.buffer) |*cell| {
            cell.* = Cell{
                .char = ' ',
                .attr = self.current_attr,
            };
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    pub fn putChar(self: *VirtualTerminal, char: u8) void {
        switch (self.ansi_state) {
            .Normal => self.putNormalChar(char),
            .Escape => self.handleEscape(char),
            .CSI => self.handleCSI(char),
            .OSC => self.handleOSC(char),
        }

        if (self.active) {
            self.render();
        }
    }

    fn putNormalChar(self: *VirtualTerminal, char: u8) void {
        switch (char) {
            0x07 => {},
            0x08 => {
                if (self.cursor_x > 0) {
                    self.cursor_x -= 1;
                }
            },
            0x09 => {
                self.cursor_x = ((self.cursor_x / 8) + 1) * 8;
                if (self.cursor_x >= SCREEN_WIDTH) {
                    self.cursor_x = SCREEN_WIDTH - 1;
                }
            },
            0x0A => {
                self.lineFeed();
            },
            0x0C => {
                self.clear();
            },
            0x0D => {
                self.cursor_x = 0;
            },
            0x1B => {
                self.ansi_state = .Escape;
            },
            0x20...0x7E => {
                const idx = @as(usize, self.cursor_y) * SCREEN_WIDTH + self.cursor_x;
                self.buffer[idx] = Cell{
                    .char = char,
                    .attr = self.current_attr,
                };

                self.cursor_x += 1;
                if (self.cursor_x >= SCREEN_WIDTH) {
                    self.cursor_x = 0;
                    self.lineFeed();
                }
            },
            else => {},
        }
    }

    fn handleEscape(self: *VirtualTerminal, char: u8) void {
        switch (char) {
            '[' => {
                self.ansi_state = .CSI;
                self.ansi_param_count = 0;
                self.ansi_params = [_]u32{0} ** 16;
                self.ansi_intermediate = 0;
            },
            ']' => {
                self.ansi_state = .OSC;
            },
            'c' => {
                self.clear();
                self.ansi_state = .Normal;
            },
            '7' => {
                self.saved_cursor_x = self.cursor_x;
                self.saved_cursor_y = self.cursor_y;
                self.saved_attr = self.current_attr;
                self.ansi_state = .Normal;
            },
            '8' => {
                self.cursor_x = self.saved_cursor_x;
                self.cursor_y = self.saved_cursor_y;
                self.current_attr = self.saved_attr;
                self.ansi_state = .Normal;
            },
            'D' => {
                self.lineFeed();
                self.ansi_state = .Normal;
            },
            'E' => {
                self.cursor_x = 0;
                self.lineFeed();
                self.ansi_state = .Normal;
            },
            'M' => {
                if (self.cursor_y > 0) {
                    self.cursor_y -= 1;
                } else {
                    self.scrollDown();
                }
                self.ansi_state = .Normal;
            },
            else => {
                self.ansi_state = .Normal;
            },
        }
    }

    fn handleCSI(self: *VirtualTerminal, char: u8) void {
        switch (char) {
            '0'...'9' => {
                if (self.ansi_param_count == 0) {
                    self.ansi_param_count = 1;
                }
                const idx = self.ansi_param_count - 1;
                self.ansi_params[idx] = self.ansi_params[idx] * 10 + (char - '0');
            },
            ';' => {
                if (self.ansi_param_count < 16) {
                    self.ansi_param_count += 1;
                }
            },
            ' ', '!', '"', '#', '$', '%', '&', '\'', '*', '+' => {
                self.ansi_intermediate = char;
            },
            'A' => {
                const n = if (self.ansi_param_count > 0) self.ansi_params[0] else 1;
                self.cursor_y -|= @as(u8, @intCast(@min(n, self.cursor_y)));
                self.ansi_state = .Normal;
            },
            'B' => {
                const n = if (self.ansi_param_count > 0) self.ansi_params[0] else 1;
                self.cursor_y = @min(self.cursor_y + @as(u8, @intCast(n)), SCREEN_HEIGHT - 1);
                self.ansi_state = .Normal;
            },
            'C' => {
                const n = if (self.ansi_param_count > 0) self.ansi_params[0] else 1;
                self.cursor_x = @min(self.cursor_x + @as(u8, @intCast(n)), SCREEN_WIDTH - 1);
                self.ansi_state = .Normal;
            },
            'D' => {
                const n = if (self.ansi_param_count > 0) self.ansi_params[0] else 1;
                self.cursor_x -|= @as(u8, @intCast(@min(n, self.cursor_x)));
                self.ansi_state = .Normal;
            },
            'H', 'f' => {
                const row = if (self.ansi_param_count > 0) self.ansi_params[0] else 1;
                const col = if (self.ansi_param_count > 1) self.ansi_params[1] else 1;
                self.cursor_y = @as(u8, @intCast(@min(row -| 1, SCREEN_HEIGHT - 1)));
                self.cursor_x = @as(u8, @intCast(@min(col -| 1, SCREEN_WIDTH - 1)));
                self.ansi_state = .Normal;
            },
            'J' => {
                const mode = if (self.ansi_param_count > 0) self.ansi_params[0] else 0;
                self.eraseDisplay(mode);
                self.ansi_state = .Normal;
            },
            'K' => {
                const mode = if (self.ansi_param_count > 0) self.ansi_params[0] else 0;
                self.eraseLine(mode);
                self.ansi_state = .Normal;
            },
            'm' => {
                self.handleSGR();
                self.ansi_state = .Normal;
            },
            's' => {
                self.saved_cursor_x = self.cursor_x;
                self.saved_cursor_y = self.cursor_y;
                self.ansi_state = .Normal;
            },
            'u' => {
                self.cursor_x = self.saved_cursor_x;
                self.cursor_y = self.saved_cursor_y;
                self.ansi_state = .Normal;
            },
            else => {
                self.ansi_state = .Normal;
            },
        }
    }

    fn handleOSC(self: *VirtualTerminal, char: u8) void {
        if (char == 0x07 or char == 0x1B) {
            self.ansi_state = .Normal;
        }
    }

    fn handleSGR(self: *VirtualTerminal) void {
        if (self.ansi_param_count == 0) {
            self.current_attr = Attribute{
                .fg = .White,
                .bg = .Black,
            };
            return;
        }

        for (0..self.ansi_param_count) |i| {
            const param = self.ansi_params[i];
            switch (param) {
                0 => self.current_attr = Attribute{ .fg = .White, .bg = .Black },
                1 => self.current_attr.bold = true,
                4 => self.current_attr.underline = true,
                5 => self.current_attr.blink = true,
                7 => self.current_attr.reverse = true,
                22 => self.current_attr.bold = false,
                24 => self.current_attr.underline = false,
                25 => self.current_attr.blink = false,
                27 => self.current_attr.reverse = false,
                30...37 => self.current_attr.fg = @as(Color, @enumFromInt(param - 30)),
                40...47 => self.current_attr.bg = @as(Color, @enumFromInt(param - 40)),
                90...97 => self.current_attr.fg = @as(Color, @enumFromInt(param - 90 + 8)),
                100...107 => self.current_attr.bg = @as(Color, @enumFromInt(param - 100 + 8)),
                else => {},
            }
        }
    }

    fn lineFeed(self: *VirtualTerminal) void {
        if (self.cursor_y < SCREEN_HEIGHT - 1) {
            self.cursor_y += 1;
        } else {
            self.scrollUp();
        }
    }

    fn scrollUp(self: *VirtualTerminal) void {
        @memcpy(&self.scrollback[self.scrollback_pos], self.buffer[0..SCREEN_WIDTH]);
        self.scrollback_pos = (self.scrollback_pos + 1) % SCROLLBACK_SIZE;

        @memcpy(self.buffer[0..(BUFFER_SIZE - SCREEN_WIDTH)],
                self.buffer[SCREEN_WIDTH..BUFFER_SIZE]);

        const last_line_start = (SCREEN_HEIGHT - 1) * SCREEN_WIDTH;
        for (self.buffer[last_line_start..]) |*cell| {
            cell.* = Cell{
                .char = ' ',
                .attr = self.current_attr,
            };
        }
    }

    fn scrollDown(self: *VirtualTerminal) void {
        @memcpy(self.buffer[SCREEN_WIDTH..BUFFER_SIZE],
                self.buffer[0..(BUFFER_SIZE - SCREEN_WIDTH)]);

        for (self.buffer[0..SCREEN_WIDTH]) |*cell| {
            cell.* = Cell{
                .char = ' ',
                .attr = self.current_attr,
            };
        }
    }

    fn eraseDisplay(self: *VirtualTerminal, mode: u32) void {
        switch (mode) {
            0 => {
                const start = @as(usize, self.cursor_y) * SCREEN_WIDTH + self.cursor_x;
                for (self.buffer[start..]) |*cell| {
                    cell.* = Cell{ .char = ' ', .attr = self.current_attr };
                }
            },
            1 => {
                const end = @as(usize, self.cursor_y) * SCREEN_WIDTH + self.cursor_x + 1;
                for (self.buffer[0..end]) |*cell| {
                    cell.* = Cell{ .char = ' ', .attr = self.current_attr };
                }
            },
            2 => {
                self.clear();
            },
            else => {},
        }
    }

    fn eraseLine(self: *VirtualTerminal, mode: u32) void {
        const line_start = @as(usize, self.cursor_y) * SCREEN_WIDTH;
        const line_end = line_start + SCREEN_WIDTH;

        switch (mode) {
            0 => {
                const start = line_start + self.cursor_x;
                for (self.buffer[start..line_end]) |*cell| {
                    cell.* = Cell{ .char = ' ', .attr = self.current_attr };
                }
            },
            1 => {
                const end = line_start + self.cursor_x + 1;
                for (self.buffer[line_start..end]) |*cell| {
                    cell.* = Cell{ .char = ' ', .attr = self.current_attr };
                }
            },
            2 => {
                for (self.buffer[line_start..line_end]) |*cell| {
                    cell.* = Cell{ .char = ' ', .attr = self.current_attr };
                }
            },
            else => {},
        }
    }

    pub fn render(self: *VirtualTerminal) void {
        if (framebuffer.isInitialized()) {
            self.renderFramebuffer();
        } else {
            self.renderVGA();
        }
    }

    fn renderVGA(self: *VirtualTerminal) void {
        for (self.buffer, 0..) |cell, i| {
            const x = @as(u8, @intCast(i % SCREEN_WIDTH));
            const y = @as(u8, @intCast(i / SCREEN_WIDTH));

            const vga_attr = @as(u8, @intFromEnum(cell.attr.bg)) << 4 |
                            @as(u8, @intFromEnum(cell.attr.fg));

            vga.putCharAt(x, y, cell.char, vga_attr);
        }

        if (self.cursor_visible) {
            vga.setCursor(self.cursor_x, self.cursor_y);
        }
    }

    fn renderFramebuffer(self: *VirtualTerminal) void {
        _ = self;
    }

    pub fn handleInput(self: *VirtualTerminal, char: u8) void {
        if (self.input_mode.canonical) {
            if (char == '\n' or self.input_pos >= 255) {
                self.input_buffer[self.input_pos] = char;
                self.input_pos += 1;

                if (self.controlling_process) |proc| {
                    proc.wakeup();
                }

                if (self.input_mode.echo) {
                    self.putChar(char);
                }
            } else if (char == 0x08 or char == 0x7F) {
                if (self.input_pos > 0) {
                    self.input_pos -= 1;
                    if (self.input_mode.echo) {
                        self.putChar(0x08);
                        self.putChar(' ');
                        self.putChar(0x08);
                    }
                }
            } else if (char == 0x03 and self.input_mode.signal) {
                if (self.controlling_process) |proc| {
                    signal.sendSignal(proc, signal.SIGINT);
                }
            } else if (char == 0x1A and self.input_mode.signal) {
                if (self.controlling_process) |proc| {
                    signal.sendSignal(proc, signal.SIGTSTP);
                }
            } else {
                if (self.input_pos < 255) {
                    self.input_buffer[self.input_pos] = char;
                    self.input_pos += 1;

                    if (self.input_mode.echo) {
                        self.putChar(char);
                    }
                }
            }
        } else {
            if (self.input_pos < 255) {
                self.input_buffer[self.input_pos] = char;
                self.input_pos += 1;

                if (self.controlling_process) |proc| {
                    proc.wakeup();
                }
            }
        }
    }

    pub fn read(self: *VirtualTerminal, buffer: []u8) usize {
        const read_count = @min(buffer.len, self.input_pos);
        if (read_count > 0) {
            @memcpy(buffer[0..read_count], self.input_buffer[0..read_count]);

            if (read_count < self.input_pos) {
                @memcpy(self.input_buffer[0..self.input_pos - read_count],
                       self.input_buffer[read_count..self.input_pos]);
            }
            self.input_pos -= @as(u16, @intCast(read_count));
        }
        return read_count;
    }

    pub fn write(self: *VirtualTerminal, buffer: []const u8) void {
        for (buffer) |char| {
            self.putChar(char);
        }
    }
};

var virtual_terminals: [NUM_VIRTUAL_TERMINALS]VirtualTerminal = undefined;
var current_vt: u8 = 0;

pub fn init() void {
    for (&virtual_terminals, 0..) |*vt, i| {
        vt.* = VirtualTerminal.init(@as(u8, @intCast(i)));
    }

    virtual_terminals[0].active = true;
    current_vt = 0;

    vga.print("Virtual terminal support initialized\n");
}

pub fn switchTo(vt_num: u8) void {
    if (vt_num >= NUM_VIRTUAL_TERMINALS) return;

    virtual_terminals[current_vt].active = false;
    current_vt = vt_num;
    virtual_terminals[current_vt].active = true;
    virtual_terminals[current_vt].render();
}

pub fn getCurrentTerminal() *VirtualTerminal {
    return &virtual_terminals[current_vt];
}

pub fn getTerminal(vt_num: u8) ?*VirtualTerminal {
    if (vt_num >= NUM_VIRTUAL_TERMINALS) return null;
    return &virtual_terminals[vt_num];
}