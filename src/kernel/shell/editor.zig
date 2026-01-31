// zlint-disable suppressed-errors
const vga = @import("../drivers/vga.zig");
const vfs = @import("../fs/vfs.zig");
const memory = @import("../memory/memory.zig");

const MAX_LINES = 100;
const MAX_LINE_LENGTH = 256;
const SCREEN_HEIGHT = 25;
const SCREEN_WIDTH = 80;

pub const TextEditor = struct {
    lines: [][]u8,
    line_count: usize,
    cursor_x: usize,
    cursor_y: usize,
    scroll_y: usize,
    filename: []const u8,
    modified: bool,
    running: bool,
    allocator: *memory.Allocator,

    pub fn init(allocator: *memory.Allocator) !TextEditor {
        const lines = try allocator.alloc([]u8, MAX_LINES);
        for (lines) |*line| {
            line.* = try allocator.alloc(u8, MAX_LINE_LENGTH);
            @memset(line.*, 0);
        }

        return TextEditor{
            .lines = lines,
            .line_count = 1,
            .cursor_x = 0,
            .cursor_y = 0,
            .scroll_y = 0,
            .filename = "",
            .modified = false,
            .running = true,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TextEditor) void {
        for (self.lines) |line| {
            self.allocator.free(line);
        }
        const lines_bytes = @as([*]u8, @ptrCast(self.lines.ptr))[0..(@sizeOf([]u8) * self.lines.len)];
        self.allocator.free(lines_bytes);
    }

    pub fn loadFile(self: *TextEditor, filename: []const u8) !void {
        self.filename = filename;


        const fd = vfs.open(filename, vfs.O_RDONLY) catch {

            self.line_count = 1;
            @memset(self.lines[0], 0);
            return;
        };
        defer vfs.close(fd) catch {};


        // SAFETY: filled by the subsequent vfs.read call
        var buffer: [4096]u8 = undefined;
        var line_idx: usize = 0;
        var char_idx: usize = 0;

        while (true) {
            const bytes_read = try vfs.read(fd, &buffer);
            if (bytes_read == 0) break;

            for (buffer[0..bytes_read]) |char| {
                if (char == '\n') {
                    self.lines[line_idx][char_idx] = 0;
                    line_idx += 1;
                    char_idx = 0;
                    if (line_idx >= MAX_LINES) break;
                } else if (char_idx < MAX_LINE_LENGTH - 1) {
                    self.lines[line_idx][char_idx] = char;
                    char_idx += 1;
                }
            }

            if (line_idx >= MAX_LINES) break;
        }

        if (char_idx > 0) {
            self.lines[line_idx][char_idx] = 0;
            line_idx += 1;
        }

        self.line_count = if (line_idx == 0) 1 else line_idx;
        self.modified = false;
    }

    pub fn saveFile(self: *TextEditor) !void {
        const fd = try vfs.open(self.filename, vfs.O_WRONLY | vfs.O_CREAT | vfs.O_TRUNC);
        defer vfs.close(fd) catch {};

        var i: usize = 0;
        while (i < self.line_count) : (i += 1) {
            const line = self.lines[i];
            var len: usize = 0;
            while (len < MAX_LINE_LENGTH and line[len] != 0) : (len += 1) {}

            if (len > 0) {
                _ = try vfs.write(fd, line[0..len]);
            }

            if (i < self.line_count - 1) {
                _ = try vfs.write(fd, "\n");
            }
        }

        self.modified = false;
    }

    pub fn draw(self: *TextEditor) void {
        vga.clear();


        vga.print("[EDITOR] ");
        if (self.filename.len > 0) {
            for (self.filename) |c| vga.put_char(c);
        } else {
            vga.print("New File");
        }
        if (self.modified) {
            vga.print(" *");
        }
        vga.print(" Line:");
        printNumber(self.cursor_y + 1);
        vga.print("/");
        printNumber(self.line_count);
        vga.print("\n");


        var i: usize = 0;
        while (i < SCREEN_WIDTH) : (i += 1) {
            vga.put_char('-');
        }
        vga.put_char('\n');


        var screen_y: usize = 2;
        var file_y = self.scroll_y;

        while (screen_y < SCREEN_HEIGHT - 2 and file_y < self.line_count) {
            const line = self.lines[file_y];
            var x: usize = 0;
            while (x < MAX_LINE_LENGTH and line[x] != 0) : (x += 1) {
                if (x < SCREEN_WIDTH) {
                    vga.put_char(line[x]);
                }
            }
            vga.put_char('\n');

            screen_y += 1;
            file_y += 1;
        }


        while (screen_y < SCREEN_HEIGHT - 2) : (screen_y += 1) {
            vga.put_char('~');
            vga.put_char('\n');
        }


        i = 0;
        while (i < SCREEN_WIDTH) : (i += 1) {
            vga.put_char('-');
        }
        vga.put_char('\n');
        vga.print("^S:Save ^Q:Quit ^X:Exit without save");
    }

    pub fn handleKey(self: *TextEditor, key: u8) void {
        switch (key) {

            0x13 => {
                self.saveFile() catch {
                    self.showMessage("Failed to save file!");
                    return;
                };
                self.showMessage("File saved");
            },

            0x11 => {
                if (self.modified) {
                    self.showMessage("Unsaved changes! Press ^Q again to quit");
                    self.modified = false;
                } else {
                    self.running = false;
                }
            },

            0x08 => {
                if (self.cursor_x > 0) {

                    const line = self.lines[self.cursor_y];
                    var i = self.cursor_x - 1;
                    while (i < MAX_LINE_LENGTH - 1 and line[i + 1] != 0) : (i += 1) {
                        line[i] = line[i + 1];
                    }
                    line[i] = 0;
                    self.cursor_x -= 1;
                    self.modified = true;
                } else if (self.cursor_y > 0) {

                    self.cursor_y -= 1;
                    const prev_line = self.lines[self.cursor_y];
                    var prev_len: usize = 0;
                    while (prev_len < MAX_LINE_LENGTH and prev_line[prev_len] != 0) : (prev_len += 1) {}

                    const curr_line = self.lines[self.cursor_y + 1];
                    var curr_len: usize = 0;
                    while (curr_len < MAX_LINE_LENGTH and curr_line[curr_len] != 0) : (curr_len += 1) {}


                    var i: usize = 0;
                    while (i < curr_len and prev_len + i < MAX_LINE_LENGTH - 1) : (i += 1) {
                        prev_line[prev_len + i] = curr_line[i];
                    }
                    prev_line[prev_len + i] = 0;


                    var y = self.cursor_y + 1;
                    while (y < self.line_count - 1) : (y += 1) {
                        @memcpy(self.lines[y], self.lines[y + 1]);
                    }
                    self.line_count -= 1;
                    self.cursor_x = prev_len;
                    self.modified = true;
                }
            },

            '\n' => {
                if (self.line_count < MAX_LINES - 1) {

                    const line = self.lines[self.cursor_y];
                    var new_line = self.lines[self.line_count];


                    var i: usize = 0;
                    while (self.cursor_x + i < MAX_LINE_LENGTH and line[self.cursor_x + i] != 0) : (i += 1) {
                        new_line[i] = line[self.cursor_x + i];
                    }
                    new_line[i] = 0;
                    line[self.cursor_x] = 0;


                    var y = self.line_count;
                    while (y > self.cursor_y + 1) : (y -= 1) {
                        @memcpy(self.lines[y], self.lines[y - 1]);
                    }
                    @memcpy(self.lines[self.cursor_y + 1], new_line);

                    self.line_count += 1;
                    self.cursor_y += 1;
                    self.cursor_x = 0;
                    self.modified = true;
                }
            },

            else => {

                if (key >= 32 and key < 127) {
                    const line = self.lines[self.cursor_y];
                    var len: usize = 0;
                    while (len < MAX_LINE_LENGTH and line[len] != 0) : (len += 1) {}

                    if (len < MAX_LINE_LENGTH - 1) {

                        var i = len;
                        while (i > self.cursor_x) : (i -= 1) {
                            line[i] = line[i - 1];
                        }
                        line[self.cursor_x] = key;
                        line[len + 1] = 0;
                        self.cursor_x += 1;
                        self.modified = true;
                    }
                }
            },
        }


        if (self.cursor_y < self.scroll_y) {
            self.scroll_y = self.cursor_y;
        } else if (self.cursor_y >= self.scroll_y + SCREEN_HEIGHT - 2) {
            self.scroll_y = self.cursor_y - (SCREEN_HEIGHT - 3);
        }
    }

    fn showMessage(self: *TextEditor, msg: []const u8) void {
        _ = self;
        vga.print("\n[");
        for (msg) |c| vga.put_char(c);
        vga.print("]\n");
    }

    fn printNumber(n: usize) void {
        if (n == 0) {
            vga.put_char('0');
            return;
        }

        var num = n;
        // SAFETY: filled by the following digit extraction loop
        var digits: [20]u8 = undefined;
        var i: usize = 0;

        while (num > 0) : (i += 1) {
            digits[i] = @intCast((num % 10) + '0');
            num /= 10;
        }

        while (i > 0) {
            i -= 1;
            vga.put_char(digits[i]);
        }
    }
};