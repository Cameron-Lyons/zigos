const std = @import("std");
const vga = @import("vga.zig");
const shell = @import("../shell/shell.zig");

var char_buffer: [256]u8 = undefined;
var buffer_start: usize = 0;
var buffer_end: usize = 0;

const KEYBOARD_DATA_PORT: u16 = 0x60;
const KEYBOARD_STATUS_PORT: u16 = 0x64;

const KeyboardScancode = enum(u8) {
    escape = 0x01,
    one = 0x02,
    two = 0x03,
    three = 0x04,
    four = 0x05,
    five = 0x06,
    six = 0x07,
    seven = 0x08,
    eight = 0x09,
    nine = 0x0A,
    zero = 0x0B,
    minus = 0x0C,
    equal = 0x0D,
    backspace = 0x0E,
    tab = 0x0F,
    q = 0x10,
    w = 0x11,
    e = 0x12,
    r = 0x13,
    t = 0x14,
    y = 0x15,
    u = 0x16,
    i = 0x17,
    o = 0x18,
    p = 0x19,
    left_bracket = 0x1A,
    right_bracket = 0x1B,
    enter = 0x1C,
    left_ctrl = 0x1D,
    a = 0x1E,
    s = 0x1F,
    d = 0x20,
    f = 0x21,
    g = 0x22,
    h = 0x23,
    j = 0x24,
    k = 0x25,
    l = 0x26,
    semicolon = 0x27,
    apostrophe = 0x28,
    grave = 0x29,
    left_shift = 0x2A,
    backslash = 0x2B,
    z = 0x2C,
    x = 0x2D,
    c = 0x2E,
    v = 0x2F,
    b = 0x30,
    n = 0x31,
    m = 0x32,
    comma = 0x33,
    period = 0x34,
    slash = 0x35,
    right_shift = 0x36,
    keypad_asterisk = 0x37,
    left_alt = 0x38,
    space = 0x39,
    caps_lock = 0x3A,
    f1 = 0x3B,
    f2 = 0x3C,
    f3 = 0x3D,
    f4 = 0x3E,
    f5 = 0x3F,
    f6 = 0x40,
    f7 = 0x41,
    f8 = 0x42,
    f9 = 0x43,
    f10 = 0x44,
    up_arrow = 0x48,
    down_arrow = 0x50,
    left_arrow = 0x4B,
    right_arrow = 0x4D,
    _,
};

const scancode_to_ascii = [_]u8{
    0,    27,   '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',  '0',  '-',  '=',  '\x08', '\t',
    'q',  'w',  'e',  'r',  't',  'y',  'u',  'i',  'o',  'p',  '[',  ']',  '\n', 0,    'a',  's',
    'd',  'f',  'g',  'h',  'j',  'k',  'l',  ';',  '\'', '`',  0,    '\\', 'z',  'x',  'c',  'v',
    'b',  'n',  'm',  ',',  '.',  '/',  0,    '*',  0,    ' ',  0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    '-',  0,    0,    0,    '+',  0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

const scancode_to_ascii_shift = [_]u8{
    0,    27,   '!',  '@',  '#',  '$',  '%',  '^',  '&',  '*',  '(',  ')',  '_',  '+',  '\x08', '\t',
    'Q',  'W',  'E',  'R',  'T',  'Y',  'U',  'I',  'O',  'P',  '{',  '}',  '\n', 0,    'A',  'S',
    'D',  'F',  'G',  'H',  'J',  'K',  'L',  ':',  '"',  '~',  0,    '|',  'Z',  'X',  'C',  'V',
    'B',  'N',  'M',  '<',  '>',  '?',  0,    '*',  0,    ' ',  0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    '-',  0,    0,    0,    '+',  0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

var shift_pressed: bool = false;
var ctrl_pressed: bool = false;
var alt_pressed: bool = false;
var caps_lock: bool = false;
var keyboard_shell: ?*shell.Shell = null;

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

pub fn handleInterrupt() void {
    const scancode = inb(KEYBOARD_DATA_PORT);

    if ((scancode & 0x80) != 0) {
        const key_release = scancode & 0x7F;
        switch (key_release) {
            @intFromEnum(KeyboardScancode.left_shift), @intFromEnum(KeyboardScancode.right_shift) => {
                shift_pressed = false;
            },
            @intFromEnum(KeyboardScancode.left_ctrl) => {
                ctrl_pressed = false;
            },
            @intFromEnum(KeyboardScancode.left_alt) => {
                alt_pressed = false;
            },
            else => {},
        }
    } else {
        switch (scancode) {
            @intFromEnum(KeyboardScancode.left_shift), @intFromEnum(KeyboardScancode.right_shift) => {
                shift_pressed = true;
            },
            @intFromEnum(KeyboardScancode.left_ctrl) => {
                ctrl_pressed = true;
            },
            @intFromEnum(KeyboardScancode.left_alt) => {
                alt_pressed = true;
            },
            @intFromEnum(KeyboardScancode.caps_lock) => {
                caps_lock = !caps_lock;
            },
            @intFromEnum(KeyboardScancode.tab) => {
                if (keyboard_shell) |sh| {
                    sh.handleTabCompletion();
                }
            },
            @intFromEnum(KeyboardScancode.up_arrow) => {
                if (keyboard_shell) |sh| {
                    sh.handleArrowKey(.Up);
                }
            },
            @intFromEnum(KeyboardScancode.down_arrow) => {
                if (keyboard_shell) |sh| {
                    sh.handleArrowKey(.Down);
                }
            },
            @intFromEnum(KeyboardScancode.left_arrow) => {
                if (keyboard_shell) |sh| {
                    sh.handleArrowKey(.Left);
                }
            },
            @intFromEnum(KeyboardScancode.right_arrow) => {
                if (keyboard_shell) |sh| {
                    sh.handleArrowKey(.Right);
                }
            },
            else => {
                if (scancode < scancode_to_ascii.len) {
                    var ch: u8 = 0;

                    if (shift_pressed or (caps_lock and isAlpha(scancode_to_ascii[scancode]))) {
                        ch = scancode_to_ascii_shift[scancode];
                    } else {
                        ch = scancode_to_ascii[scancode];
                    }

                    if (ch != 0) {
                        put_char_buffer(ch);

                        if (keyboard_shell) |sh| {
                            sh.handleChar(ch);
                        } else {
                            if (ch == '\n') {
                                vga.print("\n");
                            } else if (ch == '\x08') {
                                vga.print("\x08 \x08");
                            } else {
                                var buf: [2]u8 = .{ ch, 0 };
                                vga.print(&buf);
                            }
                        }
                    }
                }
            },
        }
    }
}

fn isAlpha(ch: u8) bool {
    return (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z');
}

pub fn init() void {
    while (inb(KEYBOARD_STATUS_PORT) & 0x01 != 0) {
        _ = inb(KEYBOARD_DATA_PORT);
    }
}

pub fn setShell(sh: *shell.Shell) void {
    keyboard_shell = sh;
}

pub fn has_char() bool {
    return buffer_start != buffer_end;
}

pub fn getchar() ?u8 {
    if (buffer_start == buffer_end) {
        return null;
    }

    const ch = char_buffer[buffer_start];
    buffer_start = (buffer_start + 1) % char_buffer.len;
    return ch;
}

fn put_char_buffer(ch: u8) void {
    const next_end = (buffer_end + 1) % char_buffer.len;
    if (next_end != buffer_start) {
        char_buffer[buffer_end] = ch;
        buffer_end = next_end;
    }
}