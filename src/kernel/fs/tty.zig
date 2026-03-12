const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const abi = @import("../process/syscall/abi.zig");
const console = @import("../utils/console.zig");
const keyboard = @import("../drivers/keyboard.zig");
const serial = @import("../drivers/serial.zig");
const protection = @import("../memory/protection.zig");
const vt = @import("../devices/vt.zig");
const vfs = @import("vfs.zig");

const SCREEN_ROWS: u16 = 25;
const SCREEN_COLS: u16 = 80;

pub const Termios = extern struct {
    c_iflag: u32 = 0,
    c_oflag: u32 = 0,
    c_cflag: u32 = 0,
    c_lflag: u32 = abi.TTY_LFLAG_ISIG | abi.TTY_LFLAG_ICANON | abi.TTY_LFLAG_ECHO,
    c_line: u8 = 0,
    c_cc: [19]u8 = [_]u8{0} ** 19,
};

pub const WinSize = extern struct {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
};

var active_termios = Termios{};

fn winSize() WinSize {
    return .{
        .ws_row = SCREEN_ROWS,
        .ws_col = SCREEN_COLS,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };
}

fn isCanonical() bool {
    return (active_termios.c_lflag & abi.TTY_LFLAG_ICANON) != 0;
}

pub fn read(buffer: []u8) usize {
    if (buffer.len == 0) return 0;

    var read_count: usize = 0;
    while (read_count < buffer.len) {
        while (!keyboard.has_char()) {
            x86.hlt();
        }

        const ch = keyboard.getchar() orelse continue;
        buffer[read_count] = ch;
        read_count += 1;

        if (isCanonical()) {
            if (ch == '\n') break;
        } else {
            break;
        }
    }

    return read_count;
}

pub fn write(buffer: []const u8) void {
    if (vt.isInitialized()) {
        vt.getCurrentTerminal().write(buffer);
        serial.print(buffer);
        return;
    }

    console.print(buffer);
}

pub fn ioctl(request: u32, arg: usize) i32 {
    switch (request) {
        abi.TCGETS => {
            if (!protection.verifyUserPointer(arg, @sizeOf(Termios))) return abi.EFAULT;
            protection.copyToUser(arg, std.mem.asBytes(&active_termios)) catch return abi.EFAULT;
            return 0;
        },
        abi.TCSETS, abi.TCSETSW, abi.TCSETSF => {
            if (!protection.verifyUserPointer(arg, @sizeOf(Termios))) return abi.EFAULT;
            protection.copyFromUser(std.mem.asBytes(&active_termios), arg) catch return abi.EFAULT;
            return 0;
        },
        abi.TIOCGWINSZ => {
            if (!protection.verifyUserPointer(arg, @sizeOf(WinSize))) return abi.EFAULT;
            const size = winSize();
            protection.copyToUser(arg, std.mem.asBytes(&size)) catch return abi.EFAULT;
            return 0;
        },
        else => return abi.ENOTTY,
    }
}

pub fn isTtyVNode(vnode: *const vfs.VNode) bool {
    return vnode.file_type == .CharDevice and
        vnode.name_len == 3 and
        std.mem.eql(u8, vnode.name[0..vnode.name_len], "tty");
}
