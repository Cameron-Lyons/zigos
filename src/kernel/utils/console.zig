const serial = @import("../drivers/serial.zig");

pub fn init() void {
    serial.init();
}

pub fn print(str: []const u8) void {
    serial.print(str);
}

pub fn printChar(c: u8) void {
    putChar(c);
}

pub fn putChar(c: u8) void {
    serial.putChar(c);
}

pub fn printWithColor(str: []const u8, color: u8) void {
    _ = color;
    serial.print(str);
}

pub fn clear() void {}

pub fn clearWithColor(color: u8) void {
    _ = color;
}
