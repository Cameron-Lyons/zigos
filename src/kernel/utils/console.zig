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
