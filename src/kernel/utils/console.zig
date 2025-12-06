const vga = @import("../drivers/vga.zig");
const serial = @import("../drivers/serial.zig");

pub fn init() void {
    serial.init();
}

pub fn print(str: []const u8) void {
    vga.print(str);
    serial.print(str);
}

pub fn printChar(c: u8) void {
    vga.printChar(c);
    serial.putChar(c);
}

pub fn putChar(c: u8) void {
    vga.put_char(c);
    serial.putChar(c);
}

pub fn printWithColor(str: []const u8, color: u8) void {
    vga.printWithColor(str, color);
    serial.print(str);
}

pub fn clear() void {
    vga.clear();
}

pub fn clearWithColor(color: u8) void {
    vga.clearWithColor(color);
}

