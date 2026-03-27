const std = @import("std");
const fsutil = @import("fsutil");
const syscall = @import("syscall");

const format_buffer_size = 256;

pub fn writeAll(fd: i32, buffer: []const u8) void {
    fsutil.writeAll(fd, buffer) catch {};
}

pub fn puts(text: []const u8) void {
    writeAll(syscall.STDOUT, text);
}

pub fn eputs(text: []const u8) void {
    writeAll(syscall.STDERR, text);
}

fn writeFormatted(fd: i32, comptime format: []const u8, args: anytype) void {
    var buffer: [format_buffer_size]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buffer, format, args) catch return;
    writeAll(fd, rendered);
}

pub fn print(comptime format: []const u8, args: anytype) void {
    writeFormatted(syscall.STDOUT, format, args);
}

pub fn eprint(comptime format: []const u8, args: anytype) void {
    writeFormatted(syscall.STDERR, format, args);
}
