const std = @import("std");
const syscall = @import("syscall");

pub fn writeAll(fd: i32, buffer: []const u8) void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const rc = syscall.write(fd, buffer[offset..]);
        if (rc <= 0) return;
        offset += @intCast(rc);
    }
}

pub fn puts(text: []const u8) void {
    writeAll(syscall.STDOUT, text);
}

pub fn eputs(text: []const u8) void {
    writeAll(syscall.STDERR, text);
}

pub fn print(comptime format: []const u8, args: anytype) void {
    var buffer: [256]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buffer, format, args) catch return;
    puts(rendered);
}

pub fn eprint(comptime format: []const u8, args: anytype) void {
    var buffer: [256]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buffer, format, args) catch return;
    eputs(rendered);
}
