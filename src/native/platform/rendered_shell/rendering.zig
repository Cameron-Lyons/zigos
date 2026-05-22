const std = @import("std");

pub fn renderControl(buffer: []u8, used: *usize, name: []const u8, done: bool) !void {
    try appendFmt(buffer, used, "control={s} state={s}\n", .{ name, if (done) "done" else "ready" });
}

pub fn appendFmt(buffer: []u8, used: *usize, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.bufPrint(buffer[used.*..], fmt, args);
    used.* += rendered.len;
}
