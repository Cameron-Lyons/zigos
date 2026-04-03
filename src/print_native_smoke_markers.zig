const std = @import("std");
const smoke_markers = @import("native_smoke_markers.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);

    if (args.len != 2) {
        try stderr_writer.interface.print(
            "usage: {s} <ready|cold_boot|boot2_reloaded_phase4|boot2_fresh_phase4>\n",
            .{args[0]},
        );
        try stderr_writer.interface.flush();
        return error.InvalidArguments;
    }

    const group = args[1];
    if (std.mem.eql(u8, group, "ready")) {
        try stdout_writer.interface.print("{s}\n", .{smoke_markers.ready});
    } else if (std.mem.eql(u8, group, "cold_boot")) {
        for (smoke_markers.cold_boot_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "boot2_reloaded_phase4")) {
        for (smoke_markers.boot2_reloaded_phase4_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "boot2_fresh_phase4")) {
        for (smoke_markers.boot2_fresh_phase4_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else {
        try stderr_writer.interface.print("unknown marker group: {s}\n", .{group});
        try stderr_writer.interface.flush();
        return error.InvalidArguments;
    }

    try stdout_writer.interface.flush();
}
