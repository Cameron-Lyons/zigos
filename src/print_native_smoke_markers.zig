const std = @import("std");
const smoke_markers = @import("native_smoke_markers.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);

    if (args.len != 2) {
        try stderr_writer.interface.print(
            "usage: {s} <ready|cold_boot|first_boot|cold_reboot|driver_restart|ab_rollback|tampered_artifact_manifest|rollback_slot_failure|recovery>\n",
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
    } else if (std.mem.eql(u8, group, "first_boot")) {
        for (smoke_markers.first_boot_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "cold_reboot")) {
        for (smoke_markers.cold_reboot_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "driver_restart")) {
        for (smoke_markers.driver_restart_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "ab_rollback")) {
        for (smoke_markers.ab_rollback_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "tampered_artifact_manifest")) {
        for (smoke_markers.tampered_artifact_manifest_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "rollback_slot_failure")) {
        for (smoke_markers.rollback_slot_failure_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else if (std.mem.eql(u8, group, "recovery")) {
        for (smoke_markers.recovery_required) |line| {
            try stdout_writer.interface.print("{s}\n", .{line});
        }
    } else {
        try stderr_writer.interface.print("unknown marker group: {s}\n", .{group});
        try stderr_writer.interface.flush();
        return error.InvalidArguments;
    }

    try stdout_writer.interface.flush();
}
