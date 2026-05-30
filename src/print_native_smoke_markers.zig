const std = @import("std");
const smoke_markers = @import("native_smoke_markers.zig");

const stdout_buffer_bytes: usize = 1024;
const stderr_buffer_bytes: usize = 256;

const MarkerGroup = struct {
    name: []const u8,
    markers: []const []const u8,
};

const ready_required = [_][]const u8{smoke_markers.ready};

const marker_groups = [_]MarkerGroup{
    .{ .name = "ready", .markers = &ready_required },
    .{ .name = "cold_boot", .markers = &smoke_markers.cold_boot_required },
    .{ .name = "first_boot", .markers = &smoke_markers.first_boot_required },
    .{ .name = "cold_reboot", .markers = &smoke_markers.cold_reboot_required },
    .{ .name = "driver_restart", .markers = &smoke_markers.driver_restart_required },
    .{ .name = "ab_rollback", .markers = &smoke_markers.ab_rollback_required },
    .{ .name = "tampered_artifact_manifest", .markers = &smoke_markers.tampered_artifact_manifest_required },
    .{ .name = "tampered_kernel", .markers = &smoke_markers.tampered_kernel_required },
    .{ .name = "tampered_userspace_image", .markers = &smoke_markers.tampered_userspace_image_required },
    .{ .name = "tampered_policy", .markers = &smoke_markers.tampered_policy_required },
    .{ .name = "tampered_driver_set", .markers = &smoke_markers.tampered_driver_set_required },
    .{ .name = "rollback_slot_failure", .markers = &smoke_markers.rollback_slot_failure_required },
    .{ .name = "storage_durability", .markers = &smoke_markers.storage_durability_required },
    .{ .name = "sync_two_node", .markers = &smoke_markers.sync_two_node_required },
    .{ .name = "recovery", .markers = &smoke_markers.recovery_required },
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;

    var stdout_buffer: [stdout_buffer_bytes]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    var stderr_buffer: [stderr_buffer_bytes]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);

    if (args.len != 2) {
        try printUsage(&stderr_writer.interface, args[0]);
        try stderr_writer.interface.flush();
        return error.InvalidArguments;
    }

    const group = args[1];
    const marker_group = findMarkerGroup(group) orelse {
        try stderr_writer.interface.print("unknown marker group: {s}\n", .{group});
        try stderr_writer.interface.flush();
        return error.InvalidArguments;
    };
    for (marker_group.markers) |line| {
        try stdout_writer.interface.print("{s}\n", .{line});
    }

    try stdout_writer.interface.flush();
}

fn findMarkerGroup(name: []const u8) ?MarkerGroup {
    for (marker_groups) |group| {
        if (std.mem.eql(u8, group.name, name)) return group;
    }
    return null;
}

fn printUsage(writer: *std.Io.Writer, program: []const u8) !void {
    try writer.print("usage: {s} <", .{program});
    for (marker_groups, 0..) |group, index| {
        if (index != 0) try writer.print("|", .{});
        try writer.print("{s}", .{group.name});
    }
    try writer.print(">\n", .{});
}
