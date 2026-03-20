const std = @import("std");
const shared = @import("shared.zig");

pub fn addRootfsCommand(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "bash",
        "scripts/build-rootfs.sh",
        shared.rootfs_image_path,
        "zig-out/user/bin",
        "zig-out/user/rootfs/etc",
    });
}
