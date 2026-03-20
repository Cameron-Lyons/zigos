const std = @import("std");

pub const headless_qemu_runner = "scripts/run-headless-qemu.sh";

pub fn addHeadlessRunner(
    b: *std.Build,
    kernel_output_path: []const u8,
    memory: []const u8,
    serial_target: []const u8,
) *std.Build.Step.Run {
    return b.addSystemCommand(&.{
        "bash",
        headless_qemu_runner,
        kernel_output_path,
        memory,
        serial_target,
    });
}
