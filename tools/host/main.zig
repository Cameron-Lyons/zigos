const std = @import("std");
const common = @import("common.zig");
const images = @import("images.zig");
const checks = @import("checks.zig");
const qemu = @import("qemu.zig");
const release = @import("release.zig");
const hardware = @import("hardware.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var ctx: common.Context = .{ .allocator = init.arena.allocator(), .io = init.io, .environ = init.environ_map };
    const basename = std.fs.path.basename(args[0]);
    if (std.mem.startsWith(u8, basename, "hardware-fixture-")) {
        hardware.run(&ctx, basename, args[1..]) catch |err| fail(basename, err);
        return;
    }
    if (args.len < 2 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "help")) {
        try ctx.print("Usage: zig build tool -- COMMAND [ARGUMENTS]\n\nCommands use the former script names without .sh:\n  clean-build, build-native-store, check-efi-image, check-multiboot2-image\n  build-efi-iso, build-grub-iso, check-production-boot-log\n  test-production-boot-log-checker, fmt-check, lint-shell, lint-zig, lint-actions\n  qemu-harness, run-headless-qemu, run-zigos-native-smoke\n  run-with-qemu-boot-iso, run-uefi-boot-test\n  run-x86-64-kernel-smoke, run-long-mode-entry-smoke\n  run-storage-durability-qemu, run-sync-two-node-qemu, run-tpm2-qemu\n  run-unified-efi-qemu, run-kernel-recovery, capture-kernel-benchmark\n  generate-release-sbom-provenance, check-reproducible-build\n  finalize-release-manifest, verify-release-bundle\n  prepare-nuc15crsu7-hardware-proof, write-nuc15crsu7-capture-statement\n  check-nuc15crsu7-hardware-proof, test-nuc15crsu7-hardware-proof-checker\n", .{});
        return;
    }
    dispatch(&ctx, args[1], args[2..]) catch |err| fail(args[1], err);
}

fn fail(command: []const u8, err: anyerror) noreturn {
    std.debug.print("{s}: {s}\n", .{ command, @errorName(err) });
    std.process.exit(if (err == error.Interrupted) qemu.interruptionExitCode() else if (err == error.QemuFailed) qemu.failureExitCode() else if (err == error.ChildProcessFailed) common.child_failure_exit_code else if (err == error.InvalidArguments or err == error.UnknownCommand) 2 else 1);
}

fn dispatch(ctx: *common.Context, command: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, command, "clean-build") or std.mem.startsWith(u8, command, "build-") or std.mem.eql(u8, command, "check-efi-image") or std.mem.eql(u8, command, "check-multiboot2-image") or std.mem.eql(u8, command, "check-production-boot-log") or std.mem.eql(u8, command, "test-production-boot-log-checker")) return images.run(ctx, command, args);
    if (std.mem.startsWith(u8, command, "lint-") or std.mem.eql(u8, command, "fmt-check")) return checks.run(ctx, command, args);
    if (std.mem.eql(u8, command, "qemu-harness") or std.mem.startsWith(u8, command, "run-") or std.mem.eql(u8, command, "capture-kernel-benchmark")) return qemu.run(ctx, command, args);
    if (std.mem.indexOf(u8, command, "nuc15crsu7") != null) return hardware.run(ctx, command, args);
    if (std.mem.indexOf(u8, command, "release") != null or std.mem.eql(u8, command, "check-reproducible-build")) return release.run(ctx, command, args);
    return error.UnknownCommand;
}

test {
    std.testing.refAllDecls(images);
    std.testing.refAllDecls(checks);
    std.testing.refAllDecls(qemu);
    std.testing.refAllDecls(release);
    std.testing.refAllDecls(hardware);
}
