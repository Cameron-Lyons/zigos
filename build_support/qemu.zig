const std = @import("std");
const shared = @import("shared.zig");
const userspace_build = @import("userspace.zig");

pub const NativeSmokeMode = enum {
    full,
    driver_restart,
    tampered_artifact_manifest,
    rollback_slot_failure,

    fn arg(self: NativeSmokeMode) ?[]const u8 {
        return switch (self) {
            .full => null,
            else => @tagName(self),
        };
    }
};

pub const NativeStoreImage = struct {
    command: *std.Build.Step.Run,
    step: *std.Build.Step,
};

pub const NativeRunSteps = struct {
    command: *std.Build.Step.Run,
    run: *std.Build.Step,
    run_zigos_native: *std.Build.Step,
};

pub fn addNativeStoreImageStep(b: *std.Build) NativeStoreImage {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/build-native-store.sh",
        shared.native_store_image_path,
        shared.native_store_size_mib,
        "preserve",
    });

    const step = b.step("native-store-image", "Build or preserve the dedicated native storage image");
    step.dependOn(&command.step);
    return .{
        .command = command,
        .step = step,
    };
}

pub fn addNativeRunSteps(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    native_store: NativeStoreImage,
) NativeRunSteps {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/qemu-harness.sh",
        "native-store",
        kernel.output_path,
        shared.native_store_image_path,
        "stdio",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(&native_store.command.step);
    command.step.dependOn(userspace_images.step);

    const run_step = b.step("run", "Run the native-only Zigos kernel in QEMU");
    run_step.dependOn(&command.step);

    const run_zigos_native_step = b.step("run-zigos-native", "Run the Zigos native bootstrap kernel in QEMU");
    run_zigos_native_step.dependOn(&command.step);

    return .{
        .command = command,
        .run = run_step,
        .run_zigos_native = run_zigos_native_step,
    };
}

pub fn addNativeSmokeCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    log_path: []const u8,
    store_path: []const u8,
    mode: NativeSmokeMode,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/run-zigos-native-smoke.sh",
        kernel.output_path,
        log_path,
        store_path,
    });
    if (mode.arg()) |arg| {
        command.addArg(arg);
    }
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspace_images.step);
    return command;
}

pub fn addRecoveryQemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/run-kernel-recovery.sh",
        kernel.output_path,
        "build/kernel-recovery.log",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspace_images.step);
    return command;
}

pub fn addBenchmarkCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/run-kernel-benchmark.sh",
        kernel.output_path,
        "build/kernel-benchmark.log",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspace_images.step);
    return command;
}

pub fn addIsoCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
        kernel.output_path,
        "build/os.iso",
        "build/iso",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspace_images.step);
    return command;
}
