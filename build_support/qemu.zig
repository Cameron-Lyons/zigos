const std = @import("std");
const shared = @import("shared.zig");
const userspace_build = @import("userspace.zig");

pub const NativeSmokeMode = enum {
    production,
    full,
    driver_restart,
    tampered_artifact_manifest,
    tampered_bootloader_measurement,
    tampered_kernel,
    tampered_userspace_image,
    tampered_policy,
    tampered_driver_set,
    rollback_slot_failure,

    fn arg(self: NativeSmokeMode) ?[]const u8 {
        return switch (self) {
            .full => null,
            else => @tagName(self),
        };
    }

    fn fileStem(self: NativeSmokeMode) []const u8 {
        return switch (self) {
            .production => "production",
            .full => "full",
            .driver_restart => "driver-restart",
            .tampered_artifact_manifest => "tampered-artifact-manifest",
            .tampered_bootloader_measurement => "tampered-bootloader-measurement",
            .tampered_kernel => "tampered-kernel",
            .tampered_userspace_image => "tampered-userspace-image",
            .tampered_policy => "tampered-policy",
            .tampered_driver_set => "tampered-driver-set",
            .rollback_slot_failure => "rollback-slot-failure",
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
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));

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
    command.addArg(mode.arg() orelse "full");
    command.addArg(b.getInstallPath(.bin, ""));
    command.addArg(kernel.bootloader_source_path);
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addNativeFaultSmokeCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    mode: NativeSmokeMode,
) *std.Build.Step.Run {
    std.debug.assert(mode != .production and mode != .full and mode != .driver_restart);
    const file_stem = mode.fileStem();
    return addNativeSmokeCommand(
        b,
        kernel,
        userspace_images,
        b.fmt("build/zigos-native-{s}.log", .{file_stem}),
        b.fmt("build/native-store-{s}.img", .{file_stem}),
        mode,
    );
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
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addStorageDurabilityQemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/run-storage-durability-qemu.sh",
        kernel.output_path,
        "build/storage-durability-qemu.log",
        "build/native-store-storage-durability.img",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addSyncTwoNodeQemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/run-sync-two-node-qemu.sh",
        kernel.output_path,
        "build/sync-two-node-qemu.log",
        "build/native-store-sync-node-a.img",
        "build/native-store-sync-node-b.img",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addBenchmarkCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/capture-kernel-benchmark.sh",
        kernel.output_path,
        "build/kernel-benchmark.log",
        "build/kernel-benchmark-summary.md",
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addIsoCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    output_path: []const u8,
    staging_path: []const u8,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
        kernel.output_path,
        output_path,
        staging_path,
    });
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

fn userspaceStepForKernel(
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step {
    return switch (kernel.kernel_role) {
        .production => userspace_images.production_step,
        .verification => userspace_images.verification_step,
    };
}

pub fn addUefiQemuCommand(
    b: *std.Build,
    iso_command: *std.Build.Step.Run,
    iso_path: []const u8,
    log_path: []const u8,
    expected_role: []const u8,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "bash",
        "scripts/run-uefi-boot-test.sh",
        iso_path,
        log_path,
        expected_role,
    });
    command.step.dependOn(&iso_command.step);
    return command;
}
