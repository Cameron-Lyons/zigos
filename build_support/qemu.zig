const std = @import("std");
const shared = @import("shared.zig");
const userspace_build = @import("userspace.zig");
const kernel_build = @import("kernel.zig");
const tools_build = @import("host_tools.zig");

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
};

pub fn addNativeStoreImageStep(b: *std.Build) *std.Build.Step.Run {
    const command = tools_build.addRun(b, "build-native-store");
    command.addArgs(&.{
        shared.native_store_image_path,
        shared.native_store_size_mib,
        "preserve",
    });
    b.step("native-store-image", "Build or preserve the dedicated native storage image").dependOn(&command.step);
    return command;
}

pub fn addNativeRunCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    native_store: *std.Build.Step.Run,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, kernel.qemu_boot_iso_path, "qemu-harness", &.{"native-store"}, &.{
        shared.native_store_image_path,
        "stdio",
    });
    command.step.dependOn(&native_store.step);
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    b.step("run", "Run the native-only Zigos kernel in QEMU").dependOn(&command.step);
    return command;
}

pub fn addNativeSmokeCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    log_path: []const u8,
    store_path: []const u8,
    mode: NativeSmokeMode,
) *std.Build.Step.Run {
    return addNativeSmokeBoot(b, kernel, kernel.qemu_boot_iso_path, userspace_images, log_path, store_path, mode);
}

fn addNativeSmokeBoot(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    boot_iso: std.Build.LazyPath,
    userspace_images: userspace_build.ArtifactSet,
    log_path: []const u8,
    store_path: []const u8,
    mode: NativeSmokeMode,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, boot_iso, "run-zigos-native-smoke", &.{}, &.{
        log_path,
        store_path,
    });
    command.addArg(@tagName(mode));
    command.addArg(shared.bootloader_source_path);
    const expected_userspace_count = userspace_build.production_artifact_count +
        if (mode == .production) 0 else userspace_build.verification_only_artifact_count;
    command.addArg(b.fmt("{d}", .{expected_userspace_count}));
    for (userspace_images.production_compile_steps) |image| command.addFileArg(image.getEmittedBin());
    if (kernel.kernel_role == .verification) {
        for (userspace_images.verification_only_compile_steps) |image| command.addFileArg(image.getEmittedBin());
    }
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

/// Boots the verification kernel from an authenticated image whose command line
/// selects one injected boot fault. Production kernels compile no fault paths.
fn addSmokeFaultIso(b: *std.Build, kernel: shared.KernelArtifact, fault: []const u8) std.Build.LazyPath {
    std.debug.assert(kernel.kernel_role == .verification);
    const name = b.fmt("smoke-fault-{s}", .{fault});
    return kernel_build.addBootImage(b, name, kernel.output_file, kernel_build.addQemuCommandLine(b, b.fmt("smoke_fault_{s}", .{fault}))).iso;
}

pub fn addTpm2QemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, kernel.qemu_boot_iso_path, "run-tpm2-qemu", &.{}, &.{});
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addTpm2SealingQemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, kernel.qemu_boot_iso_path, "run-tpm2-qemu", &.{}, &.{"sealing"});
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addTpm2OwnershipQemuCommand(b: *std.Build, kernel: shared.KernelArtifact, userspace_images: userspace_build.ArtifactSet) *std.Build.Step.Run {
    return addTpm2ProfileQemuCommand(b, kernel, userspace_images, "ownership");
}

pub fn addTpm2QuoteQemuCommand(b: *std.Build, kernel: shared.KernelArtifact, userspace_images: userspace_build.ArtifactSet) *std.Build.Step.Run {
    return addTpm2ProfileQemuCommand(b, kernel, userspace_images, "quote");
}

fn addTpm2ProfileQemuCommand(b: *std.Build, kernel: shared.KernelArtifact, userspace_images: userspace_build.ArtifactSet, comptime mode: []const u8) *std.Build.Step.Run {
    const image = kernel_build.addBootImage(b, "tpm-" ++ mode, kernel.output_file, kernel_build.addQemuCommandLine(b, "tpm_" ++ mode ++ "_proof"));
    const command = addKernelBootCommand(b, kernel, image.iso, "run-tpm2-qemu", &.{}, &.{mode});
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
    const file_stem = b.allocator.dupe(u8, @tagName(mode)) catch @panic("OOM");
    std.mem.replaceScalar(u8, file_stem, '_', '-');
    return addNativeSmokeBoot(
        b,
        kernel,
        addSmokeFaultIso(b, kernel, @tagName(mode)),
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
    const command = addKernelBootCommand(b, kernel, kernel.qemu_boot_iso_path, "run-kernel-recovery", &.{}, &.{
        "build/kernel-recovery.log",
    });
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addStorageDurabilityQemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, addSmokeFaultIso(b, kernel, "storage_durability"), "run-storage-durability-qemu", &.{}, &.{
        "build/storage-durability-qemu.log",
        "build/native-store-storage-durability.img",
    });
    command.addArg(b.fmt("{d}", .{@import("../src/native/storage/volume/layout.zig").sector_size}));
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addSyncTwoNodeQemuCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, kernel.qemu_boot_iso_path, "run-sync-two-node-qemu", &.{}, &.{
        "build/sync-two-node-qemu.log",
        "build/native-store-sync-node-a.img",
        "build/native-store-sync-node-b.img",
    });
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

pub fn addBenchmarkCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step.Run {
    const command = addKernelBootCommand(b, kernel, kernel.qemu_boot_iso_path, "capture-kernel-benchmark", &.{}, &.{
        "build/kernel-benchmark.log",
        "build/kernel-benchmark-summary.md",
    });
    command.step.dependOn(userspaceStepForKernel(kernel, userspace_images));
    return command;
}

fn addKernelBootCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    boot_iso: std.Build.LazyPath,
    command_name: []const u8,
    prefix_args: []const []const u8,
    args: []const []const u8,
) *std.Build.Step.Run {
    const command = tools_build.addRun(b, command_name);
    command.addArg("--boot-iso");
    command.addFileArg(boot_iso);
    command.addArgs(prefix_args);
    command.addFileArg(kernel.output_path);
    command.addArgs(args);
    command.step.dependOn(kernel.install_step);
    return command;
}

pub fn addIsoCommand(
    b: *std.Build,
    kernel: shared.KernelArtifact,
    userspace_images: userspace_build.ArtifactSet,
    efi_stub: *std.Build.Step.Compile,
    output_path: []const u8,
    staging_path: []const u8,
) *std.Build.Step.Run {
    const command = tools_build.addRun(b, "build-efi-iso");
    command.addFileArg(efi_stub.getEmittedBin());
    command.addArgs(&.{
        output_path,
        staging_path,
    });
    shared.addEfiIsoEpochArg(b, command);
    command.step.dependOn(kernel.install_step);
    command.step.dependOn(&efi_stub.step);
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
    const command = tools_build.addRun(b, "run-uefi-boot-test");
    command.addArgs(&.{
        iso_path,
        log_path,
        expected_role,
    });
    command.step.dependOn(&iso_command.step);
    return command;
}
