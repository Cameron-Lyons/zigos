const std = @import("std");
const shared = @import("shared.zig");
const userspace_build = @import("userspace.zig");

pub const KernelArtifacts = struct {
    zigos_native: shared.KernelArtifact,
    zigos_native_tampered_artifact_manifest: shared.KernelArtifact,
    zigos_native_rollback_slot_failure: shared.KernelArtifact,
    recovery: shared.KernelArtifact,
    benchmark: shared.KernelArtifact,
};

pub const KernelSteps = struct {
    kernel: *std.Build.Step,
    zigos_native: *std.Build.Step,
    benchmark: *std.Build.Step,
    recovery: *std.Build.Step,
};

pub fn addKernelProfiles(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    userspace_images: userspace_build.ArtifactSet,
) KernelArtifacts {
    return .{
        .zigos_native = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native.elf",
            .zigos_native,
            .none,
            userspace_images.archive_module,
            userspace_images.production_manifest_module,
        ),
        .zigos_native_tampered_artifact_manifest = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-artifact-manifest.elf",
            .zigos_native,
            .tampered_artifact_manifest,
            userspace_images.archive_module,
            userspace_images.production_manifest_module,
        ),
        .zigos_native_rollback_slot_failure = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-rollback-slot-failure.elf",
            .zigos_native,
            .rollback_slot_failure,
            userspace_images.archive_module,
            userspace_images.production_manifest_module,
        ),
        .recovery = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-recovery.elf",
            .recovery,
            .none,
            userspace_images.archive_module,
            userspace_images.production_manifest_module,
        ),
        .benchmark = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-benchmark.elf",
            .benchmark,
            .none,
            userspace_images.archive_module,
            userspace_images.production_manifest_module,
        ),
    };
}

pub fn addKernelProfileSteps(
    b: *std.Build,
    kernels: KernelArtifacts,
    userspace_images: userspace_build.ArtifactSet,
) KernelSteps {
    const kernel_step = addKernelInstallStep(
        b,
        "kernel",
        "Build the native-only Zigos kernel",
        kernels.zigos_native,
        userspace_images.step,
    );
    const zigos_native_step = addKernelInstallStep(
        b,
        "kernel-zigos-native",
        "Build the Zigos native bootstrap kernel",
        kernels.zigos_native,
        userspace_images.step,
    );
    const benchmark_step = addKernelInstallStep(
        b,
        "kernel-benchmark",
        "Build the spec-aligned native benchmark kernel",
        kernels.benchmark,
        userspace_images.step,
    );
    const recovery_step = addKernelInstallStep(
        b,
        "kernel-recovery",
        "Build the freestanding recovery-mode kernel",
        kernels.recovery,
        userspace_images.step,
    );
    return .{
        .kernel = kernel_step,
        .zigos_native = zigos_native_step,
        .benchmark = benchmark_step,
        .recovery = recovery_step,
    };
}

fn addKernelInstallStep(
    b: *std.Build,
    name: []const u8,
    description: []const u8,
    kernel: shared.KernelArtifact,
    userspace_step: *std.Build.Step,
) *std.Build.Step {
    const step = b.step(name, description);
    step.dependOn(kernel.install_step);
    step.dependOn(userspace_step);
    return step;
}

pub fn addKernelArtifact(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    boot_profile: shared.BootProfile,
    smoke_fault_mode: shared.SmokeFaultMode,
    userspace_archive: ?*std.Build.Module,
    production_manifest: ?*std.Build.Module,
) shared.KernelArtifact {
    const options = b.addOptions();
    options.addOption(shared.BootProfile, "boot_profile", boot_profile);
    options.addOption(shared.SmokeFaultMode, "smoke_fault_mode", smoke_fault_mode);
    const module_name = if (smoke_fault_mode == .none)
        b.fmt("kernel-{s}", .{@tagName(boot_profile)})
    else
        b.fmt("kernel-{s}-{s}", .{ @tagName(boot_profile), @tagName(smoke_fault_mode) });

    const kernel_module = b.addModule(module_name, .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const binary_cursor_module = b.createModule(.{
        .root_source_file = b.path("src/native/core/binary_cursor.zig"),
        .target = target,
        .optimize = optimize,
    });
    kernel_module.addImport("binary_cursor", binary_cursor_module);
    if (userspace_archive) |archive_module| {
        kernel_module.addImport("userspace_archive", archive_module);
    }
    if (production_manifest) |manifest_module| {
        kernel_module.addImport("production_artifact_manifest", manifest_module);
    }

    kernel_module.addOptions("build_options", options);
    kernel_module.addAssemblyFile(b.path("src/boot/boot64.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupt32.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupts.s"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/gdt_flush.S"));
    kernel_module.addAssemblyFile(b.path("src/arch/x86/syscall_trap.S"));
    kernel_module.addAssemblyFile(b.path("src/native/task/userspace_entry.S"));

    const kernel = b.addExecutable(.{
        .name = name,
        .root_module = kernel_module,
    });
    kernel.setLinkerScript(b.path("src/arch/x86_64/linker.ld"));

    const install = b.addInstallArtifact(kernel, .{});
    return .{
        .compile_step = kernel,
        .install_step = &install.step,
        .output_path = b.fmt("zig-out/bin/{s}", .{name}),
    };
}
