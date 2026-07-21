const std = @import("std");
const shared = @import("shared.zig");
const userspace_build = @import("userspace.zig");

pub const KernelArtifacts = struct {
    zigos_native: shared.KernelArtifact,
    zigos_native_verification: shared.KernelArtifact,
    zigos_native_tampered_artifact_manifest: shared.KernelArtifact,
    zigos_native_tampered_bootloader_measurement: shared.KernelArtifact,
    zigos_native_tampered_kernel: shared.KernelArtifact,
    zigos_native_tampered_userspace_image: shared.KernelArtifact,
    zigos_native_tampered_policy: shared.KernelArtifact,
    zigos_native_tampered_driver_set: shared.KernelArtifact,
    zigos_native_rollback_slot_failure: shared.KernelArtifact,
    zigos_native_storage_durability: shared.KernelArtifact,
    recovery: shared.KernelArtifact,
    benchmark: shared.KernelArtifact,
};

pub const KernelSteps = struct {
    kernel: *std.Build.Step,
    zigos_native: *std.Build.Step,
    zigos_native_verification: *std.Build.Step,
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
            .production,
            .none,
            userspace_images.production_archive_module,
            userspace_images.production_manifest_module,
        ),
        .zigos_native_verification = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-verification.elf",
            .zigos_native,
            .verification,
            .none,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_tampered_artifact_manifest = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-artifact-manifest.elf",
            .zigos_native,
            .verification,
            .tampered_artifact_manifest,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_tampered_bootloader_measurement = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-bootloader-measurement.elf",
            .zigos_native,
            .verification,
            .tampered_bootloader_measurement,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_tampered_kernel = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-kernel.elf",
            .zigos_native,
            .verification,
            .tampered_kernel,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_tampered_userspace_image = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-userspace-image.elf",
            .zigos_native,
            .verification,
            .tampered_userspace_image,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_tampered_policy = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-policy.elf",
            .zigos_native,
            .verification,
            .tampered_policy,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_tampered_driver_set = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-tampered-driver-set.elf",
            .zigos_native,
            .verification,
            .tampered_driver_set,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_rollback_slot_failure = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-rollback-slot-failure.elf",
            .zigos_native,
            .verification,
            .rollback_slot_failure,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .zigos_native_storage_durability = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-zigos-native-storage-durability.elf",
            .zigos_native,
            .verification,
            .storage_durability,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .recovery = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-recovery.elf",
            .recovery,
            .verification,
            .none,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
        ),
        .benchmark = addKernelArtifact(
            b,
            target,
            optimize,
            "kernel-benchmark.elf",
            .benchmark,
            .verification,
            .none,
            userspace_images.verification_archive_module,
            userspace_images.verification_manifest_module,
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
        userspace_images.production_step,
    );
    const zigos_native_step = addKernelInstallStep(
        b,
        "kernel-zigos-native",
        "Build the Zigos native bootstrap kernel",
        kernels.zigos_native,
        userspace_images.production_step,
    );
    const zigos_native_verification_step = addKernelInstallStep(
        b,
        "kernel-zigos-native-verification",
        "Build the Zigos native verification kernel",
        kernels.zigos_native_verification,
        userspace_images.verification_step,
    );
    const benchmark_step = addKernelInstallStep(
        b,
        "kernel-benchmark",
        "Build the spec-aligned native benchmark kernel",
        kernels.benchmark,
        userspace_images.verification_step,
    );
    const recovery_step = addKernelInstallStep(
        b,
        "kernel-recovery",
        "Build the freestanding recovery-mode kernel",
        kernels.recovery,
        userspace_images.verification_step,
    );
    return .{
        .kernel = kernel_step,
        .zigos_native = zigos_native_step,
        .zigos_native_verification = zigos_native_verification_step,
        .benchmark = benchmark_step,
        .recovery = recovery_step,
    };
}

pub fn gateArtifactInstalls(kernels: KernelArtifacts, validation_step: *std.Build.Step) void {
    inline for (std.meta.fields(KernelArtifacts)) |field| {
        @field(kernels, field.name).install_step.dependOn(validation_step);
    }
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
    kernel_role: shared.KernelRole,
    smoke_fault_mode: shared.SmokeFaultMode,
    userspace_archive: ?*std.Build.Module,
    production_manifest: ?*std.Build.Module,
) shared.KernelArtifact {
    std.debug.assert(kernel_role == .verification or
        (boot_profile == .zigos_native and smoke_fault_mode == .none));
    const options = b.addOptions();
    options.addOption(shared.BootProfile, "boot_profile", boot_profile);
    options.addOption(shared.KernelRole, "kernel_role", kernel_role);
    options.addOption(shared.SmokeFaultMode, "smoke_fault_mode", smoke_fault_mode);
    const module_name = if (smoke_fault_mode == .none)
        b.fmt("kernel-{s}-{s}", .{ @tagName(boot_profile), @tagName(kernel_role) })
    else
        b.fmt("kernel-{s}-{s}-{s}", .{ @tagName(boot_profile), @tagName(kernel_role), @tagName(smoke_fault_mode) });

    const kernel_module = b.addModule(module_name, .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        // The role gate inspects symbols as well as loaded bytes. Keep the
        // kernel symbol table in every supported optimization mode; public
        // release packaging can produce a separately stripped derivative.
        .strip = false,
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
        .output_path = b.getInstallPath(.bin, name),
        .kernel_role = kernel_role,
    };
}
