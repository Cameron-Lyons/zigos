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

pub fn addX86_64ArchitectureCompileCheck(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const object = b.addObject(.{
        .name = "x86_64-architecture-compile-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/arch/x86_compile_check.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const step = b.step("x86_64-architecture-compile-check", "Compile privileged helpers for the x86-64 target");
    step.dependOn(&object.step);
    return step;
}

pub fn addX86_64KernelCompileCheck(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step {
    const kernel_module = createX86_64KernelModule(b, optimize, userspace_images);
    const object = b.addObject(.{
        .name = "kernel-x86_64-compile-check",
        .root_module = kernel_module,
    });
    const step = b.step("kernel-x86_64-compile-check", "Compile the kernel, descriptor tables, interrupts, and userspace transition for x86-64");
    step.dependOn(&object.step);
    return step;
}

pub fn addX86_64KernelBootCheck(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Step {
    const kernel_module = createX86_64KernelModule(b, optimize, userspace_images);
    const kernel_object = b.addObject(.{
        .name = "kernel-x86_64-core-boot",
        .root_module = kernel_module,
    });
    kernel_object.bundle_compiler_rt = true;

    const link = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "ld.lld",
        "-m",
        "elf_x86_64",
        "--gc-sections",
        "-z",
        "common-page-size=4096",
        "-z",
        "max-page-size=4096",
        "-T",
    });
    link.addFileArg(b.path("src/arch/x86_64/linker.ld"));
    link.addArg("-o");
    const linked_kernel = link.addOutputFileArg("kernel-x86_64-core-boot.elf");
    link.addFileArg(kernel_object.getEmittedBin());

    const validate_image = b.addSystemCommand(&.{
        "bash",
        "scripts/check-multiboot2-image.sh",
    });
    validate_image.addFileArg(linked_kernel);

    const iso = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
    });
    iso.addFileArg(linked_kernel);
    const iso_path = iso.addOutputFileArg("x86_64-kernel-core-boot.iso");
    _ = iso.addOutputDirectoryArg("x86_64-kernel-core-boot-staging");
    iso.addFileArg(b.path("src/boot/grub-x86_64-kernel.cfg"));
    iso.step.dependOn(&validate_image.step);

    const run = b.addSystemCommand(&.{
        "bash",
        "scripts/run-x86-64-kernel-smoke.sh",
    });
    run.addFileArg(iso_path);
    run.addArg("build/x86_64-kernel-core-boot.log");

    const step = b.step("x86_64-kernel-core-boot-check", "Boot the production kernel and complete ELF64 userspace catalog through a trap/resume cycle in QEMU");
    step.dependOn(&run.step);
    const userspace_step = b.step("x86_64-userspace-launch-check", "Launch the production ELF64 userspace catalog and prove its first trap/resume cycle in QEMU");
    userspace_step.dependOn(step);
    return step;
}

fn createX86_64KernelModule(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    userspace_images: userspace_build.ArtifactSet,
) *std.Build.Module {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const options = b.addOptions();
    options.addOption(shared.BootProfile, "boot_profile", .zigos_native);
    options.addOption(shared.KernelRole, "kernel_role", .production);
    options.addOption(shared.SmokeFaultMode, "smoke_fault_mode", .none);

    const kernel_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = false,
        // Interrupts may arrive at any instruction boundary, so the kernel
        // cannot use the userspace ABI's 128-byte area below RSP.
        .red_zone = false,
    });
    kernel_module.addImport("binary_cursor", b.createModule(.{
        .root_source_file = b.path("src/native/core/binary_cursor.zig"),
        .target = target,
        .optimize = optimize,
    }));
    kernel_module.addImport("userspace_archive", userspace_images.production_archive_module);
    kernel_module.addImport("production_artifact_manifest", userspace_images.production_manifest_module);
    kernel_module.addOptions("build_options", options);
    addKernelAssemblyFiles(b, kernel_module);
    return kernel_module;
}

pub fn addX86_64LongModeEntryCheck(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const module = b.createModule(.{
        .root_source_file = b.path("src/arch/x86_64/long_mode_probe.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    module.addImport("x86", b.createModule(.{
        .root_source_file = b.path("src/arch/x86.zig"),
        .target = target,
        .optimize = optimize,
    }));
    module.addAssemblyFile(b.path("src/arch/x86_64/long_mode_entry.S"));
    const probe = b.addObject(.{
        .name = "x86_64-long-mode-entry-probe",
        .root_module = module,
    });

    const link = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "ld.lld",
        "-m",
        "elf_x86_64",
        "--gc-sections",
        "-z",
        "common-page-size=4096",
        "-z",
        "max-page-size=4096",
        "-T",
    });
    link.addFileArg(b.path("src/arch/x86_64/long_mode_linker.ld"));
    link.addArg("-o");
    const linked_probe = link.addOutputFileArg("x86_64-long-mode-entry-probe.elf");
    link.addFileArg(probe.getEmittedBin());

    const validate_image = b.addSystemCommand(&.{
        "bash",
        "scripts/check-multiboot2-image.sh",
    });
    validate_image.addFileArg(linked_probe);

    const iso = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
    });
    iso.addFileArg(linked_probe);
    const iso_path = iso.addOutputFileArg("x86_64-long-mode-entry.iso");
    _ = iso.addOutputDirectoryArg("x86_64-long-mode-entry-staging");
    iso.addFileArg(b.path("src/boot/grub-long-mode.cfg"));
    iso.step.dependOn(&validate_image.step);

    const run = b.addSystemCommand(&.{
        "bash",
        "scripts/run-long-mode-entry-smoke.sh",
    });
    run.addFileArg(iso_path);
    run.addArg("build/x86_64-long-mode-entry.log");

    const step = b.step("x86_64-long-mode-entry-check", "Boot through PAE page tables and enter 64-bit Zig code in QEMU");
    step.dependOn(&run.step);
    return step;
}

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
        // Privileged code may be interrupted at any instruction boundary and
        // cannot rely on an ABI-owned area below the current stack pointer.
        .red_zone = false,
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
    addKernelAssemblyFiles(b, kernel_module);

    const kernel = b.addExecutable(.{
        .name = name,
        .root_module = kernel_module,
    });
    kernel.setLinkerScript(b.path("src/arch/x86_64/linker.ld"));

    const validate_qemu_image = b.addSystemCommand(&.{
        "bash",
        "scripts/check-multiboot2-image.sh",
    });
    validate_qemu_image.addFileArg(kernel.getEmittedBin());

    const qemu_iso = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
    });
    qemu_iso.addFileArg(kernel.getEmittedBin());
    const qemu_iso_path = qemu_iso.addOutputFileArg(b.fmt("{s}.qemu.iso", .{name}));
    _ = qemu_iso.addOutputDirectoryArg(b.fmt("{s}.qemu-staging", .{name}));
    qemu_iso.addFileArg(b.path("src/boot/grub-x86_64-qemu.cfg"));
    qemu_iso.step.dependOn(&validate_qemu_image.step);

    const install = b.addInstallArtifact(kernel, .{});
    return .{
        .compile_step = kernel,
        .install_step = &install.step,
        .output_path = b.getInstallPath(.bin, name),
        .kernel_role = kernel_role,
        .bootloader_source_path = "src/boot/boot_x86_64.S",
        .qemu_boot_iso_path = qemu_iso_path,
    };
}

fn addKernelAssemblyFiles(
    b: *std.Build,
    kernel_module: *std.Build.Module,
) void {
    kernel_module.addAssemblyFile(b.path("src/boot/boot_x86_64.S"));
    kernel_module.addAssemblyFile(b.path("src/arch/x86/syscall_trap.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupt64.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/gdt_flush64.S"));
    kernel_module.addAssemblyFile(b.path("src/native/task/userspace_entry64.S"));
}
