const std = @import("std");
const native_modules = @import("native_modules.zig");
const production_registry = @import("../src/native/task/userspace_registry.zig");
const verification_registry = @import("../src/native/task/userspace_verification_registry.zig");
const userspace_layout = @import("../src/native/core/userspace_layout.zig");

pub const production_artifact_count = production_registry.production_boot_image_specs.len;
pub const verification_only_artifact_count = verification_registry.verification_only_boot_image_specs.len;

pub const ArtifactSet = struct {
    step: *std.Build.Step,
    production_step: *std.Build.Step,
    verification_step: *std.Build.Step,
    production_count: usize,
    verification_count: usize,
    production_compile_steps: [production_artifact_count]*std.Build.Step.Compile,
    verification_only_compile_steps: [verification_only_artifact_count]*std.Build.Step.Compile,
    production_install_steps: [production_artifact_count]*std.Build.Step,
    verification_only_install_steps: [verification_only_artifact_count]*std.Build.Step,
    production_archive_module: *std.Build.Module,
    production_manifest_module: *std.Build.Module,
    verification_archive_module: *std.Build.Module,
    verification_manifest_module: *std.Build.Module,
};

pub const X86_64ArtifactSet = struct {
    step: *std.Build.Step,
    production_compile_steps: [production_artifact_count]*std.Build.Step.Compile,
    production_archive_module: *std.Build.Module,
    production_manifest_module: *std.Build.Module,
};

const BuiltArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    install_step: *std.Build.Step,
};

pub fn addUserspaceArtifacts(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ArtifactSet {
    const step = b.step("userspace-images", "Build userspace image artifacts");
    const production_step = b.step("userspace-production-images", "Build production userspace image artifacts");
    const verification_step = b.step("userspace-verification-images", "Build production and verification userspace image artifacts");
    const userspace_modules = native_modules.addUserspaceRuntimeModules(b, target, optimize);
    const native_archive_deps_module = b.createModule(.{
        .root_source_file = b.path("src/native/archive_generator_deps.zig"),
    });
    const archive_generator = addArchiveGenerator(b, userspace_modules.descriptor, native_archive_deps_module);
    const production_archive_run = b.addRunArtifact(archive_generator);
    const production_archive_dir = production_archive_run.addOutputDirectoryArg("userspace-production-archive");
    const production_archive_source = production_archive_dir.path(b, "userspace_archive.zig");
    const production_manifest_source = production_archive_dir.path(b, "production_artifact_manifest.zig");
    production_archive_run.addArg("zigos_native");
    production_archive_run.addArg("production");
    production_archive_run.addFileArg(b.path("src/boot/boot64.S"));

    const verification_archive_run = b.addRunArtifact(archive_generator);
    const verification_archive_dir = verification_archive_run.addOutputDirectoryArg("userspace-verification-archive");
    const verification_archive_source = verification_archive_dir.path(b, "userspace_archive.zig");
    const verification_manifest_source = verification_archive_dir.path(b, "verification_artifact_manifest.zig");
    verification_archive_run.addArg("zigos_native");
    verification_archive_run.addArg("verification");
    verification_archive_run.addFileArg(b.path("src/boot/boot64.S"));

    var production_compile_steps: [production_artifact_count]*std.Build.Step.Compile = undefined;
    var verification_only_compile_steps: [verification_only_artifact_count]*std.Build.Step.Compile = undefined;
    var production_install_steps: [production_artifact_count]*std.Build.Step = undefined;
    var verification_only_install_steps: [verification_only_artifact_count]*std.Build.Step = undefined;

    for (production_registry.production_boot_image_specs, 0..) |spec, artifact_index| {
        const artifact = addUserspaceArtifact(b, target, optimize, userspace_modules, spec);
        production_compile_steps[artifact_index] = artifact.compile_step;
        production_install_steps[artifact_index] = artifact.install_step;
        production_archive_run.addArtifactArg(artifact.compile_step);
        verification_archive_run.addArtifactArg(artifact.compile_step);
        production_step.dependOn(artifact.install_step);
        verification_step.dependOn(artifact.install_step);
    }
    for (verification_registry.verification_only_boot_image_specs, 0..) |spec, artifact_index| {
        const artifact = addUserspaceArtifact(b, target, optimize, userspace_modules, spec);
        verification_only_compile_steps[artifact_index] = artifact.compile_step;
        verification_only_install_steps[artifact_index] = artifact.install_step;
        verification_archive_run.addArtifactArg(artifact.compile_step);
        verification_step.dependOn(artifact.install_step);
    }
    production_step.dependOn(&production_archive_run.step);
    verification_step.dependOn(&verification_archive_run.step);
    step.dependOn(production_step);
    step.dependOn(verification_step);

    return .{
        .step = step,
        .production_step = production_step,
        .verification_step = verification_step,
        .production_count = production_registry.production_boot_image_specs.len,
        .verification_count = verification_registry.verification_boot_image_specs.len,
        .production_compile_steps = production_compile_steps,
        .verification_only_compile_steps = verification_only_compile_steps,
        .production_install_steps = production_install_steps,
        .verification_only_install_steps = verification_only_install_steps,
        .production_archive_module = b.createModule(.{
            .root_source_file = production_archive_source,
        }),
        .production_manifest_module = b.createModule(.{
            .root_source_file = production_manifest_source,
        }),
        .verification_archive_module = b.createModule(.{
            .root_source_file = verification_archive_source,
        }),
        .verification_manifest_module = b.createModule(.{
            .root_source_file = verification_manifest_source,
        }),
    };
}

pub fn addX86_64Artifacts(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) X86_64ArtifactSet {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const userspace_modules = native_modules.addUserspaceRuntimeModules(b, target, optimize);
    const native_archive_deps_module = b.createModule(.{
        .root_source_file = b.path("src/native/archive_generator_deps.zig"),
    });
    const archive_generator = addArchiveGenerator(b, userspace_modules.descriptor, native_archive_deps_module);
    const archive_run = b.addRunArtifact(archive_generator);
    const archive_dir = archive_run.addOutputDirectoryArg("userspace-x86_64-production-archive");
    const archive_source = archive_dir.path(b, "userspace_archive.zig");
    const manifest_source = archive_dir.path(b, "production_artifact_manifest.zig");
    archive_run.addArg("zigos_native");
    archive_run.addArg("production");
    archive_run.addFileArg(b.path("src/boot/boot_x86_64.S"));

    var production_compile_steps: [production_artifact_count]*std.Build.Step.Compile = undefined;
    for (production_registry.production_boot_image_specs, 0..) |spec, artifact_index| {
        const artifact = addUserspaceCompile(
            b,
            target,
            optimize,
            userspace_modules,
            spec,
            b.fmt("x86_64-{s}", .{spec.artifact_name}),
        );
        production_compile_steps[artifact_index] = artifact;
        archive_run.addArtifactArg(artifact);
    }

    const step = b.step("userspace-x86_64-compile-check", "Compile and inspect the complete production userspace catalog for the long-mode target");
    step.dependOn(&archive_run.step);
    return .{
        .step = step,
        .production_compile_steps = production_compile_steps,
        .production_archive_module = b.createModule(.{
            .root_source_file = archive_source,
        }),
        .production_manifest_module = b.createModule(.{
            .root_source_file = manifest_source,
        }),
    };
}

fn addArchiveGenerator(
    b: *std.Build,
    descriptor_module: *std.Build.Module,
    native_archive_deps_module: *std.Build.Module,
) *std.Build.Step.Compile {
    const archive_generator = b.addExecutable(.{
        .name = "userspace-archive-generator",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/generate_userspace_archive.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    archive_generator.root_module.addImport("userspace_descriptor", descriptor_module);
    archive_generator.root_module.addImport("native_archive_deps", native_archive_deps_module);
    return archive_generator;
}

pub fn gateArtifactInstalls(artifacts: ArtifactSet, validation_step: *std.Build.Step) void {
    for (artifacts.production_install_steps) |install_step| {
        install_step.dependOn(validation_step);
    }
    for (artifacts.verification_only_install_steps) |install_step| {
        install_step.dependOn(validation_step);
    }
}

fn addUserspaceArtifact(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    userspace_modules: native_modules.UserspaceRuntimeModules,
    spec: production_registry.ImageSpec,
) BuiltArtifact {
    const artifact = addUserspaceCompile(b, target, optimize, userspace_modules, spec, spec.artifact_name);
    const install = b.addInstallArtifact(artifact, .{});
    return .{
        .compile_step = artifact,
        .install_step = &install.step,
    };
}

fn addUserspaceCompile(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    userspace_modules: native_modules.UserspaceRuntimeModules,
    spec: production_registry.ImageSpec,
    artifact_name: []const u8,
) *std.Build.Step.Compile {
    const options = b.addOptions();
    options.addOption([]const u8, "bundle_id", spec.bundle_id);
    options.addOption([]const u8, "display_name", spec.display_name);
    options.addOption([]const u8, "label", spec.label);
    options.addOption([]const u8, "entry", spec.entry);
    options.addOption([]const u8, "publisher", spec.publisher);
    options.addOption(u8, "component_class", @intFromEnum(spec.component_class));
    options.addOption(bool, "signed", spec.signed);
    options.addOption(u32, "role_tag", spec.role_tag);
    options.addOption(u32, "heartbeat_increment", spec.heartbeat_increment);
    options.addOption(u32, "contract_flags", spec.contract_flags);
    options.addOption(bool, "run_mmu_isolation_probe", (spec.contract_flags & production_registry.FLAG_MMU_PROOF_PROBE) != 0);
    options.addOption(u8, "service_kind", @intFromEnum(spec.service_kind));

    const module = b.createModule(.{
        .root_source_file = b.path(spec.source_path),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    module.addAssemblyFile(b.path("src/arch/x86/syscall_trap.S"));
    module.addAssemblyFile(b.path("src/arch/x86/userspace_start.S"));
    module.addOptions("build_options", options);
    module.addImport("userspace_descriptor", userspace_modules.descriptor);
    module.addImport("userspace_runtime", userspace_modules.runtime);

    const artifact = b.addExecutable(.{
        .name = artifact_name,
        .root_module = module,
    });
    artifact.image_base = userspace_layout.image_start;
    artifact.setLinkerScript(b.path("src/userspace/linker.ld"));
    return artifact;
}
