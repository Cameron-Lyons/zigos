const std = @import("std");
const registry = @import("../src/native/task/userspace_registry.zig");

pub const ArtifactSet = struct {
    step: *std.Build.Step,
    count: usize,
    archive_module: *std.Build.Module,
};

pub fn addUserspaceArtifacts(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ArtifactSet {
    const step = b.step("userspace-images", "Build userspace image artifacts");
    var count: usize = 0;
    const descriptor_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_descriptor.zig"),
    });
    const abi_module = b.createModule(.{
        .root_source_file = b.path("src/native/core/abi.zig"),
    });
    const bootstrap_mailbox_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_bootstrap_mailbox.zig"),
    });
    const runtime_module = b.createModule(.{
        .root_source_file = b.path("src/userspace/runtime.zig"),
        .target = target,
        .optimize = optimize,
    });
    runtime_module.addImport("userspace_descriptor", descriptor_module);
    runtime_module.addImport("native_abi", abi_module);
    runtime_module.addImport("userspace_bootstrap_mailbox", bootstrap_mailbox_module);
    const archive_generator = b.addExecutable(.{
        .name = "userspace-archive-generator",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/generate_userspace_archive.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    archive_generator.root_module.addImport("userspace_descriptor", descriptor_module);
    const archive_run = b.addRunArtifact(archive_generator);
    const archive_dir = archive_run.addOutputDirectoryArg("userspace-archive");
    const archive_source = archive_dir.path(b, "userspace_archive.zig");

    for (registry.boot_image_specs) |spec| {
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

        const module = b.addModule(spec.artifact_name, .{
            .root_source_file = b.path(spec.source_path),
            .target = target,
            .optimize = optimize,
        });
        module.addAssemblyFile(b.path("src/arch/x86/syscall_trap.S"));
        module.addOptions("build_options", options);
        module.addImport("userspace_descriptor", descriptor_module);
        module.addImport("userspace_runtime", runtime_module);

        const artifact = b.addExecutable(.{
            .name = spec.artifact_name,
            .root_module = module,
        });
        artifact.setLinkerScript(b.path("src/userspace/linker.ld"));
        const install = b.addInstallArtifact(artifact, .{});
        archive_run.addArtifactArg(artifact);
        step.dependOn(&install.step);
        count += 1;
    }
    step.dependOn(&archive_run.step);

    return .{
        .step = step,
        .count = count,
        .archive_module = b.createModule(.{
            .root_source_file = archive_source,
        }),
    };
}
