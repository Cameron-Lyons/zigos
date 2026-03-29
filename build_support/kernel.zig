const std = @import("std");
const shared = @import("shared.zig");

pub fn addKernelArtifact(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    boot_profile: shared.BootProfile,
    userspace_archive: ?*std.Build.Module,
) shared.KernelArtifact {
    const options = b.addOptions();
    options.addOption(shared.BootProfile, "boot_profile", boot_profile);

    const kernel_module = b.addModule(b.fmt("kernel-{s}", .{@tagName(boot_profile)}), .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (userspace_archive) |archive_module| {
        kernel_module.addImport("userspace_archive", archive_module);
    }

    kernel_module.addOptions("build_options", options);
    kernel_module.addAssemblyFile(b.path("src/boot/boot64.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupt32.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupts.s"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/gdt_flush.S"));
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

pub fn createHostModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    root_source: []const u8,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
    });
}
