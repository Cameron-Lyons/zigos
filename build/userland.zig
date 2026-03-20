const std = @import("std");
const shared = @import("shared.zig");

pub fn dependOnUserPrograms(step: *std.Build.Step, programs: []const shared.UserProgramArtifact, extra_steps: []const *std.Build.Step) void {
    for (programs) |program| {
        step.dependOn(program.install_step);
    }
    for (extra_steps) |extra_step| {
        step.dependOn(extra_step);
    }
}

pub fn createUserAssetsModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    specs: []const shared.UserProgramSpec,
    programs: []const shared.UserProgramArtifact,
) *std.Build.Module {
    std.debug.assert(specs.len == programs.len);

    const write_files = b.addWriteFiles();
    for (specs, 0..) |spec, i| {
        _ = write_files.addCopyFile(programs[i].emitted_bin, b.fmt("assets/{s}", .{spec.name}));
    }
    _ = write_files.addCopyFile(b.path("user/rootfs/etc/motd"), "assets/motd");
    _ = write_files.addCopyFile(b.path("user/rootfs/etc/passwd"), "assets/passwd");

    var source = std.ArrayList(u8).empty;
    source.appendSlice(b.allocator,
        \\pub const ProgramAsset = struct {
        \\    name: []const u8,
        \\    data: []const u8,
        \\};
        \\
        \\pub const programs = [_]ProgramAsset{
    ) catch @panic("failed to start user assets source");

    for (specs) |spec| {
        source.print(b.allocator, "    .{{ .name = \"{s}\", .data = @embedFile(\"assets/{s}\") }},\n", .{
            spec.name,
            spec.name,
        }) catch @panic("failed to append user asset");
    }

    source.appendSlice(b.allocator,
        \\};
        \\
        \\pub const motd = @embedFile("assets/motd");
        \\pub const passwd = @embedFile("assets/passwd");
    ) catch @panic("failed to finish user assets source");

    const assets_source = write_files.add("user_assets.zig", source.toOwnedSlice(b.allocator) catch @panic("failed to allocate user assets source"));

    return b.createModule(.{
        .root_source_file = assets_source,
        .target = target,
        .optimize = optimize,
    });
}

pub fn addUserProgram(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    root_source: []const u8,
) shared.UserProgramArtifact {
    _ = optimize;
    const user_optimize: std.builtin.OptimizeMode = .ReleaseSmall;

    const abi_module = b.createModule(.{
        .root_source_file = b.path("src/kernel/process/syscall/abi.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const syscall_module = b.createModule(.{
        .root_source_file = b.path("user/lib/syscall.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    syscall_module.addImport("abi", abi_module);
    syscall_module.addImport("syscall_trap", b.createModule(.{
        .root_source_file = b.path("src/shared/syscall_trap.zig"),
        .target = target,
        .optimize = user_optimize,
    }));

    const runtime_module = b.createModule(.{
        .root_source_file = b.path("user/lib/runtime.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    runtime_module.addImport("syscall", syscall_module);

    const cstr_module = b.createModule(.{
        .root_source_file = b.path("user/lib/cstr.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const stdio_module = b.createModule(.{
        .root_source_file = b.path("user/lib/stdio.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    stdio_module.addImport("syscall", syscall_module);

    const cli_module = b.createModule(.{
        .root_source_file = b.path("user/lib/cli.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    cli_module.addImport("stdio", stdio_module);

    const fsutil_module = b.createModule(.{
        .root_source_file = b.path("user/lib/fsutil.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    fsutil_module.addImport("syscall", syscall_module);

    const processutil_module = b.createModule(.{
        .root_source_file = b.path("user/lib/processutil.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    processutil_module.addImport("cstr", cstr_module);
    processutil_module.addImport("syscall", syscall_module);

    const envutil_module = b.createModule(.{
        .root_source_file = b.path("user/lib/envutil.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    envutil_module.addImport("cstr", cstr_module);

    const account_module = b.createModule(.{
        .root_source_file = b.path("user/lib/account.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    account_module.addImport("stdio", stdio_module);
    account_module.addImport("syscall", syscall_module);

    const shell_registry_module = b.createModule(.{
        .root_source_file = b.path("src/kernel/shell/registry.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const user_module = b.addModule(b.fmt("user-{s}", .{name}), .{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = user_optimize,
    });
    user_module.addImport("account", account_module);
    user_module.addImport("cstr", cstr_module);
    user_module.addImport("cli", cli_module);
    user_module.addImport("envutil", envutil_module);
    user_module.addImport("fsutil", fsutil_module);
    user_module.addImport("processutil", processutil_module);
    user_module.addImport("runtime", runtime_module);
    user_module.addImport("shell_registry", shell_registry_module);
    user_module.addImport("syscall", syscall_module);
    user_module.addImport("stdio", stdio_module);

    user_module.addAssemblyFile(b.path("src/arch/x86/syscall_trap.S"));
    user_module.addAssemblyFile(b.path("user/crt0.S"));

    const program = b.addExecutable(.{
        .name = name,
        .root_module = user_module,
    });
    program.setLinkerScript(b.path("user/linker.ld"));

    const install = b.addInstallArtifact(program, .{
        .dest_dir = .{ .override = .{ .custom = "user/bin" } },
        .dest_sub_path = name,
    });

    return .{
        .install_step = &install.step,
        .emitted_bin = program.getEmittedBin(),
        .output_path = b.fmt("zig-out/user/bin/{s}", .{name}),
    };
}
