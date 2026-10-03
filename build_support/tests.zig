const std = @import("std");
const native_modules = @import("native_modules.zig");
const userspace_build = @import("userspace.zig");
const shared = @import("shared.zig");

pub const TestArtifacts = struct {
    run_host_tests: *std.Build.Step.Run,
    run_spec_tests: *std.Build.Step.Run,
    run_userspace_runtime_tests: *std.Build.Step.Run,
};

pub fn addTestArtifacts(
    b: *std.Build,
    optimize: std.lang.Optimize,
    userspace_images: userspace_build.ArtifactSet,
) TestArtifacts {
    // These roots exercise AMD64 worker assembly even on a different host CPU.
    const test_target = nativeTestTarget(b);
    const wire_modules = native_modules.addTargetWireModules(b, test_target, optimize);
    const test_modules = native_modules.addUserspaceRuntimeHostTestModules(b, optimize);
    const kernel_options = b.addOptions();
    kernel_options.addOption(shared.BootProfile, "boot_profile", .zigos_native);
    kernel_options.addOption(shared.KernelRole, "kernel_role", .production);
    kernel_options.addOption(shared.SmokeFaultMode, "smoke_fault_mode", .none);

    const host_tests_module = b.createModule(.{
        .root_source_file = b.path("src/native_host_test.zig"),
        .target = test_target,
        .optimize = optimize,
    });
    host_tests_module.addAssemblyFile(b.path("src/native/task/cooperative_worker64.S"));
    host_tests_module.addOptions("build_options", kernel_options);
    addNativeTestImports(host_tests_module, wire_modules, userspace_images);
    const host_tests = b.addTest(.{
        .name = "native-host-tests",
        .root_module = host_tests_module,
    });

    const spec_tests_module = b.createModule(.{
        .root_source_file = b.path("src/zigos_spec_test.zig"),
        .target = test_target,
        .optimize = optimize,
    });
    spec_tests_module.addAssemblyFile(b.path("src/native/task/cooperative_worker64.S"));
    addNativeTestImports(spec_tests_module, wire_modules, userspace_images);
    const spec_tests = b.addTest(.{
        .name = "zigos-spec-tests",
        .root_module = spec_tests_module,
    });

    const userspace_runtime_tests = b.addTest(.{
        .name = "userspace-runtime-tests",
        .root_module = test_modules.runtime,
    });

    return .{
        .run_host_tests = b.addRunArtifact(host_tests),
        .run_spec_tests = b.addRunArtifact(spec_tests),
        .run_userspace_runtime_tests = b.addRunArtifact(userspace_runtime_tests),
    };
}

fn nativeTestTarget(b: *std.Build) std.Build.ResolvedTarget {
    const target_query = if (b.option(
        []const u8,
        "host-test-target",
        "x86-64 target for native and spec tests (defaults to the host OS and ABI)",
    )) |triple|
        std.Build.parseTargetQuery(.{ .arch_os_abi = triple }) catch @panic("invalid host-test-target")
    else
        std.Target.Query{
            .cpu_arch = .x86_64,
            .os_tag = b.graph.host.result.os.tag,
            .abi = b.graph.host.result.abi,
        };
    const target = b.resolveTargetQuery(target_query);
    if (target.result.cpu.arch != .x86_64 or target.result.os.tag == .freestanding) {
        @panic("native and spec tests require a hosted x86-64 target");
    }
    return target;
}

fn addNativeTestImports(
    module: *std.Build.Module,
    wire: native_modules.WireModules,
    userspace_images: userspace_build.ArtifactSet,
) void {
    module.addImport("binary_cursor", wire.binary_cursor);
    module.addImport("userspace_wire", wire.userspace_wire);
    module.addImport("userspace_archive", userspace_images.verification_archive_module);
    module.addImport("production_artifact_manifest", userspace_images.verification_manifest_module);
}
