const std = @import("std");
const native_modules = @import("native_modules.zig");
const userspace_build = @import("userspace.zig");

pub const TestArtifacts = struct {
    run_host_tests: *std.Build.Step.Run,
    run_spec_tests: *std.Build.Step.Run,
    run_userspace_runtime_tests: *std.Build.Step.Run,
};

pub fn addTestArtifacts(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    userspace_images: userspace_build.ArtifactSet,
) TestArtifacts {
    const test_modules = native_modules.addUserspaceRuntimeHostTestModules(b, optimize);

    const host_tests_module = b.createModule(.{
        .root_source_file = b.path("src/native_host_test.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addNativeTestImports(host_tests_module, test_modules.wire, userspace_images);
    const host_tests = b.addTest(.{
        .name = "native-host-tests",
        .root_module = host_tests_module,
    });

    const spec_tests_module = b.createModule(.{
        .root_source_file = b.path("src/zigos_spec_test.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addNativeTestImports(spec_tests_module, test_modules.wire, userspace_images);
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
