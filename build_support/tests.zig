const std = @import("std");
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
    const binary_cursor_test_module = b.createModule(.{
        .root_source_file = b.path("src/native/core/binary_cursor.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const userspace_wire_test_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_wire.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    userspace_wire_test_module.addImport("binary_cursor", binary_cursor_test_module);

    const host_tests_module = b.createModule(.{
        .root_source_file = b.path("src/native_host_test.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addNativeTestImports(host_tests_module, binary_cursor_test_module, userspace_wire_test_module, userspace_images);
    const host_tests = b.addTest(.{
        .name = "native-host-tests",
        .root_module = host_tests_module,
    });

    const spec_tests_module = b.createModule(.{
        .root_source_file = b.path("src/zigos_spec_test.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addNativeTestImports(spec_tests_module, binary_cursor_test_module, userspace_wire_test_module, userspace_images);
    const spec_tests = b.addTest(.{
        .name = "zigos-spec-tests",
        .root_module = spec_tests_module,
    });

    const userspace_descriptor_test_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_descriptor.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    userspace_descriptor_test_module.addImport("userspace_wire", userspace_wire_test_module);
    const userspace_abi_test_module = b.createModule(.{
        .root_source_file = b.path("src/native/core/abi.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const userspace_bootstrap_mailbox_test_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_bootstrap_mailbox.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const userspace_service_protocol_test_module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_service_protocol.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    userspace_service_protocol_test_module.addImport("userspace_wire", userspace_wire_test_module);
    const userspace_runtime_tests_module = b.createModule(.{
        .root_source_file = b.path("src/userspace/runtime.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    userspace_runtime_tests_module.addImport("userspace_descriptor", userspace_descriptor_test_module);
    userspace_runtime_tests_module.addImport("native_abi", userspace_abi_test_module);
    userspace_runtime_tests_module.addImport("userspace_bootstrap_mailbox", userspace_bootstrap_mailbox_test_module);
    userspace_runtime_tests_module.addImport("userspace_service_protocol", userspace_service_protocol_test_module);
    const userspace_runtime_tests = b.addTest(.{
        .name = "userspace-runtime-tests",
        .root_module = userspace_runtime_tests_module,
    });

    return .{
        .run_host_tests = b.addRunArtifact(host_tests),
        .run_spec_tests = b.addRunArtifact(spec_tests),
        .run_userspace_runtime_tests = b.addRunArtifact(userspace_runtime_tests),
    };
}

fn addNativeTestImports(
    module: *std.Build.Module,
    binary_cursor: *std.Build.Module,
    userspace_wire: *std.Build.Module,
    userspace_images: userspace_build.ArtifactSet,
) void {
    module.addImport("binary_cursor", binary_cursor);
    module.addImport("userspace_wire", userspace_wire);
    module.addImport("userspace_archive", userspace_images.archive_module);
    module.addImport("production_artifact_manifest", userspace_images.production_manifest_module);
}
