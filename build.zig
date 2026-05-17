const std = @import("std");
const builtin = @import("builtin");
const shared = @import("build_support/shared.zig");
const kernel_build = @import("build_support/kernel.zig");
const userspace_build = @import("build_support/userspace.zig");

pub const BootProfile = shared.BootProfile;
const required_zig_version = "0.16.0";

pub fn build(b: *std.Build) void {
    enforceZigVersion();

    const verify_smoke = b.option(bool, "verify-smoke", "Include the QEMU native smoke test in `zig build verify`") orelse false;
    const verify_benchmark = b.option(bool, "verify-benchmark", "Include the QEMU benchmark suite in `zig build verify`") orelse false;

    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });
    const optimize = b.standardOptimizeOption(.{});
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
    host_tests_module.addImport("binary_cursor", binary_cursor_test_module);
    host_tests_module.addImport("userspace_wire", userspace_wire_test_module);
    const host_tests = b.addTest(.{
        .name = "native-host-tests",
        .root_module = host_tests_module,
    });
    const run_host_tests = b.addRunArtifact(host_tests);
    const spec_tests_module = b.createModule(.{
        .root_source_file = b.path("src/zigos_spec_test.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    spec_tests_module.addImport("binary_cursor", binary_cursor_test_module);
    spec_tests_module.addImport("userspace_wire", userspace_wire_test_module);
    const spec_tests = b.addTest(.{
        .name = "zigos-spec-tests",
        .root_module = spec_tests_module,
    });
    const run_spec_tests = b.addRunArtifact(spec_tests);
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
    const run_userspace_runtime_tests = b.addRunArtifact(userspace_runtime_tests);
    const userspace_images = userspace_build.addUserspaceArtifacts(b, target, optimize);

    const zigos_native_kernel = kernel_build.addKernelArtifact(
        b,
        target,
        optimize,
        "kernel-zigos-native.elf",
        .zigos_native,
        userspace_images.archive_module,
        userspace_images.production_manifest_module,
    );

    const recovery_kernel = kernel_build.addKernelArtifact(
        b,
        target,
        optimize,
        "kernel-recovery.elf",
        .recovery,
        userspace_images.archive_module,
        userspace_images.production_manifest_module,
    );

    const benchmark_kernel = kernel_build.addKernelArtifact(
        b,
        target,
        optimize,
        "kernel-benchmark.elf",
        .benchmark,
        userspace_images.archive_module,
        userspace_images.production_manifest_module,
    );

    const kernel_step = b.step("kernel", "Build the native-only Zigos kernel");
    kernel_step.dependOn(zigos_native_kernel.install_step);
    kernel_step.dependOn(userspace_images.step);

    const zigos_native_kernel_step = b.step("kernel-zigos-native", "Build the Zigos native bootstrap kernel");
    zigos_native_kernel_step.dependOn(zigos_native_kernel.install_step);
    zigos_native_kernel_step.dependOn(userspace_images.step);

    const kernel_benchmark_step = b.step("kernel-benchmark", "Build the spec-aligned native benchmark kernel");
    kernel_benchmark_step.dependOn(benchmark_kernel.install_step);
    kernel_benchmark_step.dependOn(userspace_images.step);

    const kernel_recovery_step = b.step("kernel-recovery", "Build the freestanding recovery-mode kernel");
    kernel_recovery_step.dependOn(recovery_kernel.install_step);
    kernel_recovery_step.dependOn(userspace_images.step);

    const native_store_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-native-store.sh",
        shared.native_store_image_path,
        "8",
        "preserve",
    });

    const native_store_step = b.step("native-store-image", "Build or preserve the dedicated native storage image");
    native_store_step.dependOn(&native_store_cmd.step);

    const zigos_native_qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        zigos_native_kernel.output_path,
        "-m",
        "256M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-drive",
        "file=" ++ shared.native_store_image_path ++ ",if=ide,format=raw,index=0,id=disk0",
    });
    zigos_native_qemu_cmd.step.dependOn(zigos_native_kernel.install_step);
    zigos_native_qemu_cmd.step.dependOn(&native_store_cmd.step);
    zigos_native_qemu_cmd.step.dependOn(userspace_images.step);

    const run_step = b.step("run", "Run the native-only Zigos kernel in QEMU");
    run_step.dependOn(&zigos_native_qemu_cmd.step);

    const run_zigos_native_step = b.step("run-zigos-native", "Run the Zigos native bootstrap kernel in QEMU");
    run_zigos_native_step.dependOn(&zigos_native_qemu_cmd.step);

    const zigos_native_smoke_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-zigos-native-smoke.sh",
        zigos_native_kernel.output_path,
        "build/zigos-native-smoke.log",
        shared.native_store_smoke_image_path,
    });
    zigos_native_smoke_test_cmd.step.dependOn(zigos_native_kernel.install_step);
    zigos_native_smoke_test_cmd.step.dependOn(userspace_images.step);

    const zigos_native_smoke_test_step = b.step("zigos-native-smoke-test", "Run the Zigos native bootstrap smoke test in QEMU");
    zigos_native_smoke_test_step.dependOn(&zigos_native_smoke_test_cmd.step);

    const driver_restart_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-zigos-native-smoke.sh",
        zigos_native_kernel.output_path,
        "build/driver-restart-qemu.log",
        "build/native-store-driver-restart.img",
    });
    driver_restart_qemu_cmd.step.dependOn(zigos_native_kernel.install_step);
    driver_restart_qemu_cmd.step.dependOn(userspace_images.step);

    const driver_restart_qemu_step = b.step("driver-restart-qemu-test", "Run QEMU proof that a userspace driver crashes and restarts without reboot");
    driver_restart_qemu_step.dependOn(&driver_restart_qemu_cmd.step);

    const recovery_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-kernel-recovery.sh",
        recovery_kernel.output_path,
        "build/kernel-recovery.log",
    });
    recovery_qemu_cmd.step.dependOn(recovery_kernel.install_step);
    recovery_qemu_cmd.step.dependOn(userspace_images.step);

    const recovery_qemu_step = b.step("recovery-qemu-test", "Run QEMU proof that the recovery profile performs break-glass repair operations");
    recovery_qemu_step.dependOn(&recovery_qemu_cmd.step);

    const zig_test_roots_cmd = b.addSystemCommand(&.{
        "python3",
        "tools/check_zig_test_roots.py",
    });
    const zig_test_roots_step = b.step("test-roots", "Check that Zig test-bearing files are reachable from build test roots");
    zig_test_roots_step.dependOn(&zig_test_roots_cmd.step);

    const host_tests_step = b.step("host-tests", "Run host-side unit tests for native logic and userspace runtime");
    host_tests_step.dependOn(&zig_test_roots_cmd.step);
    host_tests_step.dependOn(&run_host_tests.step);
    host_tests_step.dependOn(&run_userspace_runtime_tests.step);

    const fmt_check_cmd = b.addSystemCommand(&.{
        "bash",
        "-c",
        "git ls-files -z '*.zig' | while IFS= read -r -d '' file; do [ -e \"$file\" ] && printf '%s\\0' \"$file\"; done | xargs -0 ./scripts/zig.sh fmt --check",
    });
    const fmt_check_step = b.step("fmt-check", "Check Zig formatting for tracked source files");
    fmt_check_step.dependOn(&fmt_check_cmd.step);

    const shell_lint_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/lint-shell.sh",
    });
    const shell_lint_step = b.step("shell-lint", "Run ShellCheck over all repository shell scripts");
    shell_lint_step.dependOn(&shell_lint_cmd.step);

    const zig_lint_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/lint-zig.sh",
    });
    const zig_lint_step = b.step("zig-lint", "Run zlint over Zig sources when zlint is installed");
    zig_lint_step.dependOn(&zig_lint_cmd.step);

    const action_lint_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/lint-actions.sh",
    });
    const action_lint_step = b.step("action-lint", "Run actionlint over GitHub workflows when actionlint is installed");
    action_lint_step.dependOn(&action_lint_cmd.step);

    const lint_step = b.step("lint", "Run local lint checks: Zig fmt, optional zlint, ShellCheck, and optional actionlint");
    lint_step.dependOn(&fmt_check_cmd.step);
    lint_step.dependOn(&zig_lint_cmd.step);
    lint_step.dependOn(&shell_lint_cmd.step);
    lint_step.dependOn(&action_lint_cmd.step);

    const spec_coverage_cmd = b.addSystemCommand(&.{
        "python3",
        "tools/check_spec_coverage.py",
    });
    run_spec_tests.step.dependOn(&spec_coverage_cmd.step);
    run_spec_tests.step.dependOn(&zig_test_roots_cmd.step);
    const spec_tests_step = b.step("spec-tests", "Run the spec coverage gate and native spec unit tests");
    spec_tests_step.dependOn(&run_spec_tests.step);

    const prod_readiness_cmd = b.addSystemCommand(&.{
        "python3",
        "tools/check_production_readiness.py",
    });
    const prod_readiness_step = b.step("prod-readiness", "Validate the production-readiness manifest and generated matrix");
    prod_readiness_step.dependOn(&prod_readiness_cmd.step);

    const spec_smoke_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-zigos-native-smoke.sh",
        zigos_native_kernel.output_path,
        "build/zigos-native-spec.log",
        shared.native_store_smoke_image_path,
    });
    spec_smoke_cmd.step.dependOn(zigos_native_kernel.install_step);
    spec_smoke_cmd.step.dependOn(userspace_images.step);
    spec_smoke_cmd.step.dependOn(&run_spec_tests.step);
    const spec_conformance_step = b.step("spec-conformance", "Validate spec coverage, run native spec tests, and verify the freestanding smoke path");
    spec_conformance_step.dependOn(&spec_smoke_cmd.step);
    spec_conformance_step.dependOn(&recovery_qemu_cmd.step);

    const benchmark_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-kernel-benchmark.sh",
        benchmark_kernel.output_path,
        "build/kernel-benchmark.log",
    });
    benchmark_cmd.step.dependOn(benchmark_kernel.install_step);
    benchmark_cmd.step.dependOn(userspace_images.step);
    const benchmark_step = b.step("benchmark", "Build and run the spec-aligned native benchmark suite in QEMU");
    benchmark_step.dependOn(&benchmark_cmd.step);

    const verify_step = b.step("verify", "Run local CI-aligned checks: lint, kernel build, host tests, spec tests, and production-readiness checks; pass -Dverify-smoke=true and/or -Dverify-benchmark=true for QEMU gates");
    verify_step.dependOn(lint_step);
    verify_step.dependOn(kernel_step);
    verify_step.dependOn(host_tests_step);
    verify_step.dependOn(spec_tests_step);
    verify_step.dependOn(prod_readiness_step);
    if (verify_smoke) verify_step.dependOn(&zigos_native_smoke_test_cmd.step);
    if (verify_benchmark) verify_step.dependOn(&benchmark_cmd.step);

    const iso_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
        zigos_native_kernel.output_path,
        "build/os.iso",
        "build/iso",
    });
    iso_cmd.step.dependOn(zigos_native_kernel.install_step);
    iso_cmd.step.dependOn(userspace_images.step);

    const iso_step = b.step("iso", "Build a bootable native-only ISO");
    iso_step.dependOn(&iso_cmd.step);
}

fn enforceZigVersion() void {
    if (std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) return;

    std.debug.print(
        "Zigos requires Zig {s}; found {s}. Use `./scripts/zig.sh build ...` or switch the repo toolchain before running `zig build`.\n",
        .{ required_zig_version, builtin.zig_version_string },
    );
    std.process.exit(1);
}
