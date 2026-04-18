const std = @import("std");
const builtin = @import("builtin");
const shared = @import("build_support/shared.zig");
const kernel_build = @import("build_support/kernel.zig");
const userspace_build = @import("build_support/userspace.zig");

pub const BootProfile = shared.BootProfile;
const required_zig_version = "0.16.0";

pub fn build(b: *std.Build) void {
    enforceZigVersion();

    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });
    const optimize = b.standardOptimizeOption(.{});
    const host_tests_module = b.createModule(.{
        .root_source_file = b.path("src/native_host_test.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
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
    const spec_tests = b.addTest(.{
        .name = "zigos-spec-tests",
        .root_module = spec_tests_module,
    });
    const run_spec_tests = b.addRunArtifact(spec_tests);
    const userspace_images = userspace_build.addUserspaceArtifacts(b, target, optimize);

    const zigos_native_kernel = kernel_build.addKernelArtifact(
        b,
        target,
        optimize,
        "kernel-zigos-native.elf",
        .zigos_native,
        userspace_images.archive_module,
    );

    const benchmark_kernel = kernel_build.addKernelArtifact(
        b,
        target,
        optimize,
        "kernel-benchmark.elf",
        .benchmark,
        userspace_images.archive_module,
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
        "file=" ++ shared.native_store_image_path ++ ",if=ide,format=raw,index=1,id=disk1",
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

    const host_tests_step = b.step("host-tests", "Run host-side unit tests for native logic");
    host_tests_step.dependOn(&run_host_tests.step);

    const spec_coverage_cmd = b.addSystemCommand(&.{
        "python3",
        "tools/check_spec_coverage.py",
    });
    run_spec_tests.step.dependOn(&spec_coverage_cmd.step);
    const spec_tests_step = b.step("spec-tests", "Run the spec coverage gate and native spec unit tests");
    spec_tests_step.dependOn(&run_spec_tests.step);

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
