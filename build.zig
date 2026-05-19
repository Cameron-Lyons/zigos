const std = @import("std");
const builtin = @import("builtin");
const checks_build = @import("build_support/checks.zig");
const shared = @import("build_support/shared.zig");
const kernel_build = @import("build_support/kernel.zig");
const qemu_build = @import("build_support/qemu.zig");
const tests_build = @import("build_support/tests.zig");
const userspace_build = @import("build_support/userspace.zig");

pub const BootProfile = shared.BootProfile;
const required_zig_version = "0.16.0";

pub fn build(b: *std.Build) void {
    enforceZigVersion();

    const clean_dry_run = b.option(bool, "clean-dry-run", "Print generated paths that clean would remove without deleting them") orelse false;
    const clean_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/clean-build.sh",
    });
    if (clean_dry_run) clean_cmd.addArg("--dry-run");
    const clean_step = b.step("clean", "Remove generated build outputs and Zig caches");
    clean_step.dependOn(&clean_cmd.step);

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
    const userspace_images = userspace_build.addUserspaceArtifacts(b, target, optimize);
    const test_artifacts = tests_build.addTestArtifacts(b, optimize, userspace_images);
    const kernels = kernel_build.addKernelProfiles(b, target, optimize, userspace_images);
    const kernel_steps = kernel_build.addKernelProfileSteps(b, kernels, userspace_images);

    const native_store = qemu_build.addNativeStoreImageStep(b);
    _ = qemu_build.addNativeRunSteps(b, kernels.zigos_native, userspace_images, native_store);

    const zigos_native_smoke_test_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native,
        userspace_images,
        "build/zigos-native-smoke.log",
        shared.native_store_smoke_image_path,
        .full,
    );

    const tampered_artifact_manifest_smoke_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native_tampered_artifact_manifest,
        userspace_images,
        "build/zigos-native-tampered-artifact-manifest.log",
        "build/native-store-tampered-artifact-manifest.img",
        .tampered_artifact_manifest,
    );

    const rollback_slot_failure_smoke_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native_rollback_slot_failure,
        userspace_images,
        "build/zigos-native-rollback-slot-failure.log",
        "build/native-store-rollback-slot-failure.img",
        .rollback_slot_failure,
    );

    const zigos_native_smoke_test_step = b.step("zigos-native-smoke-test", "Run the Zigos native bootstrap smoke test in QEMU");
    zigos_native_smoke_test_step.dependOn(&zigos_native_smoke_test_cmd.step);
    zigos_native_smoke_test_step.dependOn(&tampered_artifact_manifest_smoke_cmd.step);
    zigos_native_smoke_test_step.dependOn(&rollback_slot_failure_smoke_cmd.step);

    const driver_restart_qemu_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native,
        userspace_images,
        "build/driver-restart-qemu.log",
        "build/native-store-driver-restart.img",
        .driver_restart,
    );

    const driver_restart_qemu_step = b.step("driver-restart-qemu-test", "Run QEMU proof that a userspace driver crashes and restarts without reboot");
    driver_restart_qemu_step.dependOn(&driver_restart_qemu_cmd.step);

    const recovery_qemu_cmd = qemu_build.addRecoveryQemuCommand(b, kernels.recovery, userspace_images);
    const recovery_qemu_step = b.step("recovery-qemu-test", "Run QEMU proof that the recovery profile performs break-glass repair operations");
    recovery_qemu_step.dependOn(&recovery_qemu_cmd.step);

    const check_steps = checks_build.addCheckSteps(b, test_artifacts);
    const spec_smoke_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native,
        userspace_images,
        "build/zigos-native-spec.log",
        shared.native_store_smoke_image_path,
        .full,
    );
    spec_smoke_cmd.step.dependOn(check_steps.spec_tests);
    const spec_conformance_step = b.step("spec-conformance", "Validate spec coverage, run native spec tests, and verify the freestanding smoke path");
    spec_conformance_step.dependOn(&spec_smoke_cmd.step);
    spec_conformance_step.dependOn(&tampered_artifact_manifest_smoke_cmd.step);
    spec_conformance_step.dependOn(&rollback_slot_failure_smoke_cmd.step);
    spec_conformance_step.dependOn(&recovery_qemu_cmd.step);

    const benchmark_cmd = qemu_build.addBenchmarkCommand(b, kernels.benchmark, userspace_images);
    const benchmark_step = b.step("benchmark", "Build and run the spec-aligned native benchmark suite in QEMU");
    benchmark_step.dependOn(&benchmark_cmd.step);

    _ = checks_build.addVerifyStep(
        b,
        check_steps,
        kernel_steps.kernel,
        zigos_native_smoke_test_step,
        benchmark_cmd,
        verify_smoke,
        verify_benchmark,
    );

    const iso_cmd = qemu_build.addIsoCommand(b, kernels.zigos_native, userspace_images);
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
