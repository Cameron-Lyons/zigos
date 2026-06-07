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

    const signing_cli = b.addExecutable(.{
        .name = "zigos-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zigos_sign_main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const signing_cli_install = b.addInstallArtifact(signing_cli, .{});
    const signing_cli_step = b.step("signing-cli", "Build the native app manifest signing CLI");
    signing_cli_step.dependOn(&signing_cli_install.step);

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

    const negative_smoke_cmds = [_]*std.Build.Step.Run{
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_artifact_manifest, userspace_images, .tampered_artifact_manifest),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_kernel, userspace_images, .tampered_kernel),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_userspace_image, userspace_images, .tampered_userspace_image),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_policy, userspace_images, .tampered_policy),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_driver_set, userspace_images, .tampered_driver_set),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_rollback_slot_failure, userspace_images, .rollback_slot_failure),
    };

    const zigos_native_smoke_test_step = b.step("zigos-native-smoke-test", "Run the Zigos native bootstrap smoke test in QEMU");
    zigos_native_smoke_test_step.dependOn(&zigos_native_smoke_test_cmd.step);
    dependOnRunCommands(zigos_native_smoke_test_step, &negative_smoke_cmds);

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

    const storage_durability_qemu_cmd = qemu_build.addStorageDurabilityQemuCommand(
        b,
        kernels.zigos_native_storage_durability,
        userspace_images,
    );
    const storage_durability_qemu_step = b.step("storage-durability-qemu-test", "Run focused QEMU storage durability proof across forced reboots and one bad root slot");
    storage_durability_qemu_step.dependOn(&storage_durability_qemu_cmd.step);

    const sync_two_node_qemu_cmd = qemu_build.addSyncTwoNodeQemuCommand(
        b,
        kernels.zigos_native,
        userspace_images,
    );
    const sync_two_node_qemu_step = b.step("sync-two-node-qemu-test", "Run two QEMU native nodes with socket-backed sync transport");
    sync_two_node_qemu_step.dependOn(&sync_two_node_qemu_cmd.step);

    const recovery_qemu_cmd = qemu_build.addRecoveryQemuCommand(b, kernels.recovery, userspace_images);
    const recovery_qemu_step = b.step("recovery-qemu-test", "Run QEMU proof that the recovery profile performs break-glass repair operations");
    recovery_qemu_step.dependOn(&recovery_qemu_cmd.step);

    const check_steps = checks_build.addCheckSteps(b, optimize, test_artifacts);
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
    dependOnRunCommands(spec_conformance_step, &negative_smoke_cmds);
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

    const uefi_qemu_cmd = qemu_build.addUefiQemuCommand(b, iso_cmd);
    const uefi_qemu_step = b.step("uefi-qemu-test", "Run the ISO through an OVMF UEFI boot preflight in QEMU");
    uefi_qemu_step.dependOn(&uefi_qemu_cmd.step);

    const release_sbom_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/generate-release-sbom-provenance.sh",
        "build/release-security",
    });
    release_sbom_cmd.step.dependOn(&iso_cmd.step);
    release_sbom_cmd.step.dependOn(&signing_cli_install.step);
    release_sbom_cmd.step.dependOn(userspace_images.step);
    const release_sbom_step = b.step("release-sbom-provenance", "Generate release SPDX SBOM, artifact digests, DSSE in-toto/SLSA provenance, keyring/revocation metadata, customer verification policy, and disclosure dry-run bundle");
    release_sbom_step.dependOn(&release_sbom_cmd.step);

    const reproducible_build_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/check-reproducible-build.sh",
        "build/release-security",
    });
    const reproducible_build_step = b.step("reproducible-build-check", "Build release artifacts twice in isolated tracked-workspace copies and compare digests");
    reproducible_build_step.dependOn(&reproducible_build_cmd.step);

    const release_security_gate_step = b.step("release-security-gate", "Run the public-release security gate: fuzz, reproducibility, SBOM/provenance, audits, redaction, disclosure, and QEMU fault proofs");
    release_security_gate_step.dependOn(check_steps.prod_readiness);
    release_security_gate_step.dependOn(check_steps.host_tests);
    release_security_gate_step.dependOn(check_steps.spec_tests);
    release_security_gate_step.dependOn(release_sbom_step);
    release_security_gate_step.dependOn(reproducible_build_step);
    release_security_gate_step.dependOn(zigos_native_smoke_test_step);
    release_security_gate_step.dependOn(storage_durability_qemu_step);
    release_security_gate_step.dependOn(driver_restart_qemu_step);
    release_security_gate_step.dependOn(recovery_qemu_step);
    release_security_gate_step.dependOn(sync_two_node_qemu_step);
    release_security_gate_step.dependOn(uefi_qemu_step);
}

fn dependOnRunCommands(step: *std.Build.Step, commands: []const *std.Build.Step.Run) void {
    for (commands) |command| {
        step.dependOn(&command.step);
    }
}

fn enforceZigVersion() void {
    if (std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) return;

    std.debug.print(
        "Zigos requires Zig {s}; found {s}. Use `./scripts/zig.sh build ...` or switch the repo toolchain before running `zig build`.\n",
        .{ required_zig_version, builtin.zig_version_string },
    );
    std.process.exit(1);
}
