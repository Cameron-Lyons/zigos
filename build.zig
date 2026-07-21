const std = @import("std");
const builtin = @import("builtin");
const benchmarks_build = @import("build_support/benchmarks.zig");
const checks_build = @import("build_support/checks.zig");
const shared = @import("build_support/shared.zig");
const kernel_build = @import("build_support/kernel.zig");
const qemu_build = @import("build_support/qemu.zig");
const tests_build = @import("build_support/tests.zig");
const userspace_build = @import("build_support/userspace.zig");

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
    const hardware_proof_dir_option = b.option([]const u8, "hardware-proof-dir", "Path to the completed NUC11TNKi5 hardware proof bundle");
    const hardware_proof_dir = hardware_proof_dir_option orelse "<missing-hardware-proof-dir>";
    const release_trust_root = b.option([]const u8, "release-trust-root", "Absolute path to independently provisioned release root metadata");
    const release_trust_root_sha256 = b.option([]const u8, "release-trust-root-sha256", "Pinned lowercase SHA-256 digest of release root metadata");
    const release_trust_policy = b.option([]const u8, "release-trust-policy", "Absolute path to the root-threshold-signed release trust policy");
    const release_trust_state = b.option([]const u8, "release-trust-state", "Persistent verifier state path outside the release bundle and artifact root");
    const release_verifier = b.option([]const u8, "release-verifier", "Absolute path to an independently provisioned release verifier");
    const release_verifier_sha256 = b.option([]const u8, "release-verifier-sha256", "Pinned lowercase SHA-256 digest of the independent release verifier");

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

    const kernel_role_check_tool = b.addExecutable(.{
        .name = "check-kernel-roles",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/check_kernel_roles.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const kernel_role_check_cmd = b.addRunArtifact(kernel_role_check_tool);
    kernel_role_check_cmd.addFileArg(kernels.zigos_native.compile_step.getEmittedBin());
    kernel_role_check_cmd.addFileArg(kernels.zigos_native_verification.compile_step.getEmittedBin());
    kernel_role_check_cmd.addArg("--production-userspace");
    for (userspace_images.production_compile_steps) |compile_step| {
        kernel_role_check_cmd.addFileArg(compile_step.getEmittedBin());
    }
    kernel_role_check_cmd.addArg("--verification-userspace");
    for (userspace_images.verification_only_compile_steps) |compile_step| {
        kernel_role_check_cmd.addFileArg(compile_step.getEmittedBin());
    }
    const kernel_role_check_tests = b.addTest(.{
        .name = "check-kernel-roles-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/check_kernel_roles.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const kernel_role_check_test_cmd = b.addRunArtifact(kernel_role_check_tests);
    const kernel_role_check_step = b.step("kernel-role-check", "Reject verification proof code or state in the production kernel");
    kernel_role_check_step.dependOn(&kernel_role_check_cmd.step);
    kernel_role_check_step.dependOn(&kernel_role_check_test_cmd.step);
    userspace_build.gateArtifactInstalls(userspace_images, kernel_role_check_step);
    kernel_build.gateArtifactInstalls(kernels, kernel_role_check_step);
    kernel_steps.kernel.dependOn(kernel_role_check_step);
    kernel_steps.zigos_native.dependOn(kernel_role_check_step);
    kernel_steps.zigos_native_verification.dependOn(kernel_role_check_step);

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

    const verify_release_cli = b.addExecutable(.{
        .name = "zigos-verify-release",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zigos_verify_release_main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const verify_release_cli_install = b.addInstallArtifact(verify_release_cli, .{});
    const verify_release_cli_step = b.step("verify-release-cli", "Build the host release verifier for independent distribution and local tests");
    verify_release_cli_step.dependOn(&verify_release_cli_install.step);

    const release_bundle_fixture_tests = b.addTest(.{
        .name = "release-bundle-fixture-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/zigos_verify_release.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const release_bundle_fixture_test_cmd = b.addRunArtifact(release_bundle_fixture_tests);
    const release_bundle_fixture_test_step = b.step("release-bundle-fixture-test", "Run credential-free authenticated release bundle and rollback attack fixtures");
    release_bundle_fixture_test_step.dependOn(&release_bundle_fixture_test_cmd.step);

    const native_store = qemu_build.addNativeStoreImageStep(b);
    const native_run_steps = qemu_build.addNativeRunSteps(b, kernels.zigos_native, userspace_images, native_store);
    native_run_steps.command.step.dependOn(kernel_role_check_step);

    const zigos_native_production_smoke_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native,
        userspace_images,
        "build/zigos-native-production.log",
        "build/native-store-production-smoke.img",
        .production,
    );
    const zigos_native_production_smoke_step = b.step("zigos-native-production-smoke-test", "Boot the production kernel across a cold reboot without verification workloads");
    zigos_native_production_smoke_step.dependOn(&zigos_native_production_smoke_cmd.step);
    zigos_native_production_smoke_step.dependOn(kernel_role_check_step);

    const zigos_native_smoke_test_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native_verification,
        userspace_images,
        "build/zigos-native-smoke.log",
        shared.native_store_smoke_image_path,
        .full,
    );

    const negative_smoke_cmds = [_]*std.Build.Step.Run{
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_artifact_manifest, userspace_images, .tampered_artifact_manifest),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_bootloader_measurement, userspace_images, .tampered_bootloader_measurement),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_kernel, userspace_images, .tampered_kernel),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_userspace_image, userspace_images, .tampered_userspace_image),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_policy, userspace_images, .tampered_policy),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_tampered_driver_set, userspace_images, .tampered_driver_set),
        qemu_build.addNativeFaultSmokeCommand(b, kernels.zigos_native_rollback_slot_failure, userspace_images, .rollback_slot_failure),
    };

    const zigos_native_smoke_test_step = b.step("zigos-native-smoke-test", "Run the Zigos native bootstrap smoke test in QEMU");
    zigos_native_smoke_test_cmd.step.dependOn(&zigos_native_production_smoke_cmd.step);
    zigos_native_smoke_test_step.dependOn(&zigos_native_smoke_test_cmd.step);
    zigos_native_smoke_test_step.dependOn(kernel_role_check_step);
    serializeRunCommands(zigos_native_smoke_test_cmd, &negative_smoke_cmds);
    dependOnRunCommands(zigos_native_smoke_test_step, &negative_smoke_cmds);

    const driver_restart_qemu_cmd = qemu_build.addNativeSmokeCommand(
        b,
        kernels.zigos_native_verification,
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
        kernels.zigos_native_verification,
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
        kernels.zigos_native_verification,
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
    const benchmark_gate = benchmarks_build.addBenchmarkGate(b, optimize, benchmark_cmd);
    check_steps.host_tests.dependOn(&benchmark_gate.tests.step);

    const benchmark_check_tests_step = b.step("benchmark-check-tests", "Run adversarial tests for the typed benchmark gate");
    benchmark_check_tests_step.dependOn(&benchmark_gate.tests.step);

    const benchmark_step = b.step("benchmark", "Build and run the spec-aligned native benchmark suite in QEMU");
    benchmark_step.dependOn(&benchmark_gate.check.step);

    const verify_step = checks_build.addVerifyStep(
        b,
        check_steps,
        kernel_steps.kernel,
        zigos_native_smoke_test_step,
        benchmark_gate.check,
        verify_smoke,
        verify_benchmark,
    );
    verify_step.dependOn(kernel_role_check_step);

    const iso_cmd = qemu_build.addIsoCommand(
        b,
        kernels.zigos_native,
        userspace_images,
        "build/os.iso",
        "build/iso",
    );
    const iso_step = b.step("iso", "Build a bootable native-only ISO");
    iso_step.dependOn(&iso_cmd.step);
    iso_step.dependOn(kernel_role_check_step);

    const verification_iso_cmd = qemu_build.addIsoCommand(
        b,
        kernels.zigos_native_verification,
        userspace_images,
        "build/os-verification.iso",
        "build/iso-verification",
    );
    const verification_iso_step = b.step("iso-verification", "Build bootable verification media for proof workloads");
    verification_iso_step.dependOn(&verification_iso_cmd.step);
    verification_iso_step.dependOn(kernel_role_check_step);

    const uefi_qemu_cmd = qemu_build.addUefiQemuCommand(
        b,
        iso_cmd,
        "build/os.iso",
        "build/uefi-boot-qemu.log",
        "production",
    );
    const uefi_qemu_step = b.step("uefi-qemu-test", "Run the ISO through an OVMF UEFI boot preflight in QEMU");
    uefi_qemu_step.dependOn(&uefi_qemu_cmd.step);
    uefi_qemu_step.dependOn(kernel_role_check_step);

    const verification_uefi_qemu_cmd = qemu_build.addUefiQemuCommand(
        b,
        verification_iso_cmd,
        "build/os-verification.iso",
        "build/uefi-verification-boot-qemu.log",
        "verification",
    );
    const verification_uefi_qemu_step = b.step("uefi-verification-qemu-test", "Run verification media through an OVMF UEFI boot preflight in QEMU");
    verification_uefi_qemu_step.dependOn(&verification_uefi_qemu_cmd.step);
    verification_uefi_qemu_step.dependOn(kernel_role_check_step);

    const hardware_proof_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/check-nuc11tnki5-hardware-proof.sh",
        hardware_proof_dir,
    });
    const hardware_proof_step = b.step("hardware-proof", "Validate the completed NUC11TNKi5 real-hardware proof bundle");
    hardware_proof_step.dependOn(&hardware_proof_cmd.step);
    if (hardware_proof_dir_option == null) {
        hardware_proof_cmd.step.dependOn(&b.addFail("hardware proof validation requires -Dhardware-proof-dir=build/hardware-proofs/<fresh-name>").step);
    }

    const release_sbom_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/generate-release-sbom-provenance.sh",
        "build/release-security",
        "ReleaseFast",
    });
    if (optimize != .ReleaseFast) {
        release_sbom_cmd.step.dependOn(&b.addFail("public release artifacts require -Doptimize=ReleaseFast").step);
    }
    release_sbom_cmd.step.dependOn(&iso_cmd.step);
    release_sbom_cmd.step.dependOn(kernel_role_check_step);
    release_sbom_cmd.step.dependOn(userspace_images.production_step);
    const release_sbom_step = b.step("release-sbom-provenance", "Generate the eight generator-side evidence files for the exact 33-target release catalog");
    release_sbom_step.dependOn(&release_sbom_cmd.step);

    const reproducible_build_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/check-reproducible-build.sh",
        "build/release-security",
    });
    const reproducible_build_step = b.step("reproducible-build-check", "Build release artifacts twice in isolated tracked-workspace copies and compare digests");
    reproducible_build_step.dependOn(&reproducible_build_cmd.step);

    const release_manifest_finalize_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/finalize-release-manifest.sh",
        "build/release-security",
        ".",
    });
    release_manifest_finalize_cmd.step.dependOn(&release_sbom_cmd.step);
    release_manifest_finalize_cmd.step.dependOn(&reproducible_build_cmd.step);
    const release_manifest_finalize_step = b.step("release-manifest-finalize", "Candidate-verify, atomically publish, and statefully verify the signed exact manifest");
    release_manifest_finalize_step.dependOn(&release_manifest_finalize_cmd.step);

    const trust_root_arg = release_trust_root orelse "<missing-release-trust-root>";
    const trust_root_sha256_arg = release_trust_root_sha256 orelse "<missing-release-trust-root-sha256>";
    const trust_policy_arg = release_trust_policy orelse "<missing-release-trust-policy>";
    const trust_state_arg = release_trust_state orelse "<missing-release-trust-state>";
    const release_verifier_arg = release_verifier orelse "<missing-release-verifier>";
    const release_verifier_sha256_arg = release_verifier_sha256 orelse "<missing-release-verifier-sha256>";
    if (release_trust_root != null and release_trust_root_sha256 != null and release_trust_policy != null and release_verifier != null and release_verifier_sha256 != null) {
        release_sbom_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_ROOT", trust_root_arg);
        release_sbom_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_ROOT_SHA256", trust_root_sha256_arg);
        release_sbom_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_POLICY", trust_policy_arg);
        release_sbom_cmd.setEnvironmentVariable("ZIGOS_RELEASE_VERIFIER", release_verifier_arg);
        release_sbom_cmd.setEnvironmentVariable("ZIGOS_RELEASE_VERIFIER_SHA256", release_verifier_sha256_arg);
        release_manifest_finalize_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_ROOT", trust_root_arg);
        release_manifest_finalize_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_ROOT_SHA256", trust_root_sha256_arg);
        release_manifest_finalize_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_POLICY", trust_policy_arg);
        release_manifest_finalize_cmd.setEnvironmentVariable("ZIGOS_RELEASE_VERIFIER", release_verifier_arg);
        release_manifest_finalize_cmd.setEnvironmentVariable("ZIGOS_RELEASE_VERIFIER_SHA256", release_verifier_sha256_arg);
    } else {
        const missing_trust_inputs = b.addFail("release generation requires -Drelease-trust-root=<absolute path>, -Drelease-trust-root-sha256=<lowercase sha256>, -Drelease-trust-policy=<absolute path>, -Drelease-verifier=<absolute path>, and -Drelease-verifier-sha256=<lowercase sha256>");
        release_sbom_cmd.step.dependOn(&missing_trust_inputs.step);
        release_manifest_finalize_cmd.step.dependOn(&missing_trust_inputs.step);
    }
    if (release_trust_state) |_| {
        release_manifest_finalize_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_STATE", trust_state_arg);
    } else {
        const missing_trust_state = b.addFail("release verification requires -Drelease-trust-state=<persistent external state path>");
        release_manifest_finalize_cmd.step.dependOn(&missing_trust_state.step);
    }

    const release_bundle_step = b.step("release-bundle-check", "Create, candidate-verify, publish, and statefully verify the authenticated exact release bundle");
    release_bundle_step.dependOn(&release_manifest_finalize_cmd.step);

    const release_bundle_existing_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/verify-release-bundle.sh",
        release_verifier_arg,
        release_verifier_sha256_arg,
        "build/release-security",
        ".",
        trust_root_arg,
        trust_root_sha256_arg,
        trust_state_arg,
    });
    if (release_trust_root == null or release_trust_root_sha256 == null or release_trust_state == null or release_verifier == null or release_verifier_sha256 == null) {
        const missing_existing_verify_inputs = b.addFail("existing release verification requires -Drelease-trust-root, -Drelease-trust-root-sha256, -Drelease-trust-state, -Drelease-verifier, and -Drelease-verifier-sha256");
        release_bundle_existing_cmd.step.dependOn(&missing_existing_verify_inputs.step);
    }
    const release_bundle_existing_step = b.step("release-bundle-verify-existing", "Verify an existing frozen bundle with an independently pinned verifier without regenerating evidence");
    release_bundle_existing_step.dependOn(&release_bundle_existing_cmd.step);

    if (release_trust_root != null and release_trust_root_sha256 != null and release_trust_state != null and release_verifier != null and release_verifier_sha256 != null) {
        hardware_proof_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_ROOT", trust_root_arg);
        hardware_proof_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_ROOT_SHA256", trust_root_sha256_arg);
        hardware_proof_cmd.setEnvironmentVariable("ZIGOS_RELEASE_TRUST_STATE", trust_state_arg);
        hardware_proof_cmd.setEnvironmentVariable("ZIGOS_RELEASE_VERIFIER", release_verifier_arg);
        hardware_proof_cmd.setEnvironmentVariable("ZIGOS_RELEASE_VERIFIER_SHA256", release_verifier_sha256_arg);
    }

    const release_security_preflight_step = b.step("release-security-preflight", "Run all mutable public-release build, audit, fixture, and QEMU gates before freezing a candidate");
    release_security_preflight_step.dependOn(check_steps.prod_readiness);
    release_security_preflight_step.dependOn(check_steps.host_tests);
    release_security_preflight_step.dependOn(check_steps.spec_tests);
    release_security_preflight_step.dependOn(release_bundle_fixture_test_step);
    release_security_preflight_step.dependOn(kernel_role_check_step);
    release_security_preflight_step.dependOn(zigos_native_production_smoke_step);
    release_security_preflight_step.dependOn(zigos_native_smoke_test_step);
    release_security_preflight_step.dependOn(storage_durability_qemu_step);
    release_security_preflight_step.dependOn(driver_restart_qemu_step);
    release_security_preflight_step.dependOn(recovery_qemu_step);
    release_security_preflight_step.dependOn(sync_two_node_qemu_step);
    release_security_preflight_step.dependOn(uefi_qemu_step);
    release_security_preflight_step.dependOn(verification_uefi_qemu_step);
    release_sbom_cmd.step.dependOn(release_security_preflight_step);
    reproducible_build_cmd.step.dependOn(release_security_preflight_step);

    hardware_proof_cmd.step.dependOn(&release_bundle_existing_cmd.step);
    const release_security_gate_step = b.step("release-security-gate", "Seal a frozen verified release candidate with its current NUC11TNKi5 hardware proof without regenerating artifacts");
    release_security_gate_step.dependOn(hardware_proof_step);
}

fn dependOnRunCommands(step: *std.Build.Step, commands: []const *std.Build.Step.Run) void {
    for (commands) |command| {
        step.dependOn(&command.step);
    }
}

fn serializeRunCommands(first: *std.Build.Step.Run, commands: []const *std.Build.Step.Run) void {
    var previous = first;
    for (commands) |command| {
        command.step.dependOn(&previous.step);
        previous = command;
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
