const std = @import("std");
const native_modules = @import("native_modules.zig");
const tests_build = @import("tests.zig");

pub const CheckSteps = struct {
    host_tests: *std.Build.Step,
    spec_tests: *std.Build.Step,
    prod_readiness: *std.Build.Step,
    lint: *std.Build.Step,
};

pub fn addCheckSteps(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    test_artifacts: tests_build.TestArtifacts,
) CheckSteps {
    const zig_test_roots_cmd = addHostToolRun(b, optimize, "check-zig-test-roots", "tools/check_zig_test_roots.zig");
    const zig_test_roots_step = b.step("test-roots", "Check that Zig test-bearing files are reachable from build test roots");
    zig_test_roots_step.dependOn(&zig_test_roots_cmd.step);

    const host_tests_step = b.step("host-tests", "Run host-side unit tests for native logic and userspace runtime");
    host_tests_step.dependOn(&zig_test_roots_cmd.step);
    host_tests_step.dependOn(&test_artifacts.run_host_tests.step);
    host_tests_step.dependOn(&test_artifacts.run_userspace_runtime_tests.step);

    const fmt_check_script =
        \\jj file list -T 'path ++ "\0"' '*.zig' | while IFS= read -r -d '' file; do [ -e "$file" ] && printf '%s\0' "$file"; done | xargs -0 ./scripts/zig.sh fmt --check
    ;
    const fmt_check_cmd = b.addSystemCommand(&.{
        "bash",
        "-c",
        fmt_check_script,
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

    const spec_coverage_cmd = addHostToolRun(b, optimize, "check-spec-coverage", "tools/check_spec_coverage.zig");
    test_artifacts.run_spec_tests.step.dependOn(&spec_coverage_cmd.step);
    test_artifacts.run_spec_tests.step.dependOn(&zig_test_roots_cmd.step);
    const spec_tests_step = b.step("spec-tests", "Run the spec coverage gate and native spec unit tests");
    spec_tests_step.dependOn(&test_artifacts.run_spec_tests.step);

    const prod_readiness_cmd = addHostToolRun(b, optimize, "check-production-readiness", "tools/check_production_readiness.zig");
    const hardware_proof_checker_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/test-nuc11tnki5-hardware-proof-checker.sh",
    });
    const hardware_proof_checker_step = b.step("hardware-proof-checker-test", "Exercise the NUC11TNKi5 proof-bundle checker with synthetic pass/fail fixtures");
    hardware_proof_checker_step.dependOn(&hardware_proof_checker_cmd.step);

    const prod_readiness_step = b.step("prod-readiness", "Validate production-readiness tracking and the secure-by-design release gate");
    prod_readiness_step.dependOn(&prod_readiness_cmd.step);
    prod_readiness_step.dependOn(&hardware_proof_checker_cmd.step);

    const release_security_cmd = addReleaseSecurityGateRun(b, optimize);
    const release_security_test_cmd = addReleaseSecurityGateTestRun(b, optimize);
    const release_security_step = b.step("release-security-check", "Run release-security fuzz, audit, redaction, SBOM/provenance, threat-model, and disclosure source gates");
    release_security_step.dependOn(&release_security_cmd.step);
    release_security_step.dependOn(&release_security_test_cmd.step);
    prod_readiness_step.dependOn(&release_security_cmd.step);
    prod_readiness_step.dependOn(&release_security_test_cmd.step);

    return .{
        .host_tests = host_tests_step,
        .spec_tests = spec_tests_step,
        .prod_readiness = prod_readiness_step,
        .lint = lint_step,
    };
}

fn addHostToolRun(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    source_path: []const u8,
) *std.Build.Step.Run {
    const tool = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(source_path),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });
    const run = b.addRunArtifact(tool);
    run.setCwd(b.path("."));
    return run;
}

fn releaseSecurityGateModule(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const check_common_module = b.createModule(.{
        .root_source_file = b.path("tools/check_common.zig"),
    });
    const wire = native_modules.addWireModules(b);

    const module = b.createModule(.{
        .root_source_file = b.path("src/check_release_security_gate.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    module.addImport("check_common", check_common_module);
    module.addImport("binary_cursor", wire.binary_cursor);
    module.addImport("userspace_wire", wire.userspace_wire);
    return module;
}

fn addReleaseSecurityGateRun(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Run {
    const tool = b.addExecutable(.{
        .name = "check-release-security-gate",
        .root_module = releaseSecurityGateModule(b, optimize),
    });
    const run = b.addRunArtifact(tool);
    run.setCwd(b.path("."));
    return run;
}

fn addReleaseSecurityGateTestRun(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Run {
    const tests = b.addTest(.{
        .name = "check-release-security-gate-tests",
        .root_module = releaseSecurityGateModule(b, optimize),
    });
    const run = b.addRunArtifact(tests);
    run.setCwd(b.path("."));
    return run;
}

pub fn addVerifyStep(
    b: *std.Build,
    checks: CheckSteps,
    kernel_step: *std.Build.Step,
    zigos_native_smoke_step: *std.Build.Step,
    benchmark_cmd: *std.Build.Step.Run,
    verify_smoke: bool,
    verify_benchmark: bool,
) *std.Build.Step {
    const verify_step = b.step("verify", "Run local CI-aligned checks: lint, kernel build, host tests, spec tests, and production-readiness checks; pass -Dverify-smoke=true and/or -Dverify-benchmark=true for QEMU gates");
    verify_step.dependOn(checks.lint);
    verify_step.dependOn(kernel_step);
    verify_step.dependOn(checks.host_tests);
    verify_step.dependOn(checks.spec_tests);
    verify_step.dependOn(checks.prod_readiness);
    if (verify_smoke) verify_step.dependOn(zigos_native_smoke_step);
    if (verify_benchmark) verify_step.dependOn(&benchmark_cmd.step);
    return verify_step;
}
