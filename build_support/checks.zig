const std = @import("std");
const tests_build = @import("tests.zig");

pub const CheckSteps = struct {
    test_roots: *std.Build.Step,
    host_tests: *std.Build.Step,
    spec_tests: *std.Build.Step,
    prod_readiness: *std.Build.Step,
    lint: *std.Build.Step,
};

pub fn addCheckSteps(
    b: *std.Build,
    test_artifacts: tests_build.TestArtifacts,
) CheckSteps {
    const zig_test_roots_cmd = b.addSystemCommand(&.{
        "python3",
        "tools/check_zig_test_roots.py",
    });
    const zig_test_roots_step = b.step("test-roots", "Check that Zig test-bearing files are reachable from build test roots");
    zig_test_roots_step.dependOn(&zig_test_roots_cmd.step);

    const host_tests_step = b.step("host-tests", "Run host-side unit tests for native logic and userspace runtime");
    host_tests_step.dependOn(&zig_test_roots_cmd.step);
    host_tests_step.dependOn(&test_artifacts.run_host_tests.step);
    host_tests_step.dependOn(&test_artifacts.run_userspace_runtime_tests.step);

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
    test_artifacts.run_spec_tests.step.dependOn(&spec_coverage_cmd.step);
    test_artifacts.run_spec_tests.step.dependOn(&zig_test_roots_cmd.step);
    const spec_tests_step = b.step("spec-tests", "Run the spec coverage gate and native spec unit tests");
    spec_tests_step.dependOn(&test_artifacts.run_spec_tests.step);

    const prod_readiness_cmd = b.addSystemCommand(&.{
        "python3",
        "tools/check_production_readiness.py",
    });
    const prod_readiness_step = b.step("prod-readiness", "Validate the production-readiness manifest and generated matrix");
    prod_readiness_step.dependOn(&prod_readiness_cmd.step);

    return .{
        .test_roots = zig_test_roots_step,
        .host_tests = host_tests_step,
        .spec_tests = spec_tests_step,
        .prod_readiness = prod_readiness_step,
        .lint = lint_step,
    };
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
