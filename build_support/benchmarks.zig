const std = @import("std");

pub const BenchmarkGate = struct {
    check: *std.Build.Step.Run,
    tests: *std.Build.Step.Run,
};

pub fn addAllocatorBenchmarks(b: *std.Build) void {
    inline for (.{ "frame", "heap" }) |kind| {
        const module = b.createModule(.{
            .root_source_file = b.path("tools/benchmark_" ++ kind ++ "_allocator.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        });
        module.addImport(kind ++ "_allocator", b.createModule(.{
            .root_source_file = b.path(if (comptime std.mem.eql(u8, kind, "heap")) "src/heap_benchmark.zig" else "src/kernel/memory/frame_allocator.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        }));
        const executable = b.addExecutable(.{ .name = "benchmark-" ++ kind ++ "-allocator", .root_module = module });
        const run = b.addRunArtifact(executable);
        run.has_side_effects = true;
        const step = b.step(kind ++ "-allocator-benchmark", "Measure host " ++ kind ++ " allocation under reuse and memory pressure");
        step.dependOn(&run.step);
    }
}

pub fn addBenchmarkGate(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
    benchmark_command: *std.Build.Step.Run,
) BenchmarkGate {
    const checker = b.addExecutable(.{
        .name = "check-kernel-benchmarks",
        .root_module = benchmarkGateModule(b, optimize),
    });
    const check = b.addRunArtifact(checker);
    check.setCwd(b.path("."));
    check.addArgs(&.{
        "check",
        "build/kernel-benchmark.log",
        "benchmarks/kernel-thresholds.txt",
        "benchmarks/kernel-baseline.txt",
        "benchmarks/kernel-quality-gates.txt",
        "build/kernel-benchmark-summary.md",
    });
    check.step.dependOn(&benchmark_command.step);

    const checker_tests = b.addTest(.{
        .name = "check-kernel-benchmarks-tests",
        .root_module = benchmarkGateModule(b, optimize),
    });
    const tests = b.addRunArtifact(checker_tests);
    tests.setCwd(b.path("."));

    return .{
        .check = check,
        .tests = tests,
    };
}

fn benchmarkGateModule(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("tools/check_kernel_benchmarks.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
}
