const std = @import("std");

pub const BenchmarkGate = struct {
    check: *std.Build.Step.Run,
    tests: *std.Build.Step.Run,
};

const HostBenchmark = struct {
    name: []const u8,
    source: []const u8,
    import_name: []const u8,
    import_source: []const u8,
    description: []const u8,
    args: []const []const u8 = &.{},
    imports: []const struct { name: []const u8, source: []const u8 } = &.{},
};

pub fn addHostBenchmarks(b: *std.Build) void {
    const benchmarks = [_]HostBenchmark{
        .{ .name = "frame-allocator", .source = "tools/benchmark_frame_allocator.zig", .import_name = "frame_allocator", .import_source = "src/kernel/memory/frame_allocator.zig", .description = "Measure host frame allocation under reuse and memory pressure" },
        .{ .name = "heap-allocator", .source = "tools/benchmark_heap_allocator.zig", .import_name = "heap_allocator", .import_source = "src/heap_benchmark.zig", .description = "Measure host heap allocation under reuse and memory pressure" },
        .{ .name = "ipc-ring", .source = "tools/benchmark_ipc_ring.zig", .import_name = "ipc_ring", .import_source = "src/native/kernel_api/ipc_ring.zig", .description = "Measure bounded IPC ring send/receive and backpressure on the host" },
        .{ .name = "text-scanout", .source = "tools/benchmark_text_scanout.zig", .import_name = "text_scanout", .import_source = "src/text_scanout_benchmark.zig", .description = "Measure text rasterization and incremental framebuffer damage on the host", .args = &.{"--check-damage"} },
        .{ .name = "id-index", .source = "tools/benchmark_id_index.zig", .import_name = "id_index", .import_source = "src/native/core/id_index.zig", .description = "Measure bounded ID lookup and deletion under generation reuse and churn" },
        .{ .name = "endpoint-readiness", .source = "tools/benchmark_endpoint_readiness.zig", .import_name = "endpoint", .import_source = "src/endpoint_benchmark.zig", .description = "Compare owner scans with counted endpoint readiness on the host" },
        .{ .name = "text-layout", .source = "tools/benchmark_text_layout.zig", .import_name = "text_layout", .import_source = "src/text_layout_benchmark.zig", .description = "Compare repeated text layout with one visible-window scan on the host" },
        .{ .name = "workspace-index", .source = "tools/benchmark_workspace_index.zig", .import_name = "workspace_index", .import_source = "src/workspace_index_benchmark.zig", .description = "Measure workspace path and object indexes under collisions and churn" },
        .{ .name = "object-chunks", .source = "tools/benchmark_object_chunks.zig", .import_name = "object_chunks", .import_source = "src/object_chunk_benchmark.zig", .description = "Compare prefix and positioned object chunk cursors for sync transfers", .imports = &.{.{ .name = "binary_cursor", .source = "src/native/core/binary_cursor.zig" }} },
        .{ .name = "surface-text", .source = "tools/benchmark_surface_text.zig", .import_name = "surface_text", .import_source = "src/surface_text_benchmark.zig", .description = "Compare repeated and combined canonical text boundary validation" },
    };
    for (benchmarks) |benchmark| {
        const module = b.createModule(.{
            .root_source_file = b.path(benchmark.source),
            .target = b.graph.host,
            .optimize = .fast,
        });
        const imported_module = b.createModule(.{
            .root_source_file = b.path(benchmark.import_source),
            .target = b.graph.host,
            .optimize = .fast,
        });
        for (benchmark.imports) |dependency| {
            imported_module.addImport(dependency.name, b.createModule(.{
                .root_source_file = b.path(dependency.source),
                .target = b.graph.host,
                .optimize = .fast,
            }));
        }
        module.addImport(benchmark.import_name, imported_module);
        const executable = b.addExecutable(.{ .name = b.fmt("benchmark-{s}", .{benchmark.name}), .root_module = module });
        const run = b.addRunArtifact(executable);
        run.addArgs(benchmark.args);
        run.has_side_effects = true;
        b.step(b.fmt("{s}-benchmark", .{benchmark.name}), benchmark.description).dependOn(&run.step);
    }
}

pub fn addBenchmarkGate(
    b: *std.Build,
    optimize: std.lang.Optimize,
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
    optimize: std.lang.Optimize,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("tools/check_kernel_benchmarks.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
}
