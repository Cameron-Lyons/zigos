const std = @import("std");
const shared = @import("shared.zig");
const codegen_target = @import("../src/arch/codegen_target.zig");

pub const BenchmarkGate = struct {
    check: *std.Build.Step.Run,
    tests: *std.Build.Step.Run,
};

/// A `tools/benchmark_*.zig` program measuring its namespace of
/// `src/host_benchmarks.zig`.
const HostBenchmark = struct {
    name: []const u8,
    source: []const u8,
    description: []const u8,
    architecture: ?std.Target.Cpu.Arch = null,
    native_instruction_floor: bool = false,
    args: []const []const u8 = &.{},
};

pub fn addHostBenchmarks(b: *std.Build) void {
    const text_boundaries_only = b.option(bool, "text-boundaries-only", "Measure only Unicode boundary helpers in the text-layout benchmark") orelse false;
    const benchmarks = [_]HostBenchmark{
        .{ .name = "frame-allocator", .source = "tools/benchmark_frame_allocator.zig", .description = "Measure host frame allocation under reuse and memory pressure" },
        .{ .name = "heap-allocator", .source = "tools/benchmark_heap_allocator.zig", .description = "Measure host heap allocation under reuse and memory pressure" },
        .{ .name = "ipc-ring", .source = "tools/benchmark_ipc_ring.zig", .description = "Measure bounded IPC send/receive with the native x86-64 instruction floor", .native_instruction_floor = true },
        .{ .name = "response-preflight", .source = "tools/benchmark_response_preflight.zig", .description = "Compare syscall response admission with one complete user-range validation", .native_instruction_floor = true },
        .{ .name = "text-scanout", .source = "tools/benchmark_text_scanout.zig", .description = "Measure text rasterization and incremental framebuffer damage on the host", .args = &.{"--check-damage"} },
        .{ .name = "id-index", .source = "tools/benchmark_id_index.zig", .description = "Measure bounded ID lookup and deletion under generation reuse and churn" },
        .{ .name = "endpoint-readiness", .source = "tools/benchmark_endpoint_readiness.zig", .description = "Compare owner scans with counted endpoint readiness on the host" },
        .{ .name = "text-layout", .source = "tools/benchmark_text_layout.zig", .description = "Compare text layout, vertical navigation and Unicode boundary helpers on the host" },
        .{ .name = "workspace-index", .source = "tools/benchmark_workspace_index.zig", .description = "Measure workspace path and object indexes under collisions and churn" },
        .{ .name = "object-chunks", .source = "tools/benchmark_object_chunks.zig", .description = "Compare immutable hash scratch preparation and positioned object chunk cursors" },
        .{ .name = "surface-text", .source = "tools/benchmark_surface_text.zig", .description = "Compare repeated and combined canonical text boundary validation" },
        .{ .name = "scheduler-wake", .source = "tools/benchmark_scheduler_wake.zig", .description = "Measure coalesced and reactivated native task wakes on the host", .architecture = .x86_64 },
    };
    const boot_options = shared.kernelOptions(b, .zigos_native, .production);
    for (benchmarks) |benchmark| {
        const target = if (benchmark.native_instruction_floor) native: {
            var query = codegen_target.query();
            query.os_tag = b.graph.host.result.os.tag;
            query.abi = b.graph.host.result.abi;
            break :native b.resolveTargetQuery(query);
        } else if (benchmark.architecture) |architecture|
            b.resolveTargetQuery(.{
                .cpu_arch = architecture,
                .os_tag = b.graph.host.result.os.tag,
                .abi = b.graph.host.result.abi,
            })
        else
            b.graph.host;
        const module = b.createModule(.{
            .root_source_file = b.path(benchmark.source),
            .target = target,
            .optimize = .fast,
        });
        const fixtures = b.createModule(.{
            .root_source_file = b.path("src/host_benchmarks.zig"),
            .target = target,
            .optimize = .fast,
        });
        fixtures.addOptions("build_options", boot_options);
        fixtures.addImport("binary_cursor", b.createModule(.{
            .root_source_file = b.path("src/native/core/binary_cursor.zig"),
            .target = target,
            .optimize = .fast,
        }));
        module.addImport("host_benchmarks", fixtures);
        const executable = b.addExecutable(.{ .name = b.fmt("benchmark-{s}", .{benchmark.name}), .root_module = module });
        const run = b.addRunArtifact(executable);
        run.addArgs(benchmark.args);
        if (text_boundaries_only and std.mem.eql(u8, benchmark.name, "text-layout")) run.addArg("--boundaries-only");
        run.has_side_effects = true;
        b.step(b.fmt("{s}-benchmark", .{benchmark.name}), benchmark.description).dependOn(&run.step);
    }
}

pub fn addSyscallDispatchBenchmark(b: *std.Build, userspace_images: @import("userspace.zig").ArtifactSet) void {
    var query = codegen_target.query();
    query.os_tag = b.graph.host.result.os.tag;
    query.abi = b.graph.host.result.abi;
    const target = b.resolveTargetQuery(query);
    const module = b.createModule(.{
        .root_source_file = b.path("src/syscall_dispatch_benchmark.zig"),
        .target = target,
        .optimize = .fast,
    });
    const wire = @import("native_modules.zig").addTargetWireModules(b, target, .fast);
    module.addImport("binary_cursor", wire.binary_cursor);
    module.addImport("userspace_wire", wire.userspace_wire);
    module.addImport("userspace_archive", userspace_images.production_archive_module);
    module.addImport("production_artifact_manifest", userspace_images.production_manifest_module);
    module.addOptions("build_options", shared.kernelOptions(b, .zigos_native, .production));
    const tool = b.createModule(.{
        .root_source_file = b.path("tools/benchmark_syscall_dispatch.zig"),
        .target = target,
        .optimize = .fast,
    });
    tool.addImport("syscall_dispatch_benchmark", module);
    const entitlements = if (target.result.os.tag == .macos)
        b.addWriteFiles().add("syscall-benchmark-entitlements.plist", "<plist version=\"1.0\"><dict/></plist>\n")
    else
        null;
    const executable = std.Build.Step.Compile.create(b, .{
        .name = "benchmark-syscall-dispatch",
        .kind = .exe,
        .root_module = tool,
        .entitlements = entitlements,
    });
    const run = b.addRunArtifact(executable);
    run.addArgs(&.{
        if (b.graph.host.result.cpu.arch == .x86_64) "--execution-mode=native" else if (b.graph.host.result.os.tag == .macos) "--execution-mode=translated" else "--execution-mode=unspecified",
        "--seed=0x1e22b6d03db41815",
    });
    run.addPassthruArgs();
    run.has_side_effects = true;
    b.step("syscall-dispatch-benchmark", "Measure authorized successful hosted syscall dispatch, excluding native entry and return").dependOn(&run.step);
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
