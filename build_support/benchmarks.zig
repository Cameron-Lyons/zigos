const std = @import("std");
const shared = @import("shared.zig");
const codegen_target = @import("../src/arch/codegen_target.zig");

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
    architecture: ?std.Target.Cpu.Arch = null,
    native_instruction_floor: bool = false,
    boot_options: bool = false,
    args: []const []const u8 = &.{},
    imports: []const struct { name: []const u8, source: []const u8 } = &.{},
};

pub fn addHostBenchmarks(b: *std.Build) void {
    const text_boundaries_only = b.option(bool, "text-boundaries-only", "Measure only Unicode boundary helpers in the text-layout benchmark") orelse false;
    const benchmarks = [_]HostBenchmark{
        .{ .name = "frame-allocator", .source = "tools/benchmark_frame_allocator.zig", .import_name = "frame_allocator", .import_source = "src/kernel/memory/frame_allocator.zig", .description = "Measure host frame allocation under reuse and memory pressure" },
        .{ .name = "heap-allocator", .source = "tools/benchmark_heap_allocator.zig", .import_name = "heap_allocator", .import_source = "src/heap_benchmark.zig", .description = "Measure host heap allocation under reuse and memory pressure" },
        .{ .name = "ipc-ring", .source = "tools/benchmark_ipc_ring.zig", .import_name = "ipc_ring", .import_source = "src/native/kernel_api/ipc_ring.zig", .description = "Measure bounded IPC send/receive with the native x86-64 instruction floor", .native_instruction_floor = true },
        .{ .name = "response-preflight", .source = "tools/benchmark_response_preflight.zig", .import_name = "response_preflight", .import_source = "src/response_preflight_benchmark.zig", .description = "Compare syscall response admission with one complete user-range validation", .native_instruction_floor = true },
        .{ .name = "text-scanout", .source = "tools/benchmark_text_scanout.zig", .import_name = "text_scanout", .import_source = "src/text_scanout_benchmark.zig", .description = "Measure text rasterization and incremental framebuffer damage on the host", .args = &.{"--check-damage"} },
        .{ .name = "id-index", .source = "tools/benchmark_id_index.zig", .import_name = "id_index", .import_source = "src/native/core/id_index.zig", .description = "Measure bounded ID lookup and deletion under generation reuse and churn" },
        .{ .name = "endpoint-readiness", .source = "tools/benchmark_endpoint_readiness.zig", .import_name = "endpoint", .import_source = "src/endpoint_benchmark.zig", .description = "Compare owner scans with counted endpoint readiness on the host" },
        .{ .name = "text-layout", .source = "tools/benchmark_text_layout.zig", .import_name = "text_layout", .import_source = "src/text_layout_benchmark.zig", .description = "Compare text layout, vertical navigation and Unicode boundary helpers on the host" },
        .{ .name = "workspace-index", .source = "tools/benchmark_workspace_index.zig", .import_name = "workspace_index", .import_source = "src/workspace_index_benchmark.zig", .description = "Measure workspace path and object indexes under collisions and churn" },
        .{ .name = "object-chunks", .source = "tools/benchmark_object_chunks.zig", .import_name = "object_chunks", .import_source = "src/object_chunk_benchmark.zig", .description = "Compare immutable hash scratch preparation and positioned object chunk cursors", .imports = &.{.{ .name = "binary_cursor", .source = "src/native/core/binary_cursor.zig" }} },
        .{ .name = "surface-text", .source = "tools/benchmark_surface_text.zig", .import_name = "surface_text", .import_source = "src/surface_text_benchmark.zig", .description = "Compare repeated and combined canonical text boundary validation" },
        .{ .name = "scheduler-wake", .source = "tools/benchmark_scheduler_wake.zig", .import_name = "scheduler", .import_source = "src/scheduler_benchmark.zig", .description = "Measure coalesced and reactivated native task wakes on the host", .architecture = .x86_64, .boot_options = true },
        .{ .name = "storage-checksum", .source = "tools/benchmark_storage_checksum.zig", .import_name = "volume_checksum", .import_source = "src/native/storage/volume/checksum.zig", .description = "Compare portable root-v6 checksums with the previous byte-at-a-time hash on the host" },
        .{ .name = "storage-quota", .source = "tools/benchmark_storage_quota.zig", .import_name = "storage_quota", .import_source = "src/storage_quota_benchmark.zig", .description = "Compare single-pass storage quota collection with repeated arena scans", .imports = &.{.{ .name = "binary_cursor", .source = "src/native/core/binary_cursor.zig" }} },
    };
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
        const imported_module = b.createModule(.{
            .root_source_file = b.path(benchmark.import_source),
            .target = target,
            .optimize = .fast,
        });
        if (benchmark.boot_options) {
            const options = b.addOptions();
            options.addOption(shared.BootProfile, "boot_profile", .zigos_native);
            options.addOption(shared.KernelRole, "kernel_role", .production);
            options.addOption(shared.SmokeFaultMode, "smoke_fault_mode", .none);
            imported_module.addOptions("build_options", options);
        }
        for (benchmark.imports) |dependency| {
            imported_module.addImport(dependency.name, b.createModule(.{
                .root_source_file = b.path(dependency.source),
                .target = target,
                .optimize = .fast,
            }));
        }
        module.addImport(benchmark.import_name, imported_module);
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
    const options = b.addOptions();
    options.addOption(shared.BootProfile, "boot_profile", .zigos_native);
    options.addOption(shared.KernelRole, "kernel_role", .production);
    options.addOption(shared.SmokeFaultMode, "smoke_fault_mode", .none);
    module.addOptions("build_options", options);
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
