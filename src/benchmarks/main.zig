const std = @import("std");
const workload = @import("shared.zig");
const at_semantics = @import("at_semantics");
const fd_freelist = @import("fd_freelist");
const ipc = @import("ipc_semantics");
const shell = @import("shell_support");
const tcp = @import("tcp_protocol");

comptime {
    @setEvalBranchQuota(5000);
}

const parser = shell.parser;
const shell_glob = shell.glob;
const registry = shell.registry;

const Config = struct {
    filter: ?[]const u8 = null,
    duration_ns: u64 = 250 * std.time.ns_per_ms,
    warmup_ns: u64 = 50 * std.time.ns_per_ms,
    min_batch: usize = 64,
    list_only: bool = false,
    help: bool = false,
};

const BenchmarkFn = *const fn (iterations: usize) void;

const Benchmark = struct {
    meta: workload.BenchmarkMetadata,
    run: BenchmarkFn,
};

const RunStats = struct {
    iterations: u64 = 0,
    elapsed_ns: u64 = 0,
};

const sem_ops = workload.makeSemOps(ipc);
const expansion_hooks = workload.makeExpansionHooks(parser);

const registry_lookup_inputs = [_][]const u8{
    "help",
    "ls",
    "chmod",
    "chown",
    "sleep",
    "hostname",
    "which",
    "missing",
    "zz-nope",
};

const shell_registry_lookup = workload.BenchmarkMetadata{
    .name = "shell.registry.lookup",
    .description = "lookup builtin command metadata across hot hits and misses",
    .default_iterations = 400_000,
};

const benchmarks = [_]Benchmark{
    .{ .meta = shell_registry_lookup, .run = benchShellRegistryLookup },
    .{ .meta = workload.shell_tokenize_expansions, .run = benchShellTokenizeExpansions },
    .{ .meta = workload.shell_pipeline_commandline, .run = benchShellPipelineCommandline },
    .{ .meta = workload.shell_glob_compile_matrix, .run = benchShellGlobCompileMatrix },
    .{ .meta = workload.shell_glob_match_matrix, .run = benchShellGlobMatchMatrix },
    .{ .meta = workload.syscall_at_resolve_matrix, .run = benchSyscallAtResolveMatrix },
    .{ .meta = workload.vfs_fd_freelist_churn, .run = benchVfsFdFreelistChurn },
    .{ .meta = workload.tcpChecksumDualStack(@sizeOf(tcp.Header)), .run = benchTcpChecksumDualStack },
    .{ .meta = workload.tcp_options_roundtrip, .run = benchTcpOptionsRoundtrip },
    .{ .meta = workload.ipc_semops_batch, .run = benchIpcSemOpsBatch },
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const config = parseArgs(args[1..]) catch |err| {
        printUsage();
        return err;
    };

    if (config.help) {
        printUsage();
        return;
    }

    if (config.list_only) {
        listBenchmarks(config.filter);
        return;
    }

    const selected_count = countBenchmarks(config.filter);
    if (selected_count == 0) {
        if (config.filter) |filter| {
            std.debug.print("No benchmarks matched filter '{s}'.\n", .{filter});
        } else {
            std.debug.print("No benchmarks available.\n", .{});
        }
        return error.NoBenchmarksSelected;
    }

    std.debug.print(
        "Running {d} benchmark{s} ({d} ms measurement, {d} ms warmup, min batch {d})\n",
        .{ selected_count, plural(selected_count), config.duration_ns / std.time.ns_per_ms, config.warmup_ns / std.time.ns_per_ms, config.min_batch },
    );

    var suite_timer = try std.time.Timer.start();
    for (benchmarks) |benchmark| {
        if (!matchesFilter(config.filter, benchmark.meta.name)) continue;

        const stats = try executeBenchmark(benchmark, config);
        printBenchmarkResult(benchmark, stats);
    }

    std.debug.print("Completed in {d:.2} ms\n", .{nsToMs(suite_timer.read())});
}

fn parseArgs(args: []const [:0]const u8) !Config {
    var config = Config{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "--help")) {
            config.help = true;
        } else if (std.mem.eql(u8, arg, "--list")) {
            config.list_only = true;
        } else if (std.mem.eql(u8, arg, "--filter")) {
            idx += 1;
            if (idx >= args.len) return error.MissingFilterValue;
            config.filter = args[idx];
        } else if (std.mem.eql(u8, arg, "--duration-ms")) {
            idx += 1;
            if (idx >= args.len) return error.MissingDurationValue;
            config.duration_ns = try parseMilliseconds(args[idx]);
        } else if (std.mem.eql(u8, arg, "--warmup-ms")) {
            idx += 1;
            if (idx >= args.len) return error.MissingWarmupValue;
            config.warmup_ns = try parseMilliseconds(args[idx]);
        } else if (std.mem.eql(u8, arg, "--min-batch")) {
            idx += 1;
            if (idx >= args.len) return error.MissingBatchValue;
            config.min_batch = try std.fmt.parseInt(usize, args[idx], 10);
            if (config.min_batch == 0) return error.InvalidBatchValue;
        } else {
            std.debug.print("Unknown benchmark argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return config;
}

fn parseMilliseconds(value: []const u8) !u64 {
    const milliseconds = try std.fmt.parseInt(u64, value, 10);
    return milliseconds * std.time.ns_per_ms;
}

fn printUsage() void {
    std.debug.print(
        "Usage: zig build bench -- [--list] [--filter <substring>] [--duration-ms <ms>] [--warmup-ms <ms>] [--min-batch <count>]\n\nExamples:\n  zig build bench\n  zig build bench -- --list\n  zig build bench -- --filter tcp --duration-ms 1000\n",
        .{},
    );
}

fn listBenchmarks(filter: ?[]const u8) void {
    var count: usize = 0;
    for (benchmarks) |benchmark| {
        if (!matchesFilter(filter, benchmark.meta.name)) continue;
        std.debug.print("{s}\n  {s}\n", .{ benchmark.meta.name, benchmark.meta.description });
        count += 1;
    }

    if (count == 0) {
        if (filter) |needle| {
            std.debug.print("No benchmarks matched filter '{s}'.\n", .{needle});
        } else {
            std.debug.print("No benchmarks available.\n", .{});
        }
    }
}

fn countBenchmarks(filter: ?[]const u8) usize {
    var count: usize = 0;
    for (benchmarks) |benchmark| {
        if (matchesFilter(filter, benchmark.meta.name)) count += 1;
    }
    return count;
}

fn matchesFilter(filter: ?[]const u8, name: []const u8) bool {
    const needle = filter orelse return true;
    return std.mem.indexOf(u8, name, needle) != null;
}

fn executeBenchmark(benchmark: Benchmark, config: Config) !RunStats {
    if (config.warmup_ns > 0) {
        _ = try runForDuration(benchmark, config.warmup_ns, config.min_batch);
    }
    return runForDuration(benchmark, config.duration_ns, config.min_batch);
}

fn runForDuration(benchmark: Benchmark, target_ns: u64, min_batch: usize) !RunStats {
    var stats = RunStats{};
    var batch = min_batch;
    const half_target = target_ns / 2;

    while (stats.elapsed_ns < target_ns or stats.iterations == 0) {
        var timer = try std.time.Timer.start();
        benchmark.run(batch);
        const elapsed_ns = timer.read();

        stats.elapsed_ns += elapsed_ns;
        stats.iterations += @as(u64, @intCast(batch));

        if (stats.elapsed_ns >= target_ns and stats.iterations > 0) break;

        if (elapsed_ns == 0) {
            batch = saturatingDouble(batch);
            continue;
        }

        if (stats.elapsed_ns < half_target) {
            batch = saturatingDouble(batch);
            continue;
        }

        const remaining_ns = target_ns - stats.elapsed_ns;
        const batch_u64: u64 = @intCast(batch);
        var estimated_batch = batch_u64 * @max(remaining_ns, 1) / elapsed_ns;
        if (estimated_batch < batch_u64) estimated_batch = batch_u64;
        batch = clampBatch(estimated_batch, min_batch);
    }

    return stats;
}

fn clampBatch(candidate: u64, min_batch: usize) usize {
    const clamped = @min(candidate, @as(u64, std.math.maxInt(usize)));
    const batch: usize = @intCast(clamped);
    return if (batch < min_batch) min_batch else batch;
}

fn saturatingDouble(value: usize) usize {
    if (value > std.math.maxInt(usize) / 2) return std.math.maxInt(usize);
    return value * 2;
}

fn printBenchmarkResult(benchmark: Benchmark, stats: RunStats) void {
    const elapsed_ns = if (stats.elapsed_ns == 0) @as(u64, 1) else stats.elapsed_ns;
    const elapsed_ns_f = @as(f64, @floatFromInt(elapsed_ns));
    const iterations_f = @as(f64, @floatFromInt(stats.iterations));
    const ns_per_op = elapsed_ns_f / iterations_f;
    const ops_per_second = iterations_f * @as(f64, @floatFromInt(std.time.ns_per_s)) / elapsed_ns_f;

    if (benchmark.meta.bytes_per_iteration > 0) {
        const throughput = @as(f64, @floatFromInt(benchmark.meta.bytes_per_iteration)) * iterations_f;
        const mib_per_second = throughput * @as(f64, @floatFromInt(std.time.ns_per_s)) / elapsed_ns_f / (1024.0 * 1024.0);
        std.debug.print(
            "{s}: {d:.1} ns/op | {d:.2} ops/s | {d:.2} MiB/s | {d} iterations\n",
            .{ benchmark.meta.name, ns_per_op, ops_per_second, mib_per_second, stats.iterations },
        );
        return;
    }

    std.debug.print(
        "{s}: {d:.1} ns/op | {d:.2} ops/s | {d} iterations\n",
        .{ benchmark.meta.name, ns_per_op, ops_per_second, stats.iterations },
    );
}

fn plural(count: usize) []const u8 {
    return if (count == 1) "" else "s";
}

fn nsToMs(value: u64) f64 {
    return @as(f64, @floatFromInt(value)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
}

fn benchShellTokenizeExpansions(iterations: usize) void {
    var sink: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const input = if ((sink & 1) == 0) workload.tokenize_input_a else workload.tokenize_input_b;
        var storage: [parser.MAX_TOKENS][parser.MAX_COMMAND_LENGTH]u8 = undefined;
        var tokens: [parser.MAX_TOKENS]parser.CommandToken = undefined;

        const token_count = parser.tokenizeCommandLine(input, &storage, &tokens, expansion_hooks, true) catch unreachable;
        sink +%= token_count;
        sink +%= tokens[token_count - 1].len;
        std.mem.doNotOptimizeAway(&tokens);
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchShellPipelineCommandline(iterations: usize) void {
    var sink: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const input = if ((sink & 1) == 0) workload.pipeline_input_a else workload.pipeline_input_b;
        var storage: [parser.MAX_TOKENS][parser.MAX_COMMAND_LENGTH]u8 = undefined;
        var tokens: [parser.MAX_TOKENS]parser.CommandToken = undefined;

        const token_count = parser.tokenizeCommandLine(input, &storage, &tokens, .{}, true) catch unreachable;
        const pipeline = parser.parsePipeline(tokens[0..token_count]) catch unreachable;
        sink +%= pipeline.stage_count;
        sink +%= pipeline.stages[pipeline.stage_count - 1].arg_count;
        std.mem.doNotOptimizeAway(&pipeline);
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchShellGlobMatchMatrix(iterations: usize) void {
    var sink: usize = 0;
    var offset: usize = 0;
    var cache = shell_glob.PatternCache(workload.glob_patterns.len){};
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        for (workload.glob_patterns, 0..) |pattern, pattern_idx| {
            const compiled = cache.getOrCompile(pattern) catch unreachable;
            var candidate_idx = pattern_idx + offset;
            var count: usize = 0;
            while (count < workload.glob_candidates.len) : (count += 1) {
                const candidate = workload.glob_candidates[candidate_idx % workload.glob_candidates.len];
                if (compiled.matches(candidate)) sink +%= 1;
                candidate_idx += 1;
            }
        }
        offset = (offset + 1 + (sink & 3)) % workload.glob_candidates.len;
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchShellGlobCompileMatrix(iterations: usize) void {
    var sink: usize = 0;
    var offset: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        for (workload.glob_patterns, 0..) |_, pattern_idx| {
            const pattern = workload.glob_patterns[(pattern_idx + offset) % workload.glob_patterns.len];
            const compiled = shell_glob.CompiledPattern.init(pattern) catch unreachable;
            sink +%= compiled.len;
            sink +%= compiled.literal_prefix_len;
            sink +%= compiled.literal_suffix_len;
            sink +%= @intFromBool(compiled.has_wildcards);
            std.mem.doNotOptimizeAway(&compiled);
        }
        offset = (offset + 1 + (sink & 1)) % workload.glob_patterns.len;
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchShellRegistryLookup(iterations: usize) void {
    var sink: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const name = registry_lookup_inputs[(i + (sink & 1)) % registry_lookup_inputs.len];
        if (registry.lookup(name)) |command| {
            sink +%= @intFromEnum(command.id);
            sink +%= command.name.len;
        } else {
            sink +%= name.len;
        }
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchSyscallAtResolveMatrix(iterations: usize) void {
    var sink: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        for (workload.at_cases) |case| {
            var visible_buf: [512]u8 = undefined;
            var actual_buf: [512]u8 = undefined;
            const resolved = at_semantics.resolveAtPath(case.root, case.cwd, case.dir_path, case.path, &visible_buf, &actual_buf) catch unreachable;
            sink +%= resolved.len;
            sink +%= actual_buf[resolved.len - 1];
        }
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchVfsFdFreelistChurn(iterations: usize) void {
    var sink: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var freelist: [256]u8 = undefined;
        var top: usize = 0;
        fd_freelist.initFreelist(&freelist, &top);

        const first = fd_freelist.allocFd(&freelist, &top).?;
        const second = fd_freelist.allocFd(&freelist, &top).?;
        const target: u32 = @intCast(32 + (i % 16));
        const reserved = fd_freelist.reserveFd(&freelist, &top, target);
        fd_freelist.freeFd(&freelist, &top, second);
        const recycled = fd_freelist.allocFd(&freelist, &top).?;

        sink +%= first;
        sink +%= recycled;
        sink +%= top;
        sink +%= @intFromBool(reserved);
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchTcpChecksumDualStack(iterations: usize) void {
    var sink: usize = 0;
    var payload = workload.makeTcpPayload();
    var header = workload.makeTcpHeader(tcp);
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        header.seq_num +%= @intCast(i + 1);
        const payload_idx = (@as(usize, @intCast(header.seq_num)) + @as(usize, @intCast(sink & 0xff))) % payload.len;
        payload[payload_idx] +%= @truncate(header.seq_num);

        sink +%= tcp.calculateChecksumIPv4(workload.tcp_ipv4_src, workload.tcp_ipv4_dst, &header, payload[0..]);
        sink +%= tcp.calculateChecksumIPv6(&workload.tcp_ipv6_src, &workload.tcp_ipv6_dst, &header, payload[0..]);
        std.mem.doNotOptimizeAway(&header);
    }
    std.mem.doNotOptimizeAway(&payload);
    std.mem.doNotOptimizeAway(&sink);
}

fn benchTcpOptionsRoundtrip(iterations: usize) void {
    var sink: usize = 0;
    var buffer: [40]u8 = undefined;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var conn = workload.makeTcpConn(tcp, @intCast(i + @as(usize, @intCast(sink & 0xffff))));
        const options_len = tcp.buildOptions(&conn, &buffer, true);
        const measured_rtt = tcp.parseOptions(buffer[0..options_len], &conn, conn.ts_ecr +% 17);

        sink +%= options_len;
        sink +%= measured_rtt orelse 0;
        sink +%= conn.mss;
        sink +%= conn.ts_recent;
        std.mem.doNotOptimizeAway(&buffer);
        std.mem.doNotOptimizeAway(&conn);
    }
    std.mem.doNotOptimizeAway(&sink);
}

fn benchIpcSemOpsBatch(iterations: usize) void {
    var sink: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var set = workload.makeSemSet(ipc);
        set.sems[0].value = @intCast(4 + (i & 1));
        set.sems[1].value = @intCast(2 + (i & 1));
        set.sems[2].value = @intCast(i & 3);

        const rc = ipc.applySemOps(&set, sem_ops[0..]);
        if (rc != 0) unreachable;

        sink +%= @intCast(set.sems[0].value);
        sink +%= @intCast(set.sems[1].value);
        sink +%= @intCast(set.sems[2].value);
        std.mem.doNotOptimizeAway(&set);
    }
    std.mem.doNotOptimizeAway(&sink);
}
