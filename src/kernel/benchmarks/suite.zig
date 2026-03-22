const std = @import("std");
const workload = @import("../../benchmarks/shared.zig");
const x86 = @import("../../arch/x86.zig");
const console = @import("../utils/console.zig");
const fd_freelist = @import("../fs/fd_freelist.zig");
const ipc = @import("../process/syscall/ipc_semantics.zig");
const at_semantics = @import("../process/syscall/at_semantics.zig");
const path_semantics = @import("../process/syscall/path_semantics.zig");
const posix = @import("../utils/posix.zig");
const parser = @import("../shell/parser/pipeline.zig");
const shell_launcher = @import("../shell/launcher.zig");
const shell_glob = @import("../shell/glob.zig");
const tcp = @import("../net/tcp/protocol.zig");

const BenchmarkError = parser.TokenizationError || parser.PipelineConfigError || path_semantics.Error || error{ SemOpFailed, SpawnWaitFailed };
const BenchmarkFn = *const fn (iterations: usize) BenchmarkError!u64;

const Benchmark = struct {
    meta: workload.BenchmarkMetadata,
    run: BenchmarkFn,
};

const sem_ops = workload.makeSemOps(ipc);
const expansion_hooks = workload.makeExpansionHooks(parser);
const true_command = [_][*:0]const u8{"/bin/true"};

const benchmarks = [_]Benchmark{
    .{ .meta = workload.shell_tokenize_expansions, .run = benchShellTokenizeExpansions },
    .{ .meta = workload.shell_pipeline_commandline, .run = benchShellPipelineCommandline },
    .{ .meta = workload.shell_glob_compile_matrix, .run = benchShellGlobCompileMatrix },
    .{ .meta = workload.shell_glob_match_matrix, .run = benchShellGlobMatchMatrix },
    .{ .meta = workload.shell_user_spawn_wait, .run = benchShellUserSpawnWait },
    .{ .meta = workload.syscall_at_resolve_matrix, .run = benchSyscallAtResolveMatrix },
    .{ .meta = workload.vfs_fd_freelist_churn, .run = benchVfsFdFreelistChurn },
    .{ .meta = workload.tcpChecksumDualStack(@sizeOf(tcp.Header)), .run = benchTcpChecksumDualStack },
    .{ .meta = workload.tcp_options_roundtrip, .run = benchTcpOptionsRoundtrip },
    .{ .meta = workload.ipc_semops_batch, .run = benchIpcSemOpsBatch },
};

pub fn run() bool {
    printMarker("BENCH:START");

    const suite_start_cycles = x86.rdtsc();

    var completed: usize = 0;
    for (benchmarks) |benchmark| {
        const warmup_iterations = @max(@as(usize, 64), benchmark.meta.default_iterations / 10);
        _ = @call(.never_inline, benchmark.run, .{warmup_iterations}) catch |err| {
            printFailure(benchmark.meta.name, err);
            return false;
        };

        const start_cycles = x86.rdtsc();
        const checksum = @call(.never_inline, benchmark.run, .{benchmark.meta.default_iterations}) catch |err| {
            printFailure(benchmark.meta.name, err);
            return false;
        };
        const elapsed_cycles = x86.rdtsc() - start_cycles;

        printResult(benchmark, elapsed_cycles, checksum);
        completed += 1;
    }

    const suite_elapsed_cycles = x86.rdtsc() - suite_start_cycles;
    printSummary(completed, suite_elapsed_cycles);
    printMarker("BENCH:PASS");
    return true;
}

fn printMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}

fn printFailure(name: []const u8, err: BenchmarkError) void {
    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "BENCH:FAIL:{s}:{s}\n", .{ name, @errorName(err) }) catch "BENCH:FAIL\n";
    console.print(line);
}

fn printResult(benchmark: Benchmark, cycles: u64, checksum: u64) void {
    var ratio_buf: [32]u8 = undefined;
    const ratio = formatRatioFixed2(&ratio_buf, cycles, benchmark.meta.default_iterations);

    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "BENCH:RESULT:{s}:iterations={d}:cycles={d}:cycles_per_op={s}:checksum={d}\n",
        .{ benchmark.meta.name, benchmark.meta.default_iterations, cycles, ratio, checksum },
    ) catch "BENCH:RESULT\n";
    console.print(line);
}

fn printSummary(completed: usize, total_cycles: u64) void {
    var line_buf: [192]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "BENCH:SUMMARY:benchmarks={d}:total_cycles={d}\n",
        .{ completed, total_cycles },
    ) catch "BENCH:SUMMARY\n";
    console.print(line);
}

fn formatRatioFixed2(buffer: []u8, numerator: u64, denominator: usize) []const u8 {
    if (denominator == 0) return "0.00";

    const denominator_u64: u64 = @intCast(denominator);
    var whole = numerator / denominator_u64;
    var frac = ((numerator % denominator_u64) * 100 + denominator_u64 / 2) / denominator_u64;
    if (frac == 100) {
        whole += 1;
        frac = 0;
    }

    return std.fmt.bufPrint(buffer, "{d}.{d:0>2}", .{ whole, frac }) catch "0.00";
}

fn benchShellTokenizeExpansions(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const input = if ((sink & 1) == 0) workload.tokenize_input_a else workload.tokenize_input_b;
        var storage: [parser.MAX_TOKENS][parser.MAX_COMMAND_LENGTH]u8 = undefined;
        var tokens: [parser.MAX_TOKENS]parser.CommandToken = undefined;

        const token_count = try parser.tokenizeCommandLine(input, &storage, &tokens, expansion_hooks, true);
        sink +%= token_count;
        sink +%= tokens[token_count - 1].len;
        std.mem.doNotOptimizeAway(&tokens);
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchShellPipelineCommandline(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const input = if ((sink & 1) == 0) workload.pipeline_input_a else workload.pipeline_input_b;
        var storage: [parser.MAX_TOKENS][parser.MAX_COMMAND_LENGTH]u8 = undefined;
        var tokens: [parser.MAX_TOKENS]parser.CommandToken = undefined;

        const token_count = try parser.tokenizeCommandLine(input, &storage, &tokens, .{}, true);
        const pipeline = try parser.parsePipeline(tokens[0..token_count]);
        sink +%= pipeline.stage_count;
        sink +%= pipeline.stages[pipeline.stage_count - 1].arg_count;
        std.mem.doNotOptimizeAway(&pipeline);
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchShellGlobMatchMatrix(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
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
        offset = (offset + 1 + @as(usize, @intCast(sink & 3))) % workload.glob_candidates.len;
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchShellGlobCompileMatrix(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
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
        offset = (offset + 1 + @as(usize, @intCast(sink & 1))) % workload.glob_patterns.len;
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchShellUserSpawnWait(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const pid = shell_launcher.launchExternalCommand(true_command[0..], null, null, null) catch return error.SpawnWaitFailed;
        var status: i32 = 0;
        const waited = posix.wait4(@intCast(pid), &status, 0, null) catch return error.SpawnWaitFailed;
        shell_launcher.releaseIfPresent(pid);
        if (waited != @as(i32, @intCast(pid)) or status != 0) return error.SpawnWaitFailed;
        sink +%= @as(u64, @intCast(pid));
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchSyscallAtResolveMatrix(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        for (workload.at_cases) |case| {
            var visible_buf: [512]u8 = undefined;
            var actual_buf: [512]u8 = undefined;
            const resolved = try at_semantics.resolveAtPath(case.root, case.cwd, case.dir_path, case.path, &visible_buf, &actual_buf);
            sink +%= resolved.len;
            sink +%= actual_buf[resolved.len - 1];
        }
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchVfsFdFreelistChurn(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
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
    return sink;
}

fn benchTcpChecksumDualStack(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
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
    return sink;
}

fn benchTcpOptionsRoundtrip(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
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
    return sink;
}

fn benchIpcSemOpsBatch(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var set = workload.makeSemSet(ipc);
        set.sems[0].value = @intCast(4 + (i & 1));
        set.sems[1].value = @intCast(2 + (i & 1));
        set.sems[2].value = @intCast(i & 3);

        const rc = ipc.applySemOps(&set, sem_ops[0..]);
        if (rc != 0) return error.SemOpFailed;

        sink +%= @as(u64, @intCast(set.sems[0].value));
        sink +%= @as(u64, @intCast(set.sems[1].value));
        sink +%= @as(u64, @intCast(set.sems[2].value));
        std.mem.doNotOptimizeAway(&set);
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}
