const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const console = @import("../utils/console.zig");
const fd_freelist = @import("../fs/fd_freelist.zig");
const ipc = @import("../process/syscall/ipc_semantics.zig");
const at_semantics = @import("../process/syscall/at_semantics.zig");
const path_semantics = @import("../process/syscall/path_semantics.zig");
const parser = @import("../shell/parser.zig");
const shell_glob = @import("../shell/glob.zig");
const tcp = @import("../net/tcp/protocol.zig");

const BenchmarkError = parser.TokenizationError || parser.PipelineConfigError || path_semantics.Error || error{SemOpFailed};
const BenchmarkFn = *const fn (iterations: usize) BenchmarkError!u64;

const Benchmark = struct {
    name: []const u8,
    iterations: usize,
    run: BenchmarkFn,
};

const tokenize_input_a = "echo \"$USER\" $(printf hi) '*.txt' $GLOB /var/log/zigos/*.log";
const tokenize_input_b = "echo \"$USER\" $(printf ok) '*.cfg' $ALTGLOB /var/log/zigos/*.txt";
const pipeline_input_a = "cat < /var/log/kernel.log | grep zig | sort | uniq > /tmp/out.txt";
const pipeline_input_b = "cat < /var/log/serial.log | grep tcp | sort | uniq > /tmp/tcp.txt";

const glob_patterns = [_][]const u8{
    "*.zig",
    "src/kernel/shell/*.zig",
    "src/*/tests/test_*.zig",
    "user/bin/??",
    "kernel-*.elf",
    "*.log",
};

const glob_candidates = [_][]const u8{
    "src/kernel/shell/parser.zig",
    "src/kernel/tests/test_memory.zig",
    "src/kernel/tests/test_tcp_reliability.zig",
    "user/bin/ls",
    "user/bin/cp",
    "user/bin/echo",
    "kernel-ci-smoke.elf",
    "serial.log",
};

const at_cases = [_]struct {
    root: []const u8,
    cwd: []const u8,
    dir_path: ?[]const u8,
    path: []const u8,
}{
    .{ .root = "/srv/jail", .cwd = "/usr/bin", .dir_path = null, .path = "../share/man" },
    .{ .root = "/srv/jail", .cwd = "/var/log", .dir_path = "/srv/jail/etc/init.d", .path = "./rc" },
    .{ .root = "/srv/jail", .cwd = "/home/user", .dir_path = "/srv/jail/tmp/cache", .path = "../../var/tmp/out.log" },
    .{ .root = "/srv/jail", .cwd = "/", .dir_path = "/srv/jail/usr/lib", .path = "/etc/hosts" },
};

const tcp_ipv4_src: u32 = 0x0a00020f;
const tcp_ipv4_dst: u32 = 0x0a00020a;
const tcp_ipv6_src = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const tcp_ipv6_dst = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

const sem_ops = [_]ipc.Sembuf{
    .{ .sem_num = 0, .sem_op = 3, .sem_flg = 0 },
    .{ .sem_num = 1, .sem_op = 2, .sem_flg = 0 },
    .{ .sem_num = 0, .sem_op = -1, .sem_flg = 0 },
    .{ .sem_num = 1, .sem_op = -1, .sem_flg = 0 },
    .{ .sem_num = 2, .sem_op = 1, .sem_flg = 0 },
    .{ .sem_num = 3, .sem_op = 0, .sem_flg = 0 },
};

const benchmarks = [_]Benchmark{
    .{ .name = "shell.tokenize.expansions", .iterations = 50_000, .run = benchShellTokenizeExpansions },
    .{ .name = "shell.pipeline.commandline", .iterations = 8_000, .run = benchShellPipelineCommandline },
    .{ .name = "shell.glob.match_matrix", .iterations = 10_000, .run = benchShellGlobMatchMatrix },
    .{ .name = "syscall.at.resolve_matrix", .iterations = 30_000, .run = benchSyscallAtResolveMatrix },
    .{ .name = "vfs.fd.freelist_churn", .iterations = 120_000, .run = benchVfsFdFreelistChurn },
    .{ .name = "tcp.checksum.dual_stack", .iterations = 60_000, .run = benchTcpChecksumDualStack },
    .{ .name = "tcp.options.roundtrip", .iterations = 150_000, .run = benchTcpOptionsRoundtrip },
    .{ .name = "ipc.semops.batch", .iterations = 150_000, .run = benchIpcSemOpsBatch },
};

const BenchHooks = struct {
    fn getVar(_: ?*anyopaque, name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "USER")) return "root";
        if (std.mem.eql(u8, name, "GLOB")) return "*.zig";
        if (std.mem.eql(u8, name, "ALTGLOB")) return "*.txt";
        return null;
    }

    fn captureCommand(_: ?*anyopaque, line: []const u8, output: []u8) parser.CommandCaptureError!usize {
        if (std.mem.eql(u8, line, "printf hi")) {
            @memcpy(output[0..2], "hi");
            return 2;
        }
        if (std.mem.eql(u8, line, "printf ok")) {
            @memcpy(output[0..2], "ok");
            return 2;
        }
        return error.CommandFailed;
    }
};

const expansion_hooks = parser.ExpansionHooks{
    .getVarFn = BenchHooks.getVar,
    .captureCommandFn = BenchHooks.captureCommand,
};

const TcpBenchConn = struct {
    mss: u16 = tcp.MSS,
    window_scale_send: u8 = 0,
    window_scale_recv: u8 = 0,
    sack_permitted: bool = false,
    sack_blocks: [4]tcp.SACKBlock = [_]tcp.SACKBlock{.{ .left_edge = 0, .right_edge = 0 }} ** 4,
    ts_enabled: bool = true,
    ts_val: u32 = 0,
    ts_ecr: u32 = 0,
    ts_recent: u32 = 0,
};

pub fn run() bool {
    printMarker("BENCH:START");

    const suite_start_cycles = x86.rdtsc();

    var completed: usize = 0;
    for (benchmarks) |benchmark| {
        const warmup_iterations = @max(@as(usize, 64), benchmark.iterations / 10);
        _ = @call(.never_inline, benchmark.run, .{warmup_iterations}) catch |err| {
            printFailure(benchmark.name, err);
            return false;
        };

        const start_cycles = x86.rdtsc();
        const checksum = @call(.never_inline, benchmark.run, .{benchmark.iterations}) catch |err| {
            printFailure(benchmark.name, err);
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
    const ratio = formatRatioFixed2(&ratio_buf, cycles, benchmark.iterations);

    var line_buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &line_buf,
        "BENCH:RESULT:{s}:iterations={d}:cycles={d}:cycles_per_op={s}:checksum={d}\n",
        .{ benchmark.name, benchmark.iterations, cycles, ratio, checksum },
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

fn makeTcpPayload() [1460]u8 {
    var payload: [1460]u8 = undefined;
    for (&payload, 0..) |*byte, idx| {
        byte.* = @intCast((idx * 31 + 17) % 251);
    }
    return payload;
}

fn makeTcpHeader() tcp.Header {
    var header = tcp.Header{
        .src_port = 8080,
        .dst_port = 443,
        .seq_num = 0,
        .ack_num = 0x01020304,
        .data_offset_and_flags = 0,
        .window_size = 4096,
        .checksum = 0,
        .urgent_ptr = 0,
    };
    header.setDataOffsetAndFlags(@intCast(@sizeOf(tcp.Header)), tcp.Flags.ACK | tcp.Flags.PSH);
    return header;
}

fn makeTcpConn(seed: u32) TcpBenchConn {
    return .{
        .mss = tcp.MSS,
        .window_scale_send = @intCast((seed % 8) + 1),
        .window_scale_recv = 0,
        .sack_permitted = false,
        .sack_blocks = [_]tcp.SACKBlock{.{ .left_edge = 0, .right_edge = 0 }} ** 4,
        .ts_enabled = true,
        .ts_val = 0x10000000 +% seed,
        .ts_ecr = 0x01020300 +% seed,
        .ts_recent = 0,
    };
}

fn makeSemSet() ipc.SemSet {
    return .{
        .key = 1,
        .sems = [_]ipc.Semaphore{.{ .value = 0 }} ** ipc.MAX_SEMAPHORES,
        .nsems = 4,
        .mode = 0,
        .in_use = true,
    };
}

fn benchShellTokenizeExpansions(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const input = if ((sink & 1) == 0) tokenize_input_a else tokenize_input_b;
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
        const input = if ((sink & 1) == 0) pipeline_input_a else pipeline_input_b;
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
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        for (glob_patterns, 0..) |pattern, pattern_idx| {
            var candidate_idx = pattern_idx + offset;
            var count: usize = 0;
            while (count < glob_candidates.len) : (count += 1) {
                const candidate = glob_candidates[candidate_idx % glob_candidates.len];
                if (shell_glob.wildcardMatch(pattern, candidate)) sink +%= 1;
                candidate_idx += 1;
            }
        }
        offset = (offset + 1 + @as(usize, @intCast(sink & 3))) % glob_candidates.len;
    }
    std.mem.doNotOptimizeAway(&sink);
    return sink;
}

fn benchSyscallAtResolveMatrix(iterations: usize) BenchmarkError!u64 {
    var sink: u64 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        for (at_cases) |case| {
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
    var payload = makeTcpPayload();
    var header = makeTcpHeader();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        header.seq_num +%= @intCast(i + 1);
        const payload_idx = (@as(usize, @intCast(header.seq_num)) + @as(usize, @intCast(sink & 0xff))) % payload.len;
        payload[payload_idx] +%= @truncate(header.seq_num);

        sink +%= tcp.calculateChecksumIPv4(tcp_ipv4_src, tcp_ipv4_dst, &header, payload[0..]);
        sink +%= tcp.calculateChecksumIPv6(&tcp_ipv6_src, &tcp_ipv6_dst, &header, payload[0..]);
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
        var conn = makeTcpConn(@intCast(i + @as(usize, @intCast(sink & 0xffff))));
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
        var set = makeSemSet();
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
