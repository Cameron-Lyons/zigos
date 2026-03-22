const std = @import("std");

pub const BenchmarkMetadata = struct {
    name: []const u8,
    description: []const u8,
    default_iterations: usize,
    bytes_per_iteration: usize = 0,
};

pub const AtCase = struct {
    root: []const u8,
    cwd: []const u8,
    dir_path: ?[]const u8,
    path: []const u8,
};

pub const tokenize_input_a = "echo \"$USER\" $(printf hi) '*.txt' $GLOB /var/log/zigos/*.log";
pub const tokenize_input_b = "echo \"$USER\" $(printf ok) '*.cfg' $ALTGLOB /var/log/zigos/*.txt";
pub const pipeline_input_a = "cat < /var/log/kernel.log | grep zig | sort | uniq > /tmp/out.txt";
pub const pipeline_input_b = "cat < /var/log/serial.log | grep tcp | sort | uniq > /tmp/tcp.txt";

pub const glob_patterns = [_][]const u8{
    "*.zig",
    "src/kernel/shell/*.zig",
    "src/*/tests/test_*.zig",
    "user/bin/*/*.zig",
    "kernel-*.elf",
    "*.log",
};

pub const glob_candidates = [_][]const u8{
    "src/kernel/shell/parser/pipeline.zig",
    "src/kernel/tests/test_memory.zig",
    "src/kernel/tests/test_tcp_reliability.zig",
    "user/bin/fs/ls.zig",
    "user/bin/fs/cp.zig",
    "user/bin/core/echo.zig",
    "kernel-ci-smoke.elf",
    "serial.log",
};

pub const at_cases = [_]AtCase{
    .{ .root = "/srv/jail", .cwd = "/usr/bin", .dir_path = null, .path = "../share/man" },
    .{ .root = "/srv/jail", .cwd = "/var/log", .dir_path = "/srv/jail/etc/init.d", .path = "./rc" },
    .{ .root = "/srv/jail", .cwd = "/home/user", .dir_path = "/srv/jail/tmp/cache", .path = "../../var/tmp/out.log" },
    .{ .root = "/srv/jail", .cwd = "/", .dir_path = "/srv/jail/usr/lib", .path = "/etc/hosts" },
};

pub const tcp_payload_len: usize = 1460;
pub const tcp_bench_src_port: u16 = 8080;
pub const tcp_bench_dst_port: u16 = 443;
pub const tcp_bench_ack_num: u32 = 0x01020304;
pub const tcp_bench_window_size: u16 = 4096;
pub const tcp_ipv4_src: u32 = 0x0a00020f;
pub const tcp_ipv4_dst: u32 = 0x0a00020a;
pub const tcp_ipv6_src = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const tcp_ipv6_dst = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

pub const shell_tokenize_expansions = BenchmarkMetadata{
    .name = "shell.tokenize.expansions",
    .description = "tokenize quoted command lines with env and command substitutions",
    .default_iterations = 50_000,
    .bytes_per_iteration = tokenize_input_a.len,
};

pub const shell_pipeline_commandline = BenchmarkMetadata{
    .name = "shell.pipeline.commandline",
    .description = "tokenize and parse multi-stage shell pipelines",
    .default_iterations = 8_000,
    .bytes_per_iteration = pipeline_input_a.len,
};

pub const shell_glob_compile_matrix = BenchmarkMetadata{
    .name = "shell.glob.compile_matrix",
    .description = "compile realistic shell globs into reusable matcher state",
    .default_iterations = 40_000,
    .bytes_per_iteration = globPatternBytes(),
};

pub const shell_glob_match_matrix = BenchmarkMetadata{
    .name = "shell.glob.match_matrix",
    .description = "match cached shell globs against a rotating file matrix",
    .default_iterations = 10_000,
    .bytes_per_iteration = globMatchWorkloadBytes(),
};

pub const shell_user_spawn_wait = BenchmarkMetadata{
    .name = "shell.user.spawn_wait",
    .description = "spawn a tiny user program and wait for it to exit",
    .default_iterations = 128,
    .bytes_per_iteration = "/bin/true".len,
};

pub const syscall_at_resolve_matrix = BenchmarkMetadata{
    .name = "syscall.at.resolve_matrix",
    .description = "resolve cwd and dirfd-relative paths inside chroot roots",
    .default_iterations = 30_000,
    .bytes_per_iteration = atWorkloadBytes(),
};

pub const vfs_fd_freelist_churn = BenchmarkMetadata{
    .name = "vfs.fd.freelist_churn",
    .description = "allocate reserve and recycle VFS descriptor slots",
    .default_iterations = 120_000,
};

pub fn tcpChecksumDualStack(tcp_header_size: usize) BenchmarkMetadata {
    return .{
        .name = "tcp.checksum.dual_stack",
        .description = "calculate IPv4 and IPv6 TCP checksums over MTU-sized payloads",
        .default_iterations = 60_000,
        .bytes_per_iteration = 2 * (tcp_header_size + tcp_payload_len),
    };
}

pub const tcp_options_roundtrip = BenchmarkMetadata{
    .name = "tcp.options.roundtrip",
    .description = "build and parse SYN plus timestamp TCP options",
    .default_iterations = 150_000,
    .bytes_per_iteration = 48,
};

pub const ipc_semops_batch = BenchmarkMetadata{
    .name = "ipc.semops.batch",
    .description = "apply mixed semaphore operations across a small semset",
    .default_iterations = 150_000,
};

pub fn globPatternBytes() usize {
    var total: usize = 0;
    for (glob_patterns) |pattern| {
        total += pattern.len;
    }
    return total;
}

pub fn globMatchWorkloadBytes() usize {
    var total: usize = 0;
    for (glob_patterns) |pattern| {
        for (glob_candidates) |candidate| {
            total += pattern.len + candidate.len;
        }
    }
    return total;
}

pub fn atWorkloadBytes() usize {
    var total: usize = 0;
    for (at_cases) |case| {
        total += case.root.len + case.cwd.len + case.path.len;
        if (case.dir_path) |dir_path| {
            total += dir_path.len;
        }
    }
    return total;
}

pub fn getVar(_: ?*anyopaque, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "USER")) return "root";
    if (std.mem.eql(u8, name, "GLOB")) return "*.zig";
    if (std.mem.eql(u8, name, "ALTGLOB")) return "*.txt";
    return null;
}

pub fn makeExpansionHooks(comptime Parser: type) Parser.ExpansionHooks {
    return .{
        .getVarFn = getVar,
        .captureCommandFn = struct {
            fn capture(_: ?*anyopaque, line: []const u8, output: []u8) Parser.CommandCaptureError!usize {
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
        }.capture,
    };
}

pub fn makeTcpPayload() [tcp_payload_len]u8 {
    var payload: [tcp_payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, idx| {
        byte.* = @intCast((idx * 31 + 17) % 251);
    }
    return payload;
}

pub fn makeTcpHeader(comptime Tcp: type) Tcp.Header {
    var header = Tcp.Header{
        .src_port = tcp_bench_src_port,
        .dst_port = tcp_bench_dst_port,
        .seq_num = 0,
        .ack_num = tcp_bench_ack_num,
        .data_offset_and_flags = 0,
        .window_size = tcp_bench_window_size,
        .checksum = 0,
        .urgent_ptr = 0,
    };
    header.setDataOffsetAndFlags(@intCast(@sizeOf(Tcp.Header)), Tcp.Flags.ACK | Tcp.Flags.PSH);
    return header;
}

pub fn TcpBenchConn(comptime Tcp: type) type {
    return struct {
        mss: u16 = Tcp.MSS,
        window_scale_send: u8 = 0,
        window_scale_recv: u8 = 0,
        sack_permitted: bool = false,
        sack_blocks: [4]Tcp.SACKBlock = [_]Tcp.SACKBlock{.{ .left_edge = 0, .right_edge = 0 }} ** 4,
        ts_enabled: bool = true,
        ts_val: u32 = 0,
        ts_ecr: u32 = 0,
        ts_recent: u32 = 0,
    };
}

pub fn makeTcpConn(comptime Tcp: type, seed: u32) TcpBenchConn(Tcp) {
    return .{
        .mss = Tcp.MSS,
        .window_scale_send = @intCast((seed % 8) + 1),
        .window_scale_recv = 0,
        .sack_permitted = false,
        .sack_blocks = [_]Tcp.SACKBlock{.{ .left_edge = 0, .right_edge = 0 }} ** 4,
        .ts_enabled = true,
        .ts_val = 0x10000000 +% seed,
        .ts_ecr = 0x01020300 +% seed,
        .ts_recent = 0,
    };
}

pub fn makeSemOps(comptime Ipc: type) [6]Ipc.Sembuf {
    return .{
        .{ .sem_num = 0, .sem_op = 3, .sem_flg = 0 },
        .{ .sem_num = 1, .sem_op = 2, .sem_flg = 0 },
        .{ .sem_num = 0, .sem_op = -1, .sem_flg = 0 },
        .{ .sem_num = 1, .sem_op = -1, .sem_flg = 0 },
        .{ .sem_num = 2, .sem_op = 1, .sem_flg = 0 },
        .{ .sem_num = 3, .sem_op = 0, .sem_flg = 0 },
    };
}

pub fn makeSemSet(comptime Ipc: type) Ipc.SemSet {
    return .{
        .key = 1,
        .sems = [_]Ipc.Semaphore{.{ .value = 0 }} ** Ipc.MAX_SEMAPHORES,
        .nsems = 4,
        .mode = 0,
        .in_use = true,
    };
}
