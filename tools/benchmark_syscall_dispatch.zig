const std = @import("std");
const builtin = @import("builtin");
const benchmark = @import("syscall_dispatch_benchmark");
const SAMPLES = 7;
const WARMUP_ITERATIONS = 1000;
const ExecutionMode = enum { native, translated, unspecified };

const Sample = struct { nanoseconds: u64, checksum: u64 };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var iterations: usize = 100_000;
    var mode: ExecutionMode = .unspecified;
    var fixed_seed: ?u64 = null;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--execution-mode=")) {
            mode = std.meta.stringToEnum(ExecutionMode, arg["--execution-mode=".len..]) orelse return error.InvalidExecutionMode;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            iterations = try std.fmt.parseInt(usize, arg["--iterations=".len..], 10);
            if (iterations < 1000 or iterations > 1_000_000) return error.InvalidIterationCount;
        } else if (std.mem.startsWith(u8, arg, "--seed=")) {
            fixed_seed = try std.fmt.parseInt(u64, arg["--seed=".len..], 0);
        } else return error.InvalidArguments;
    }
    var output_buffer: [8192]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Hosted successful syscall dispatch: arch={s} cpu={s} os={s} optimize={s} execution={s} ABI={d}\n", .{
        @tagName(builtin.target.cpu.arch), builtin.target.cpu.model.name, @tagName(builtin.target.os.tag), @tagName(builtin.mode), @tagName(mode), @import("syscall_dispatch_benchmark").abiVersion(),
    });
    try output.interface.print("Actual Surface/Kernel authorization and host user-memory metadata/copy; excludes privilege entry/exit, native physical/demand copy, FRED/CET, compacted xstate and broker waits. Timings include loop, runtime input selection, successful scalar checks, representative response checksums and full-output memory barriers. Full wire/payload checks occur outside clocks. endpoint_pair_* also includes bounded source payload generation. endpoint_prefilled_pair_* uses untimed stable source payload initialization and two timed receive-edge canaries, with the same actual Surface send/receive copies and timed checks/barriers. Capability lifecycles mint fresh runtime-selected object targets, optionally MOVE to a distinct task, then authenticate public self-revocation; no trusted cleanup is timed. Shared-memory pairs perform fresh map/unmap metadata mutations with response canaries; they exclude native page-table and demand-mapping registration. Each shared-memory strategy/sample uses a fresh fixture outside clocks and at most 50000 timed iterations to preserve the ordinary bounded virtual cursor; reported counts are actual.\n", .{});
    try output.interface.flush();
    inline for (comptime std.meta.tags(benchmark.Workload)) |workload| {
        const fixture = try benchmark.Fixture.create(init.gpa, workload);
        defer fixture.destroy();
        var seed = fixed_seed orelse fixture.opaqueSeed();
        std.mem.doNotOptimizeAway(&seed);
        try fixture.verify(workload, seed);
        const sample_iterations = workload.iterationsPerSample(iterations);
        var samples: [2][SAMPLES]Sample = undefined;
        for (0..SAMPLES) |index| {
            const sample_seed = benchmark.inputFor(seed, index * sample_iterations);
            if (index % 2 == 0) {
                samples[0][index] = try measure(.compact, workload, init.io, init.gpa, fixture, sample_seed, sample_iterations);
                samples[1][index] = try measure(.explicit_detailed, workload, init.io, init.gpa, fixture, sample_seed, sample_iterations);
            } else {
                samples[1][index] = try measure(.explicit_detailed, workload, init.io, init.gpa, fixture, sample_seed, sample_iterations);
                samples[0][index] = try measure(.compact, workload, init.io, init.gpa, fixture, sample_seed, sample_iterations);
            }
            if (samples[0][index].checksum != samples[1][index].checksum) return error.ChecksumMismatch;
        }
        const calls = sample_iterations * workload.dispatchesPerIteration();
        try output.interface.print("workload={s} iterations/sample={d} dispatches/sample={d} samples={d} seed={x}\n", .{ @tagName(workload), sample_iterations, calls, SAMPLES, seed });
        inline for (comptime std.meta.tags(benchmark.Strategy)) |strategy| {
            const which = @backingInt(strategy);
            var elapsed: [SAMPLES]u64 = undefined;
            var total_checksum: u64 = 0;
            for (samples[which], 0..) |sample, index| {
                elapsed[index] = sample.nanoseconds;
                total_checksum +%= sample.checksum;
                try output.interface.print("sample workload={s} strategy={s} index={d} order={s} ns={d} dispatches={d} checksum={x}\n", .{
                    @tagName(workload), @tagName(strategy), index, if ((index % 2 == 0) == (strategy == .compact)) "first" else "second", sample.nanoseconds, calls, sample.checksum,
                });
            }
            std.mem.sort(u64, &elapsed, {}, std.sort.asc(u64));
            const ns_per_dispatch = @as(f64, @floatFromInt(elapsed[SAMPLES / 2])) / @as(f64, @floatFromInt(calls));
            try output.interface.print("median workload={s} strategy={s} ns/dispatch={d:.2} min_ns={d} median_ns={d} max_ns={d} total_dispatches={d} checksum={x}", .{
                @tagName(workload), @tagName(strategy), ns_per_dispatch, elapsed[0], elapsed[SAMPLES / 2], elapsed[SAMPLES - 1], calls * SAMPLES, total_checksum,
            });
            if (workload.payloadBytes() != null) try output.interface.print(" ns/send_recv_pair={d:.2} (two dispatches; mean cost, not separate send/receive latency)", .{@as(f64, @floatFromInt(elapsed[SAMPLES / 2])) / @as(f64, @floatFromInt(sample_iterations))});
            if (workload.payloadBytes() == null and workload.dispatchesPerIteration() > 1) try output.interface.print(" ns/operation_cycle={d:.2} ({d} dispatches; mean cost, not separate operation latency)", .{ @as(f64, @floatFromInt(elapsed[SAMPLES / 2])) / @as(f64, @floatFromInt(sample_iterations)), workload.dispatchesPerIteration() });
            try output.interface.print("\n", .{});
        }
        try fixture.checkStable(workload);
        try output.interface.flush();
    }
}

fn measure(comptime strategy: benchmark.Strategy, comptime workload: benchmark.Workload, io: std.Io, allocator: std.mem.Allocator, fixture: *benchmark.Fixture, seed: u64, iterations: usize) !Sample {
    if (workload == .shared_memory_map_unmap_pair) {
        const fresh = try benchmark.Fixture.create(allocator, workload);
        defer fresh.destroy();
        try fresh.verify(workload, seed);
        return measureFixture(strategy, workload, io, fresh, seed, iterations);
    }
    return measureFixture(strategy, workload, io, fixture, seed, iterations);
}

fn measureFixture(comptime strategy: benchmark.Strategy, comptime workload: benchmark.Workload, io: std.Io, fixture: *benchmark.Fixture, seed: u64, iterations: usize) !Sample {
    for (0..WARMUP_ITERATIONS) |index| _ = try fixture.iteration(workload, strategy, benchmark.inputFor(seed, index));
    try fixture.verifyAfterSample(workload, strategy, seed);
    var checksum: u64 = 0;
    const start = std.Io.Clock.awake.now(io);
    for (0..iterations) |index| checksum +%= try fixture.iteration(workload, strategy, benchmark.inputFor(seed, index));
    const elapsed = start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds();
    try fixture.verifyAfterSample(workload, strategy, benchmark.inputFor(seed, iterations - 1));
    return .{ .nanoseconds = @intCast(elapsed), .checksum = checksum };
}
