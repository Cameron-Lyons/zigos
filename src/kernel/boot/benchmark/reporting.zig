const std = @import("std");
const console = @import("../../utils/console.zig");

const BENCH_RESULT_LINE_BUFFER_BYTES: usize = 256;
const BENCH_QUALITY_LINE_BUFFER_BYTES: usize = 160;
const BENCH_QUALITY_SUMMARY_BUFFER_BYTES: usize = 96;
const BENCH_SUMMARY_LINE_BUFFER_BYTES: usize = 128;

pub fn emitResult(name: []const u8, iterations: u32, cycles: u64, checksum: u64) void {
    const scaled_cycles_per_op = if (iterations == 0)
        0
    else
        @divTrunc(cycles * 100, iterations);
    const whole = @divTrunc(scaled_cycles_per_op, 100);
    const frac = @mod(scaled_cycles_per_op, 100);

    var buffer: [BENCH_RESULT_LINE_BUFFER_BYTES]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "BENCH:RESULT:{s}:iterations={d}:cycles={d}:cycles_per_op={d}.{d:0>2}:checksum={d}\n",
        .{ name, iterations, cycles, whole, frac, checksum },
    ) catch |err| benchStepFailure("benchmark reporting", err);
    console.print(line);
}

pub fn emitQualityGate(name: []const u8, value: u64, cycles: u64) void {
    var buffer: [BENCH_QUALITY_LINE_BUFFER_BYTES]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "BENCH:QUALITY:{s}:value={d}:cycles={d}\n",
        .{ name, value, cycles },
    ) catch |err| benchStepFailure("benchmark reporting", err);
    console.print(line);
}

pub fn emitQualitySummary(gate_count: usize, total_cycles: u64) void {
    var buffer: [BENCH_QUALITY_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "BENCH:QUALITY_SUMMARY:gates={d}:total_cycles={d}\n",
        .{ gate_count, total_cycles },
    ) catch |err| benchStepFailure("benchmark reporting", err);
    console.print(line);
}

pub fn emitSummary(benchmark_count: usize, quality_gate_count: usize, quality_cycles: u64, total_cycles: u64) void {
    var buffer: [BENCH_SUMMARY_LINE_BUFFER_BYTES]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "BENCH:SUMMARY:benchmarks={d}:quality_gates={d}:quality_cycles={d}:total_cycles={d}\n",
        .{ benchmark_count, quality_gate_count, quality_cycles, total_cycles },
    ) catch |err| benchStepFailure("benchmark reporting", err);
    console.print(line);
}

// Benchmark harness steps must not fail silently: in ReleaseFast a
// `catch |err| benchStepFailure("benchmark reporting", err)` on a fallible fixture or measurement step is
// undefined behavior, and the run limps on to publish numbers and
// checksums computed from garbage state. Failing loudly at the step keeps
// the gated measurements trustworthy.
pub fn benchStepFailure(comptime step: []const u8, err: anyerror) noreturn {
    std.debug.panic("benchmark step failed: {s}: {s}", .{ step, @errorName(err) });
}
