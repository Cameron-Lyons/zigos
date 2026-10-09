const std = @import("std");
const preflight = @import("response_preflight");

const ITERATIONS = 500_000;
const Workload = enum { load_segment_1, load_segment_4, load_segment_8, terminal_stack };
const Strategy = enum { previous, current };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Response preflight ({s}, {s}): previous full-span+prefix validation versus current full-span validation; page preparation excluded equally on the host\n", .{
        @tagName(@import("builtin").target.cpu.arch), @import("builtin").target.cpu.model.name,
    });
    inline for (comptime std.meta.tags(Workload)) |workload| {
        var space = std.mem.zeroes(preflight.AddressSpaceRecord);
        const regions = switch (workload) {
            .load_segment_1 => 1,
            .load_segment_4 => 4,
            .load_segment_8 => 8,
            .terminal_stack => 9,
        };
        space.region_count = regions;
        space.owner_task_id = 42;
        for (space.regions[0..regions], 0..) |*region, index| {
            region.* = .{
                .kind = if (workload == .terminal_stack and index == regions - 1) .stack else .load_segment,
                .virtual_address = 0x20000 + index * 0x1000,
                .size_bytes = 0x1000,
                .file_offset = 0,
                .file_size = 0,
                .access = .{ .read = true, .write = true },
            };
        }
        const memory = preflight.UserMemoryContext{ .address_space = &space, .caller_task_id = space.owner_task_id };
        const address = 0x20000 + (regions - 1) * 0x1000 + 16;
        var spans = [_]usize{ 32, 64 };
        for (spans[0..]) |declared| {
            try compareStatus(memory, address, declared, 32);
            try compareStatus(memory, address, 31, 32);
            try compareStatus(memory, 0x1000, declared, 32);
            try compareStatus(memory, std.math.maxInt(usize) - 15, declared, 32);
            try compareStatus(memory, address, declared, 0);
            var samples: [2][7]u64 = undefined;
            var checksums: [2]u64 = @splat(0);
            for (0..7) |sample| {
                if (sample % 2 == 0) {
                    samples[0][sample] = try measure(.previous, init.io, memory, address, declared, &checksums[0]);
                    samples[1][sample] = try measure(.current, init.io, memory, address, declared, &checksums[1]);
                } else {
                    samples[1][sample] = try measure(.current, init.io, memory, address, declared, &checksums[1]);
                    samples[0][sample] = try measure(.previous, init.io, memory, address, declared, &checksums[0]);
                }
            }
            if (checksums[0] != checksums[1] or checksums[0] != ITERATIONS * 7) return error.ChecksumMismatch;
            inline for (comptime std.meta.tags(Strategy)) |strategy| {
                const index = @backingInt(strategy);
                std.mem.sort(u64, &samples[index], {}, std.sort.asc(u64));
                try output.interface.print("{s}, {d}-byte span, {s}: {d:.2} ns/preflight (median of 7), checksum={d}\n", .{
                    @tagName(workload), declared, @tagName(strategy), @as(f64, @floatFromInt(samples[index][3])) / ITERATIONS, checksums[index],
                });
            }
        }
        std.mem.doNotOptimizeAway(&spans);
    }
    try output.interface.flush();
}

// Reproduce the previous public-path checks in the same executable and with
// the same current permission validator and page preparation implementation.
fn previousPreflight(memory: preflight.UserMemoryContext, address: usize, declared: usize, required: usize) ?preflight.DispatchResult {
    if (required == 0) return null;
    if (declared < required) return .{ .status = .buffer_too_small };
    if (!preflight.validateUserRange(memory, address, declared, 1, .write)) return .{ .status = .invalid_response_buffer };
    if (!preflight.prepareUserRange(memory, address, required, 1, .write)) return .{ .status = .invalid_response_buffer };
    return null;
}

fn compareStatus(memory: preflight.UserMemoryContext, address: usize, declared: usize, required: usize) !void {
    const expected = previousPreflight(memory, address, declared, required);
    const actual = preflight.preflightResponse(memory, address, declared, required);
    if (expected) |failure| {
        const current = actual orelse return error.StatusMismatch;
        if (failure.status != current.status) return error.StatusMismatch;
    } else if (actual != null) return error.StatusMismatch;
}

fn measure(comptime strategy: Strategy, io: std.Io, memory: preflight.UserMemoryContext, address: usize, declared: usize, checksum: *u64) !u64 {
    for (0..1000) |_| _ = try iteration(strategy, memory, address, declared, 32);
    const start = std.Io.Clock.awake.now(io);
    for (0..ITERATIONS) |_| checksum.* +%= try iteration(strategy, memory, address, declared, 32);
    return @intCast(start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds());
}

noinline fn iteration(comptime strategy: Strategy, memory: preflight.UserMemoryContext, address: usize, declared: usize, required: usize) !u64 {
    std.mem.doNotOptimizeAway(memory);
    // Keep call-site outlining heuristics equal while comparing the actual
    // admission bodies rather than the optional-result ABI's copying cost.
    const failure = if (strategy == .previous)
        @call(.always_inline, previousPreflight, .{ memory, address, declared, required })
    else
        @call(.always_inline, preflight.preflightResponse, .{ memory, address, declared, required });
    if (failure != null) return error.UnexpectedResponseDenial;
    return 1;
}
