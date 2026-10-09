const std = @import("std");
const checksum = @import("volume_checksum");

const samples_per_case = 5;
const bytes_per_sample = 32 * 1024 * 1024;
const checkpoint_bytes = 95 * 4096;
const Algorithm = enum { previous_fnv1a, xxh64 };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    const storage = try init.gpa.alloc(u8, checkpoint_bytes);
    defer init.gpa.free(storage);
    for (storage, 0..) |*byte, index| byte.* = @truncate(index * 17 + index / 13);
    try output.interface.print("Storage checksum host benchmark ({s}, {s}): same-build previous FNV-1a versus root-v6 XXH64; median of five samples\n", .{
        @tagName(@import("builtin").target.cpu.arch), @import("builtin").target.cpu.model.name,
    });
    for ([_]usize{ 128, 4096, checkpoint_bytes }) |length| {
        const bytes = storage[0..length];
        const iterations = @max(100, bytes_per_sample / length);
        inline for (comptime std.meta.tags(Algorithm)) |algorithm| {
            const expected = hash(algorithm, bytes);
            var samples: [samples_per_case]u64 = undefined;
            var result: u64 = 0;
            for (&samples) |*sample| {
                for (0..16) |_| {
                    std.mem.doNotOptimizeAway(bytes);
                    if (hash(algorithm, bytes) != expected) return error.IncorrectChecksum;
                }
                const start = std.Io.Clock.awake.now(init.io);
                for (0..iterations) |_| {
                    std.mem.doNotOptimizeAway(bytes);
                    result +%= hash(algorithm, bytes);
                }
                sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
            }
            if (result != expected *% (samples_per_case * iterations)) return error.IncorrectChecksum;
            std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
            try output.interface.print("{d} bytes, {s}: {d:.2} ns/hash; checksum={x}\n", .{
                length,                                                                                       @tagName(algorithm),
                @as(f64, @floatFromInt(samples[samples_per_case / 2])) / @as(f64, @floatFromInt(iterations)), result,
            });
            try output.interface.flush();
        }
    }
}

fn hash(comptime algorithm: Algorithm, bytes: []const u8) u64 {
    if (algorithm == .xxh64) return checksum.checksumBytes(bytes);
    // Comparison only: production accepts exactly the root-v6 checksum.
    var value: u64 = 14695981039346656037;
    for (bytes) |byte| value = (value ^ byte) *% 1099511628211;
    return value;
}
