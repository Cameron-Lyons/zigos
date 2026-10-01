const std = @import("std");
const graphics = @import("text_scanout");
const scanout = graphics.scanout;

const WIDTH = 1280;
const HEIGHT = 720;
const Workload = enum { full_redraw, single_cell, pool_only };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const check_damage = args.len == 2 and std.mem.eql(u8, args[1], "--check-damage");
    if (args.len > 2 or (args.len == 2 and !check_damage)) return error.InvalidArguments;
    const pixels = try init.gpa.alloc(u32, WIDTH * HEIGHT);
    defer init.gpa.free(pixels);
    const info = graphics.framebuffer.Info{
        .physical_address = 0x9000_0000,
        .width = WIDTH,
        .height = HEIGHT,
        .pixels_per_scan_line = WIDTH,
        .format = .bgrx8888,
        .buffer_bytes = WIDTH * HEIGHT * 4,
    };
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("Text scanout host benchmark: {d}x{d}, normal RAM backing (device write latency excluded)\n", .{ WIDTH, HEIGHT });
    inline for (comptime std.meta.tags(Workload)) |workload| {
        const iterations: usize = if (workload == .full_redraw) 300 else 30_000;
        var samples: [5]u64 = undefined;
        var checksum: u64 = 0;
        var pixels_per_iteration: usize = 0;
        for (&samples) |*sample| {
            var renderer = try scanout.Renderer.init(info, pixels);
            var frame = try scanout.Frame.init(renderer.columns, renderer.rows);
            if (workload != .pool_only) @memset(frame.cells[0 .. frame.columns * frame.rows], .{ .character = 'A' });
            _ = try iteration(workload, &renderer, &frame, false);
            for (0..100) |index| _ = try iteration(workload, &renderer, &frame, index % 2 == 0);
            const start = std.Io.Clock.awake.now(init.io);
            for (0..iterations) |index| {
                const stats = try iteration(workload, &renderer, &frame, index % 2 == 0);
                if (check_damage) {
                    const expected_cells: usize = switch (workload) {
                        .full_redraw => frame.columns * frame.rows,
                        .single_cell => 1,
                        .pool_only => 0,
                    };
                    if (stats.changed_cells != expected_cells or stats.pixels_written != expected_cells * scanout.CELL_WIDTH * scanout.CELL_HEIGHT)
                        return error.UnexpectedDamage;
                }
                pixels_per_iteration = stats.pixels_written;
                checksum +%= stats.changed_cells + stats.pixels_written;
            }
            sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
        }
        std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
        const elapsed = @as(f64, @floatFromInt(samples[2])) / @as(f64, @floatFromInt(iterations));
        try output.interface.print("{s}: {d:.2} ns/iteration (median of 5, {d} iterations/sample), pixels_written={d}, checksum={d}\n", .{
            @tagName(workload), elapsed, iterations, pixels_per_iteration, checksum,
        });
    }
    try output.interface.flush();
}

fn iteration(comptime workload: Workload, renderer: *scanout.Renderer, frame: *scanout.Frame, alternate: bool) !scanout.PresentStats {
    switch (workload) {
        .full_redraw => @memset(frame.cells[0 .. frame.columns * frame.rows], .{ .character = if (alternate) @as(u21, 'A') else 'B' }),
        .single_cell => frame.cells[0].character = if (alternate) @as(u21, 'A') else 'B',
        .pool_only => {
            // Reorder the pool without changing any glyph, cursor, or style.
            frame.cluster_length = 0;
            if (alternate) {
                frame.put(0, 0, "e\u{301}", .body);
                frame.put(5, 0, "界\u{301}", .accent);
            } else {
                frame.put(5, 0, "界\u{301}", .accent);
                frame.put(0, 0, "e\u{301}", .body);
            }
        },
    }
    std.mem.doNotOptimizeAway(frame);
    const stats = try renderer.present(frame);
    std.mem.doNotOptimizeAway(renderer);
    return stats;
}
