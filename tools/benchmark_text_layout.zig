const std = @import("std");
const text_layout = @import("text_layout").layout;

const DOCUMENT_BYTES = 512;
const COLUMNS = 40;
const VISIBLE_ROWS = 6;
const ITERATIONS = 20_000;
const Position = enum { head, middle, end };
const Method = enum { rescan, single_pass };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [2048]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    const ascii = document("Desktop notes wrap across lines while the cursor moves.\n");
    const utf8 = document("A e\u{301} 界\t👩‍💻 notes\r\n");
    try output.interface.print("Text layout host benchmark: 512-byte documents, {d} columns, {d} visible rows; original rescan is a same-build comparison\n", .{ COLUMNS, VISIBLE_ROWS });
    inline for (.{ "ascii", "unicode" }, .{ &ascii, &utf8 }) |kind, bytes| {
        const layout = text_layout.Layout{ .text = bytes, .columns = COLUMNS };
        inline for (comptime std.meta.tags(Position)) |position| {
            const caret = text_layout.Caret{ .offset = switch (position) {
                .head => 0,
                .middle => text_layout.unicode.ceilBoundary(bytes, DOCUMENT_BYTES / 2),
                .end => DOCUMENT_BYTES,
            } };
            try requireEquivalent(layout, caret);
            inline for (comptime std.meta.tags(Method)) |method| {
                var samples: [5]u64 = undefined;
                var checksum: u64 = 0;
                for (&samples) |*sample| {
                    for (0..100) |_| _ = iteration(method, layout, caret);
                    const start = std.Io.Clock.awake.now(init.io);
                    for (0..ITERATIONS) |_| checksum +%= iteration(method, layout, caret);
                    sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
                }
                std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
                const elapsed = @as(f64, @floatFromInt(samples[2])) / ITERATIONS;
                try output.interface.print("{s}_{s}/{s}: {d:.2} ns/iteration (median of 5), checksum={d}\n", .{
                    kind, @tagName(position), @tagName(method), elapsed, checksum,
                });
            }
        }
    }
    try output.interface.flush();
}

fn document(comptime pattern: []const u8) [DOCUMENT_BYTES]u8 {
    var bytes: [DOCUMENT_BYTES]u8 = @splat('x');
    var used: usize = 0;
    while (pattern.len <= bytes.len - used) : (used += pattern.len) @memcpy(bytes[used..][0..pattern.len], pattern);
    return bytes;
}

fn rescan(layout: text_layout.Layout, caret: text_layout.Caret, storage: []text_layout.Row) text_layout.VisibleWindow {
    const position = layout.locate(caret);
    const first = position.index -| (storage.len - 1);
    var iterator = layout.rows();
    var index: usize = 0;
    var count: usize = 0;
    while (iterator.next()) |row| : (index += 1) {
        if (index < first) continue;
        if (count == storage.len) break;
        storage[count] = row;
        count += 1;
    }
    return .{ .storage = storage, .first_slot = 0, .first_index = first, .count = count, .location = position };
}

fn requireEquivalent(layout: text_layout.Layout, caret: text_layout.Caret) !void {
    var expected_rows: [VISIBLE_ROWS]text_layout.Row = undefined;
    var actual_rows: [VISIBLE_ROWS]text_layout.Row = undefined;
    const expected = rescan(layout, caret, &expected_rows);
    const actual = layout.visibleWindow(caret, &actual_rows);
    if (expected.first_index != actual.first_index or expected.count != actual.count or !std.meta.eql(expected.location, actual.location)) return error.WindowMismatch;
    for (0..expected.count) |index| {
        if (!std.meta.eql(expected.rowAt(index), actual.rowAt(index))) return error.RowMismatch;
    }
}

fn iteration(comptime method: Method, layout: text_layout.Layout, caret: text_layout.Caret) u64 {
    std.mem.doNotOptimizeAway(layout);
    var storage: [VISIBLE_ROWS]text_layout.Row = undefined;
    const window = switch (method) {
        .rescan => rescan(layout, caret, &storage),
        .single_pass => layout.visibleWindow(caret, &storage),
    };
    std.mem.doNotOptimizeAway(&storage);
    var checksum: u64 = window.location.index + window.location.column + window.first_index + window.count;
    for (0..window.count) |index| {
        const row = window.rowAt(index);
        checksum +%= row.start + row.end + row.next + row.width + @intFromBool(row.soft);
    }
    return checksum;
}
