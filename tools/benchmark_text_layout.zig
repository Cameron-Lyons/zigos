const std = @import("std");
const text_layout = @import("text_layout").layout;

const DOCUMENT_BYTES = 512;
const COLUMNS = 40;
const VISIBLE_ROWS = 6;
const ITERATIONS = 20_000;
const SAMPLE_COUNT = 5;
const Position = enum { head, middle, end };
const Method = enum { rescan, single_pass };
const NavigationMethod = enum { rescan, reuse_iterator };
const Direction = enum { up, down };
const Step = enum { row, page };
const Column = enum { initial, retained };
const BoundaryMethod = enum { original_iterator, production };
const BoundaryOperation = enum { next, previous, ceil };
const BoundaryWorkload = enum { head, middle, end, all_bytes, chained_right, chained_left, ceil_head_endpoint, ceil_end_endpoint, unicode_fallback };
const BOUNDARY_BATCH_ROUNDS = 64;
const BOUNDARY_FALLBACK_ROUNDS = 5_000;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const boundaries_only = args.len == 2 and std.mem.eql(u8, args[1], "--boundaries-only");
    const check_boundaries = args.len == 2 and std.mem.eql(u8, args[1], "--check-boundaries");
    if (args.len > 2 or (args.len == 2 and !boundaries_only and !check_boundaries)) return error.InvalidArguments;
    var output_buffer: [2048]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    if (boundaries_only or check_boundaries) {
        try benchmarkBoundaries(init.io, &output.interface, check_boundaries);
        try output.interface.flush();
        return;
    }
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
            var samples: [2][SAMPLE_COUNT]u64 = undefined;
            var checksums: [2]u64 = @splat(0);
            // Pair samples so thermal and clock drift affect both methods.
            for (0..SAMPLE_COUNT) |sample| {
                for (0..2) |phase| {
                    const method = (sample + phase) % 2;
                    const result = if (method == 0)
                        windowSample(.rescan, init.io, layout, caret)
                    else
                        windowSample(.single_pass, init.io, layout, caret);
                    samples[method][sample] = result.elapsed;
                    checksums[method] +%= result.checksum;
                }
            }
            if (checksums[0] != checksums[1]) return error.WindowChecksumMismatch;
            inline for (comptime std.meta.tags(Method), 0..) |method, index| {
                std.mem.sort(u64, &samples[index], {}, std.sort.asc(u64));
                const elapsed = @as(f64, @floatFromInt(samples[index][SAMPLE_COUNT / 2])) / ITERATIONS;
                try output.interface.print("{s}_{s}/{s}: {d:.2} ns/iteration (median of {d}), checksum={d}\n", .{
                    kind, @tagName(position), @tagName(method), elapsed, SAMPLE_COUNT, checksums[index],
                });
            }
        }
        inline for (comptime std.meta.tags(Position)) |position| {
            const caret = text_layout.Caret{ .offset = switch (position) {
                .head => 0,
                .middle => text_layout.unicode.ceilBoundary(bytes, DOCUMENT_BYTES / 2),
                .end => DOCUMENT_BYTES,
            } };
            inline for (comptime std.meta.tags(Direction)) |direction| {
                inline for (comptime std.meta.tags(Step)) |step| {
                    const count: usize = if (step == .row) 1 else VISIBLE_ROWS - 1;
                    inline for (comptime std.meta.tags(Column)) |column_kind| {
                        const preferred: ?usize = if (column_kind == .initial) null else 12;
                        try requireEquivalentNavigation(layout, caret, preferred, direction == .down, count);
                        var samples: [2][SAMPLE_COUNT]u64 = undefined;
                        var checksums: [2]u64 = @splat(0);
                        // Pair samples and alternate which method runs first.
                        for (0..SAMPLE_COUNT) |sample| {
                            for (0..2) |phase| {
                                const method = (sample + phase) % 2;
                                const result = if (method == 0)
                                    navigationSample(.rescan, init.io, layout, caret, preferred, direction == .down, count)
                                else
                                    navigationSample(.reuse_iterator, init.io, layout, caret, preferred, direction == .down, count);
                                samples[method][sample] = result.elapsed;
                                checksums[method] +%= result.checksum;
                            }
                        }
                        if (checksums[0] != checksums[1]) return error.NavigationChecksumMismatch;
                        inline for (comptime std.meta.tags(NavigationMethod), 0..) |method, index| {
                            std.mem.sort(u64, &samples[index], {}, std.sort.asc(u64));
                            const elapsed = @as(f64, @floatFromInt(samples[index][SAMPLE_COUNT / 2])) / ITERATIONS;
                            try output.interface.print("navigation_{s}_{s}_{s}_{s}_{s}/{s}: {d:.2} ns/iteration (median of {d}), checksum={d}\n", .{
                                kind, @tagName(position), @tagName(direction), @tagName(step), @tagName(column_kind), @tagName(method), elapsed, SAMPLE_COUNT, checksums[index],
                            });
                        }
                    }
                }
            }
        }
    }
    try benchmarkBoundaries(init.io, &output.interface, false);
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

fn windowSample(comptime method: Method, io: std.Io, layout: text_layout.Layout, caret: text_layout.Caret) struct { elapsed: u64, checksum: u64 } {
    for (0..100) |_| _ = iteration(method, layout, caret);
    var checksum: u64 = 0;
    const start = std.Io.Clock.awake.now(io);
    for (0..ITERATIONS) |_| checksum +%= iteration(method, layout, caret);
    return .{
        .elapsed = @intCast(start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds()),
        .checksum = checksum,
    };
}

// The original Notes path located once to establish a preferred column, then
// located again and restarted the row iterator for the target visual row.
fn navigationRescan(layout: text_layout.Layout, caret: text_layout.Caret, preferred: ?usize, down: bool, count: usize) text_layout.VerticalMovement {
    const column = preferred orelse layout.locate(caret).column;
    const index = layout.locate(caret).index;
    return .{
        .caret = layout.rowAt(if (down) index +| count else index -| count).atColumn(layout.text, column),
        .column = column,
    };
}

fn requireEquivalentNavigation(layout: text_layout.Layout, caret: text_layout.Caret, preferred: ?usize, down: bool, count: usize) !void {
    const expected = navigationRescan(layout, caret, preferred, down, count);
    const actual = layout.moveVertical(caret, preferred, down, count);
    if (!std.meta.eql(expected, actual)) return error.NavigationMismatch;
    if (!text_layout.unicode.isBoundary(layout.text, actual.caret.offset)) return error.InvalidCaret;
}

fn navigationIteration(comptime method: NavigationMethod, layout: text_layout.Layout, caret: text_layout.Caret, preferred: ?usize, down: bool, count: usize) u64 {
    std.mem.doNotOptimizeAway(layout);
    const movement = switch (method) {
        .rescan => navigationRescan(layout, caret, preferred, down, count),
        .reuse_iterator => layout.moveVertical(caret, preferred, down, count),
    };
    std.mem.doNotOptimizeAway(movement);
    return movement.caret.offset + movement.column + @intFromBool(movement.caret.upstream);
}

fn navigationSample(comptime method: NavigationMethod, io: std.Io, layout: text_layout.Layout, caret: text_layout.Caret, preferred: ?usize, down: bool, count: usize) struct { elapsed: u64, checksum: u64 } {
    for (0..100) |_| _ = navigationIteration(method, layout, caret, preferred, down, count);
    var checksum: u64 = 0;
    const start = std.Io.Clock.awake.now(io);
    for (0..ITERATIONS) |_| checksum +%= navigationIteration(method, layout, caret, preferred, down, count);
    return .{
        .elapsed = @intCast(start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds()),
        .checksum = checksum,
    };
}

// Freeze the original navigators, including their out-of-range semantics.
// Both sides share the unchanged production grapheme Iterator.
fn originalNextBoundary(text: []const u8, offset: usize) usize {
    var it = text_layout.unicode.Iterator{ .text = text };
    while (it.next()) |cluster| if (cluster.end > offset) return cluster.end;
    return text.len;
}

fn originalPreviousBoundary(text: []const u8, offset: usize) usize {
    var it = text_layout.unicode.Iterator{ .text = text };
    while (it.next()) |cluster| if (cluster.end >= offset) return cluster.start;
    return text.len;
}

fn originalCeilBoundary(text: []const u8, offset: usize) usize {
    if (offset == 0) return 0;
    var it = text_layout.unicode.Iterator{ .text = text };
    while (it.next()) |cluster| if (cluster.end >= offset) return cluster.end;
    return text.len;
}

fn boundaryCall(comptime method: BoundaryMethod, comptime operation: BoundaryOperation, text: []const u8, offset: usize) usize {
    var runtime_text = text;
    var runtime_offset = offset;
    // Mutable document backing escapes through a memory-clobber barrier;
    // opaque slice/offset storage also prevents endpoint constant folding.
    // Apply exactly the same barriers to both methods, on every call.
    std.mem.doNotOptimizeAway(runtime_text.ptr);
    std.mem.doNotOptimizeAway(&runtime_text);
    std.mem.doNotOptimizeAway(&runtime_offset);
    const result = switch (method) {
        .original_iterator => switch (operation) {
            .next => originalNextBoundary(runtime_text, runtime_offset),
            .previous => originalPreviousBoundary(runtime_text, runtime_offset),
            .ceil => originalCeilBoundary(runtime_text, runtime_offset),
        },
        .production => switch (operation) {
            .next => text_layout.unicode.nextBoundary(runtime_text, runtime_offset),
            .previous => text_layout.unicode.previousBoundary(runtime_text, runtime_offset),
            .ceil => text_layout.unicode.ceilBoundary(runtime_text, runtime_offset),
        },
    };
    std.mem.doNotOptimizeAway(result);
    return result;
}

const FallbackOffsets = struct {
    storage: [DOCUMENT_BYTES]usize = undefined,
    count: usize = 0,

    fn init(comptime operation: BoundaryOperation, text: []const u8) FallbackOffsets {
        var offsets = FallbackOffsets{};
        // Exclude every endpoint shortcut. Select the exact adjacent pair
        // tested by this helper, with at least one non-ASCII byte.
        for (2..text.len - 1) |offset| {
            const non_ascii = switch (operation) {
                .next => text[offset] >= 0x80 or text[offset + 1] >= 0x80,
                .previous => text[offset - 2] >= 0x80 or text[offset - 1] >= 0x80,
                .ceil => text[offset - 1] >= 0x80 or text[offset] >= 0x80,
            };
            if (!non_ascii) continue;
            offsets.storage[offsets.count] = offset;
            offsets.count += 1;
        }
        return offsets;
    }

    fn slice(self: *const FallbackOffsets) []const usize {
        return self.storage[0..self.count];
    }
};

const BoundaryResult = struct {
    checksum: u64 = 0,
    calls: u64 = 0,

    fn add(self: *BoundaryResult, offset: usize, result: usize) void {
        self.checksum +%= @as(u64, offset) *% 0x9E37_79B1 +% @as(u64, result) *% 0x85EB_CA77;
        self.calls += 1;
    }
};

fn boundaryIteration(comptime method: BoundaryMethod, comptime operation: BoundaryOperation, comptime workload: BoundaryWorkload, text: []const u8, fallback: []const usize, round: usize) BoundaryResult {
    var result = BoundaryResult{};
    switch (workload) {
        .all_bytes => {
            // Rotate each complete inclusive byte sweep between repetitions.
            var offset = round % (text.len + 1);
            for (0..text.len + 1) |_| {
                result.add(offset, boundaryCall(method, operation, text, offset));
                offset += 1;
                if (offset > text.len) offset = 0;
            }
        },
        .chained_right => {
            var offset: usize = 0;
            while (offset < text.len) {
                const next = boundaryCall(method, operation, text, offset);
                std.debug.assert(next > offset and next <= text.len);
                result.add(offset, next);
                offset = next;
            }
        },
        .chained_left => {
            var offset = text.len;
            while (offset != 0) {
                const previous = boundaryCall(method, operation, text, offset);
                std.debug.assert(previous < offset);
                result.add(offset, previous);
                offset = previous;
            }
        },
        else => {
            const jitter = round % 8;
            const offset = switch (workload) {
                .head => jitter,
                .middle => text.len / 2 - 4 + jitter,
                .end => text.len - jitter,
                .ceil_head_endpoint => 0,
                // All inputs use the end shortcut; report it independently
                // from adjacent ASCII and from nearby non-end byte offsets.
                .ceil_end_endpoint => text.len + jitter,
                .unicode_fallback => fallback[round % fallback.len],
                else => unreachable,
            };
            result.add(offset, boundaryCall(method, operation, text, offset));
        },
    }
    return result;
}

fn requireEquivalentBoundaries(documents: *[3][DOCUMENT_BYTES]u8) !void {
    for (documents) |*bytes| {
        const text: []const u8 = bytes;
        if (!text_layout.unicode.validText(text)) return error.InvalidBoundaryDocument;
        inline for (comptime std.meta.tags(BoundaryOperation)) |operation| {
            // This happens for all documents before any benchmark clock.
            for (0..text.len + 3) |offset| {
                if (boundaryCall(.original_iterator, operation, text, offset) != boundaryCall(.production, operation, text, offset)) return error.BoundaryMismatch;
            }
            if (boundaryCall(.original_iterator, operation, text, std.math.maxInt(usize)) != boundaryCall(.production, operation, text, std.math.maxInt(usize))) return error.BoundaryMismatch;
            const fallback = FallbackOffsets.init(operation, text);
            inline for (comptime std.meta.tags(BoundaryWorkload)) |workload| {
                if (comptime (workload == .chained_right and operation != .next) or
                    (workload == .chained_left and operation != .previous) or
                    ((workload == .ceil_head_endpoint or workload == .ceil_end_endpoint) and operation != .ceil)) continue;
                if (workload != .unicode_fallback or fallback.count != 0) {
                    for (0..8) |round| {
                        const expected = boundaryIteration(.original_iterator, operation, workload, text, fallback.slice(), round);
                        const actual = boundaryIteration(.production, operation, workload, text, fallback.slice(), round);
                        if (!std.meta.eql(expected, actual)) return error.BoundaryWorkloadMismatch;
                    }
                }
            }
        }
        // Check each intermediate chained movement, not just a final sum.
        inline for (.{ BoundaryOperation.next, BoundaryOperation.previous }) |operation| {
            var offset: usize = if (operation == .next) 0 else text.len;
            while (if (operation == .next) offset < text.len else offset != 0) {
                const expected = boundaryCall(.original_iterator, operation, text, offset);
                const actual = boundaryCall(.production, operation, text, offset);
                if (expected != actual) return error.BoundaryChainMismatch;
                if (if (operation == .next) actual <= offset or actual > text.len else actual >= offset) return error.BoundaryProgressFailure;
                offset = actual;
            }
        }
    }
    inline for (comptime std.meta.tags(BoundaryOperation)) |operation| {
        if (FallbackOffsets.init(operation, &documents[2]).count == 0) return error.MissingUnicodeFallback;
    }
}

fn boundaryRounds(comptime workload: BoundaryWorkload) usize {
    return switch (workload) {
        .all_bytes, .chained_right, .chained_left => BOUNDARY_BATCH_ROUNDS,
        .unicode_fallback => BOUNDARY_FALLBACK_ROUNDS,
        else => ITERATIONS,
    };
}

fn boundarySample(comptime method: BoundaryMethod, comptime operation: BoundaryOperation, comptime workload: BoundaryWorkload, io: std.Io, text: []const u8, fallback: []const usize) struct { elapsed: u64, result: BoundaryResult } {
    const rounds = boundaryRounds(workload);
    for (0..@min(rounds, 16)) |round| {
        const warm = boundaryIteration(method, operation, workload, text, fallback, round);
        std.mem.doNotOptimizeAway(warm);
    }
    var result = BoundaryResult{};
    const start = std.Io.Clock.awake.now(io);
    for (0..rounds) |round| {
        const iteration_result = boundaryIteration(method, operation, workload, text, fallback, round);
        result.checksum +%= iteration_result.checksum;
        result.calls += iteration_result.calls;
    }
    return .{
        .elapsed = @intCast(start.durationTo(std.Io.Clock.awake.now(io)).toNanoseconds()),
        .result = result,
    };
}

fn benchmarkBoundaries(io: std.Io, output: *std.Io.Writer, check_only: bool) !void {
    var documents = [3][DOCUMENT_BYTES]u8{
        document("Desktop notes while the cursor moves across ASCII text.\n"),
        document("Desktop notes with CRLF lines and cursor movement.\r\n"),
        document("\u{600}A e\u{301} 界 👩‍💻 🇺🇸 क्‍ष notes\r\n"),
    };
    try requireEquivalentBoundaries(&documents);
    if (check_only) {
        try output.print("Boundary navigation correctness: 3 x 512-byte documents, every byte plus oversized offsets and chained traces: PASS\n", .{});
        return;
    }
    try output.print("Boundary navigation host benchmark: frozen original Iterator loops vs production helpers, same build; paired alternating samples; {d} point rounds, {d} sweep/chain rounds, {d} Unicode fallback rounds; ns/call includes identical text/offset barriers\n", .{ ITERATIONS, BOUNDARY_BATCH_ROUNDS, BOUNDARY_FALLBACK_ROUNDS });
    try output.print("Position rows cycle eight nearby offsets: head 0..7, middle 252..259, end 512..505; ceil endpoint rows isolate 0 and 512..519; checksums aggregate all five samples\n", .{});
    for (&documents, [_][]const u8{ "ascii", "crlf_ascii", "unicode" }) |*bytes, kind| {
        const text: []const u8 = bytes;
        inline for (comptime std.meta.tags(BoundaryOperation)) |operation| {
            const fallback = FallbackOffsets.init(operation, text);
            inline for (comptime std.meta.tags(BoundaryWorkload)) |workload| {
                if (comptime (workload == .chained_right and operation != .next) or
                    (workload == .chained_left and operation != .previous) or
                    ((workload == .ceil_head_endpoint or workload == .ceil_end_endpoint) and operation != .ceil)) continue;
                try benchmarkBoundaryWorkload(operation, workload, io, output, text, kind, fallback.slice());
            }
        }
    }
}

fn benchmarkBoundaryWorkload(comptime operation: BoundaryOperation, comptime workload: BoundaryWorkload, io: std.Io, output: *std.Io.Writer, text: []const u8, kind: []const u8, fallback: []const usize) !void {
    if (workload == .unicode_fallback and fallback.len == 0) return;
    var samples: [2][SAMPLE_COUNT]u64 = undefined;
    var checksums: [2]u64 = @splat(0);
    var calls: [2]u64 = @splat(0);
    for (0..SAMPLE_COUNT) |sample| {
        var paired: [2]BoundaryResult = undefined;
        for (0..2) |phase| {
            const method = (sample + phase) % 2;
            const measured = if (method == 0)
                boundarySample(.original_iterator, operation, workload, io, text, fallback)
            else
                boundarySample(.production, operation, workload, io, text, fallback);
            samples[method][sample] = measured.elapsed;
            paired[method] = measured.result;
            checksums[method] +%= measured.result.checksum;
            calls[method] += measured.result.calls;
        }
        if (!std.meta.eql(paired[0], paired[1])) return error.BoundaryChecksumMismatch;
    }
    if (checksums[0] != checksums[1] or calls[0] != calls[1]) return error.BoundaryChecksumMismatch;
    inline for (comptime std.meta.tags(BoundaryMethod), 0..) |method, index| {
        std.mem.sort(u64, &samples[index], {}, std.sort.asc(u64));
        const elapsed = @as(f64, @floatFromInt(samples[index][SAMPLE_COUNT / 2])) /
            @as(f64, @floatFromInt(calls[index] / SAMPLE_COUNT));
        try output.print("boundary_{s}_{s}_{s}/{s}: {d:.2} ns/call (median of {d}), rounds={d}, calls_per_sample={d}, checksum={d}\n", .{
            kind, @tagName(operation), @tagName(workload), @tagName(method), elapsed, SAMPLE_COUNT, boundaryRounds(workload), calls[index] / SAMPLE_COUNT, checksums[index],
        });
    }
}
