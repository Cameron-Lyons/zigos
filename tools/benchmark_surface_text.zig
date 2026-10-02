const std = @import("std");
const abi = @import("surface_text").abi;
const unicode = abi.text_layout.unicode;

const DOCUMENT_BYTES = 512;
const ITERATIONS = 20_000;
const Position = enum { head, middle, end };
const Method = enum { original, single_pass };

pub fn main(init: std.process.Init) !void {
    var output_buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    const ascii = document("Desktop notes wrap across lines while the cursor moves.\n");
    const utf8 = document("A e\u{301} 界\t👩‍💻 notes\r\n");
    try output.interface.print("Text surface validation host benchmark: 512-byte documents; original validation is a same-build comparison\n", .{});
    inline for (.{ "ascii", "unicode" }, .{ &ascii, &utf8 }) |kind, bytes| {
        inline for (comptime std.meta.tags(Position)) |position| {
            inline for (.{ false, true }) |selection| {
                const cursor = switch (position) {
                    .head => 0,
                    .middle => unicode.ceilBoundary(bytes, DOCUMENT_BYTES / 2),
                    .end => DOCUMENT_BYTES,
                };
                const anchor = if (!selection) cursor else unicode.ceilBoundary(bytes, if (position == .middle) DOCUMENT_BYTES / 4 else DOCUMENT_BYTES / 2);
                var text = abi.SurfaceText{ .text_length = DOCUMENT_BYTES, .cursor = @intCast(cursor), .state = .{ .model = 1, .selection_anchor = @intCast(anchor) } };
                @memcpy(&text.text, bytes);
                if (!original(&text) or !text.isCanonical()) return error.InvalidWorkload;
                inline for (comptime std.meta.tags(Method)) |method| {
                    var samples: [5]u64 = undefined;
                    var checksum: usize = 0;
                    for (&samples) |*sample| {
                        for (0..100) |_| _ = iteration(method, &text);
                        const start = std.Io.Clock.awake.now(init.io);
                        for (0..ITERATIONS) |_| checksum +%= @intFromBool(iteration(method, &text));
                        sample.* = @intCast(start.durationTo(std.Io.Clock.awake.now(init.io)).toNanoseconds());
                    }
                    std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
                    if (checksum != samples.len * ITERATIONS) return error.ValidationMismatch;
                    try output.interface.print("{s}_{s}/{s}/{s}: {d:.2} ns/iteration (median of 5), checksum={d}\n", .{
                        kind, @tagName(position), if (selection) "selected" else "collapsed", @tagName(method), @as(f64, @floatFromInt(samples[2])) / ITERATIONS, checksum,
                    });
                }
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

fn iteration(comptime method: Method, text: *const abi.SurfaceText) bool {
    std.mem.doNotOptimizeAway(text);
    return switch (method) {
        .original => original(text),
        .single_pass => text.isCanonical(),
    };
}

// Keep the original ingress checks here so metadata, text and boundary work
// are compared in the same executable with the same compiler settings.
fn original(text: *const abi.SurfaceText) bool {
    if (text.text_length > DOCUMENT_BYTES or text.cursor > text.text_length or text.state.selection_anchor > text.text_length or
        text.state.reserved != 0 or text.state.model == 0 or text.state.model > 6 or text.state.flags & 0x80 != 0) return false;
    if (text.state.cursor_upstream and (text.state.model != 1 or text.cursor == 0 or unicode.followsNewline(text.textSlice(), text.cursor))) return false;
    const save_state = std.enums.fromInt(abi.DocumentSaveState, text.state.save_state) orelse return false;
    if (text.state.model != 1 and (save_state != .none or text.state.selection_anchor != text.cursor)) return false;
    if (!unicode.validText(text.textSlice()) or !unicode.isBoundary(text.textSlice(), text.cursor) or !unicode.isBoundary(text.textSlice(), text.state.selection_anchor)) return false;
    return std.mem.allEqual(u8, text.text[text.text_length..], 0);
}
