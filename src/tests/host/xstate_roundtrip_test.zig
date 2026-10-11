const std = @import("std");
const xstate = @import("../../arch/xstate.zig");
const model = @import("../../arch/xstate_roundtrip_model.zig");

const Image = model.Image;
extern fn zigos_xstate_host_supported() callconv(.c) u32;
extern fn zigos_xstate_host_roundtrip(*const [3]Image, *[3]Image) callconv(.c) void;
extern const zigos_xstate_generic_probe: u8;
extern const zigos_xstate_generic_probe_end: u8;
extern const zigos_xstate_prepared_probe: u8;
extern const zigos_xstate_prepared_probe_end: u8;

test "prepared xstate assembly preserves complete kernel and userspace FP owners" {
    if (zigos_xstate_host_supported() == 0) return error.SkipZigTest;
    var inputs: [3]Image = undefined;
    var outputs: [3]Image = undefined;
    for (&inputs, &outputs, 0..) |*input, *output, owner| {
        model.initialize(input, owner);
        model.initializeCanary(output);
    }
    zigos_xstate_host_roundtrip(&inputs, &outputs);
    try std.testing.expect(model.verify(&inputs, &outputs));
}

test "wide xstate proof detects corruption of every upper register, reserved header and canary" {
    var inputs: [3]Image = undefined;
    for (&inputs, 0..) |*input, owner| model.initialize(input, owner);
    var outputs = inputs;
    try std.testing.expect(model.verify(&inputs, &outputs));
    for (&outputs) |*output| {
        for (0..16) |register| {
            const offset = 576 + register * 16;
            output.state.image[offset] ^= 1;
            try std.testing.expect(!model.verify(&inputs, &outputs));
            output.state.image[offset] ^= 1;
        }
        for (528..576) |offset| {
            output.state.image[offset] ^= 1;
            try std.testing.expect(!model.verify(&inputs, &outputs));
            output.state.image[offset] ^= 1;
        }
        const canary = &std.mem.asBytes(output)[@sizeOf(xstate.State)];
        canary.* ^= 1;
        try std.testing.expect(!model.verify(&inputs, &outputs));
        canary.* ^= 1;
    }
    try std.testing.expect(model.verify(&inputs, &outputs));
}

fn probeBytes(start: *const u8, end: *const u8) []const u8 {
    const bytes: [*]const u8 = @ptrCast(start);
    return bytes[0 .. @intFromPtr(end) - @intFromPtr(start)];
}

test "prepared owner switch retains eager state operations without control-register exits" {
    const generic = probeBytes(&zigos_xstate_generic_probe, &zigos_xstate_generic_probe_end);
    const prepared = probeBytes(&zigos_xstate_prepared_probe, &zigos_xstate_prepared_probe_end);
    // The probes include initial entry, one syscall, and continuation return.
    // r13 prefixes identify their eager state operations independent of offsets.
    for ([_][]const u8{ generic, prepared }) |bytes| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xae, 0x65 }));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xc7, 0x6d }));
        try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xae, 0x6d }));
        try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xc7, 0x5d }));
    }
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, generic, &.{ 0x0f, 0x06 })); // CLTS
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, generic, &.{ 0x0f, 0x20, 0xe0 })); // CR4 -> RAX
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, prepared, &.{ 0x0f, 0x06 }));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, prepared, &.{ 0x0f, 0x20 }));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, prepared, &.{ 0x0f, 0x22 }));
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, prepared, &.{ 0x65, 0xf6, 0x04, 0x25, 0x20, 0, 0, 0, 1 })); // Per-CPU PKE
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, prepared, &.{ 0x0f, 0x01, 0xee })); // RDPKRU
    try std.testing.expectEqual(@as(usize, 4), std.mem.count(u8, prepared, &.{ 0x0f, 0x01, 0xef })); // WRPKRU
    try std.testing.expectEqual(@as(usize, 4), std.mem.count(u8, prepared, &.{ 0x0f, 0xae, 0xe8 })); // LFENCE
}
