const std = @import("std");
const xstate = @import("../../arch/xstate.zig");

const Image = extern struct { state: xstate.State align(xstate.alignment) };
extern fn zigos_xstate_host_supported() callconv(.c) u32;
extern fn zigos_xstate_host_roundtrip(*const [3]Image, *[3]Image) callconv(.c) void;
extern const zigos_xstate_generic_probe: u8;
extern const zigos_xstate_generic_probe_end: u8;
extern const zigos_xstate_prepared_probe: u8;
extern const zigos_xstate_prepared_probe_end: u8;

comptime {
    if (@sizeOf(Image) != 640 or @alignOf(Image) != xstate.alignment)
        @compileError("host assembly image stride must remain 640 bytes");
}

fn initialize(image: *Image, owner: usize) void {
    image.state.initialize();
    const bytes = &image.state.image;
    // Hosted XRSTOR uses the standard format. All x87 and SSE fields are live.
    std.mem.writeInt(u64, bytes[512..520], xstate.enabled_mask, .little);
    std.mem.writeInt(u64, bytes[520..528], 0, .little);
    std.mem.writeInt(u16, bytes[0..2], 0x037f | (@as(u16, @intCast(owner + 1)) << 10), .little);
    bytes[4] = 0xff;
    std.mem.writeInt(u32, bytes[24..28], 0x1f80 | (@as(u32, @intCast(owner + 1)) << 13), .little);
    for (0..8) |register| {
        const offset = 32 + register * 16;
        std.mem.writeInt(u64, bytes[offset..][0..8], 0x8000_0000_0000_0000 | (owner << 16) | register, .little);
        std.mem.writeInt(u16, bytes[offset + 8 ..][0..2], 0x3fff + @as(u16, @intCast(register)), .little);
    }
    for (0..16) |register| {
        const offset = 160 + register * 16;
        std.mem.writeInt(u64, bytes[offset..][0..8], 0x1357_2468_0000_0000 | (owner << 16) | register, .little);
        std.mem.writeInt(u64, bytes[offset + 8 ..][0..8], 0xfedc_ba98_0000_0000 | (owner << 16) | register, .little);
    }
}

test "prepared xstate assembly preserves complete kernel and userspace FP owners" {
    if (zigos_xstate_host_supported() == 0) return error.SkipZigTest;
    var inputs: [3]Image = undefined;
    var outputs: [3]Image = undefined;
    for (&inputs, &outputs, 0..) |*input, *output, owner| {
        initialize(input, owner);
        output.state.initialize();
    }
    zigos_xstate_host_roundtrip(&inputs, &outputs);
    for (inputs, outputs) |input, output| {
        try std.testing.expectEqualSlices(u8, input.state.image[0..5], output.state.image[0..5]);
        try std.testing.expectEqualSlices(u8, input.state.image[24..28], output.state.image[24..28]);
        for (0..8) |register| {
            const offset = 32 + register * 16;
            try std.testing.expectEqualSlices(u8, input.state.image[offset..][0..10], output.state.image[offset..][0..10]);
        }
        try std.testing.expectEqualSlices(u8, input.state.image[160..416], output.state.image[160..416]);
        try std.testing.expectEqual(xstate.enabled_mask, std.mem.readInt(u64, output.state.image[512..520], .little));
        try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, output.state.image[520..528], .little));
    }
}

fn probeBytes(start: *const u8, end: *const u8) []const u8 {
    const bytes: [*]const u8 = @ptrCast(start);
    return bytes[0 .. @intFromPtr(end) - @intFromPtr(start)];
}

test "prepared owner switch retains eager state operations without control-register exits" {
    const generic = probeBytes(&zigos_xstate_generic_probe, &zigos_xstate_generic_probe_end);
    const prepared = probeBytes(&zigos_xstate_prepared_probe, &zigos_xstate_prepared_probe_end);
    // The probes use r13 exclusively; these three prefixes identify XSAVES,
    // full XRSTOR and XRSTORS respectively, independent of branch offsets.
    for ([_][]const u8{ generic, prepared }) |bytes| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xc7, 0x6d }));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xae, 0x6d }));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, &.{ 0x49, 0x0f, 0xc7, 0x5d }));
    }
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, generic, &.{ 0x0f, 0x06 })); // CLTS
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, generic, &.{ 0x0f, 0x20, 0xe0 })); // CR4 -> RAX
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, prepared, &.{ 0x0f, 0x06 }));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, prepared, &.{ 0x0f, 0x20 }));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, prepared, &.{ 0x0f, 0x22 }));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, prepared, &.{ 0x0f, 0x01, 0xee })); // RDPKRU
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, prepared, &.{ 0x0f, 0x01, 0xef })); // WRPKRU
}
