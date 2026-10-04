const std = @import("std");

extern fn zigos_fred_capture_probe(*const [15]u64, *const [8]u64, *[32]u64) callconv(.c) void;
extern fn zigos_fred_return_probe(*const [24]u64, *const [8]u64, *[8]u64) callconv(.c) void;

// The host fixture supplies diagnostic text bounds for the exported real ISR.
// Import it only in test builds; registered-handler tests execute no MMIO.
comptime {
    if (@import("builtin").is_test) _ = @import("../../kernel/interrupts/isr.zig").Registers;
}

// Intel FRED rev5, section5.2.1: lowest-address error, RIP, augmented CS,
// RFLAGS, RSP, augmented SS, event data, reserved zero. Vector/type are in SS.
test "FRED captures every GPR from the architectural eight-qword event frame" {
    const index_map = [_]usize{ 16, 13, 15, 14, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    const cases = [_]struct { cs: u64, ss: u64, vector: u8, event_type: u4, syscall: bool = false, yield: bool = false }{
        .{ .cs = 0x23, .ss = 0x1b, .vector = 65, .event_type = 0 },
        .{ .cs = 0x08 | (2 << 16) | (1 << 18), .ss = 0x10 | (7 << 16), .vector = 2, .event_type = 2 },
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 1, .event_type = 7, .syscall = true },
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 1, .event_type = 7, .syscall = true, .yield = true },
        // SYSENTER and INT are not the native SYSCALL ABI, even with RAX0.
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 2, .event_type = 7 },
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 1, .event_type = 4 },
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 64, .event_type = 4 },
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 65, .event_type = 4 },
        .{ .cs = 0x08, .ss = 0x10 | (1 << 17), .vector = 65, .event_type = 4 },
        // INT1/INT3 are authentic debug/breakpoint events, not arbitrary INT n.
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 1, .event_type = 5 },
        .{ .cs = 0x23, .ss = 0x1b | (1 << 17), .vector = 3, .event_type = 6 },
        .{ .cs = 0x23, .ss = 0x1b, .vector = 14, .event_type = 3 },
    };
    for (cases) |case| {
        var seeds: [15]u64 = undefined;
        for (&seeds, 0..) |*value, index| value.* = 0x1234_0000 + @as(u64, @intCast(index)) * 0x101;
        seeds[0] = if (case.syscall and !case.yield) 44 else 0;
        const augmented_ss = case.ss | (@as(u64, case.vector) << 32) | (@as(u64, case.event_type) << 48) | (1 << 57) | (1 << 58) | (2 << 60);
        const frame = [8]u64{ 0xdead_0042, 0x400008, case.cs, 0x202, 0x9000, augmented_ss, 0xfeed_abcd, 0 };
        var captured: [32]u64 = undefined;
        zigos_fred_capture_probe(&seeds, &frame, &captured);
        for (seeds, index_map, 0..) |expected, frame_index, register_index| {
            const actual_expected = if (case.yield and register_index == 0) seeds[6] else expected;
            try std.testing.expectEqual(actual_expected, captured[frame_index]);
        }
        try std.testing.expectEqual(@as(u64, 0), captured[0]);
        try std.testing.expectEqual(@as(u64, 0), captured[12]);
        const rejected_software = !case.syscall and (case.cs & 3) == 3 and (case.event_type == 4 or case.event_type == 7);
        try std.testing.expectEqual(@as(u64, if (case.yield) 129 else if (case.syscall) 128 else if (rejected_software) 6 else case.vector), captured[17]);
        try std.testing.expectEqual(if (case.syscall or rejected_software) @as(u64, 0) else frame[0], captured[18]);
        try std.testing.expectEqualSlices(u64, &.{ frame[1], case.cs & 0xffff, frame[3], frame[4], case.ss & 0xffff }, captured[19..24]);
        try std.testing.expectEqualSlices(u64, &frame, captured[24..]);
    }
}

test "FRED publishes handler return edits while retaining augmented event metadata" {
    const raw = [8]u64{ 0xdead_0042, 0x400008, 0x08 | (2 << 16) | (1 << 18), 0x202, 0x9000, 0x10 | (7 << 16) | (@as(u64, 2) << 32) | (@as(u64, 2) << 48) | (@as(u64, 1) << 57), 0xfeed_abcd, 0 };
    var canonical: [24]u64 = @splat(0x12345678);
    canonical[19] = 0x500010;
    canonical[20] = 0x23;
    canonical[21] = 0x246;
    canonical[22] = 0xa000;
    canonical[23] = 0x1b;
    var returned: [8]u64 = undefined;
    zigos_fred_return_probe(&canonical, &raw, &returned);
    try std.testing.expectEqual(raw[0], returned[0]);
    try std.testing.expectEqual(canonical[19], returned[1]);
    try std.testing.expectEqual((raw[2] & ~@as(u64, 0xffff)) | canonical[20], returned[2]);
    try std.testing.expectEqual(canonical[21], returned[3]);
    try std.testing.expectEqual(canonical[22], returned[4]);
    try std.testing.expectEqual((raw[5] & ~@as(u64, 0xffff)) | canonical[23], returned[5]);
    try std.testing.expectEqualSlices(u64, raw[6..], returned[6..]);
}

test "FRED yield capture preserves untrusted full-width counter and disposition" {
    const frame = [8]u64{ 0, 0x4000_1008, 0x23, 0x202, 0x7fff_eff0, 0x1b | (@as(u64, 1) << 17) | (@as(u64, 1) << 32) | (@as(u64, 7) << 48), 0, 0 };
    for ([_][2]u64{
        .{ @as(u64, std.math.maxInt(u32)) + 1, 0 },
        .{ std.math.maxInt(u32), @as(u64, std.math.maxInt(u32)) + 1 },
        .{ std.math.maxInt(u64), std.math.maxInt(u64) },
        .{ std.math.maxInt(u32), 1 },
    }) |arguments| {
        var seeds: [15]u64 = @splat(0);
        seeds[6] = arguments[0]; // RDI is copied to canonical RAX for yields.
        seeds[5] = arguments[1]; // RSI remains the full untrusted disposition.
        var captured: [32]u64 = undefined;
        zigos_fred_capture_probe(&seeds, &frame, &captured);
        try std.testing.expectEqual(@as(u64, 129), captured[17]);
        try std.testing.expectEqual(arguments[0], captured[16]);
        try std.testing.expectEqual(arguments[1], captured[10]);
        try std.testing.expectEqual(frame[1], captured[19]);
        try std.testing.expectEqual(frame[4], captured[22]);
    }
}
