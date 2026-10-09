//! Verify the loader's complete-through-exit event log against the live TPM after the
//! kernel owns CRB. This is local measurement consistency, not remote attestation.
const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const paging = @import("../memory/paging64.zig");
const tpm = @import("tpm2_hw.zig");
const log = @import("../../boot/tcg_event_log.zig");

pub fn verify() !bool {
    const info = handoff.capturedInfo() orelse return error.MissingBootInfo;
    const captured = info.boot_tpm orelse return false;
    const image = info.boot_image orelse return error.MissingBootImage;
    // The allocator retains the loader's complete page-aligned copy before
    // CRB init. Access that physical extent only through its supervisor alias.
    const bytes = try mappedLogBytes(captured.log_address, captured.log_bytes);
    const replayed = try log.replay(bytes, image);
    if (!std.mem.eql(u8, &replayed, &captured.pcr11)) return error.BootMeasurementChanged;
    try requirePcr(log.pcr.INDEX, replayed);
    try requirePcr(5, try log.replayExit(bytes, captured.final_events));
    return true;
}

fn mappedLogBytes(physical_address: u64, length: u32) error{InvalidBootLogAddress}![]const u8 {
    if (physical_address == 0 or length == 0) return error.InvalidBootLogAddress;
    const last = std.math.add(u64, physical_address, length - 1) catch return error.InvalidBootLogAddress;
    _ = paging.directMapAddress(last) orelse return error.InvalidBootLogAddress;
    const alias = paging.directMapAddress(physical_address) orelse return error.InvalidBootLogAddress;
    return @as([*]const u8, @ptrFromInt(alias))[0..length];
}

test "boot TPM log uses a bounded supervisor alias for its retained physical copy" {
    const physical: u64 = 0x0200_0000;
    const bytes = try mappedLogBytes(physical, 4096);
    try std.testing.expectEqual(paging.directMapAddress(physical).?, @intFromPtr(bytes.ptr));
    try std.testing.expectEqual(@as(usize, 4096), bytes.len);
    const terminal = try mappedLogBytes(paging.MANAGED_PHYSICAL_BYTES - 1, 1);
    try std.testing.expectEqual(paging.directMapAddress(paging.MANAGED_PHYSICAL_BYTES - 1).?, @intFromPtr(terminal.ptr));
    try std.testing.expectError(error.InvalidBootLogAddress, mappedLogBytes(0, 4096));
    try std.testing.expectError(error.InvalidBootLogAddress, mappedLogBytes(physical, 0));
    try std.testing.expectError(error.InvalidBootLogAddress, mappedLogBytes(paging.MANAGED_PHYSICAL_BYTES - 1, 2));
    try std.testing.expectError(error.InvalidBootLogAddress, mappedLogBytes(std.math.maxInt(u64), 2));
}

fn requirePcr(comptime index: u5, expected: log.pcr.Digest) !void {
    const command = log.pcr.command(index);
    var response: [log.pcr.RESPONSE_BYTES]u8 = undefined;
    const actual = try log.pcr.parse(index, try tpm.execute(&command, &response, 2000));
    if (!std.mem.eql(u8, &actual, &expected)) return error.BootMeasurementChanged;
}
