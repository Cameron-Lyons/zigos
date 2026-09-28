//! Verify the loader's copied event-log prefix against the live TPM after the
//! kernel owns CRB. This is local measurement consistency, not remote attestation.
const std = @import("std");
const handoff = @import("../boot/handoff.zig");
const tpm = @import("tpm2_hw.zig");
const log = @import("../../boot/tcg_event_log.zig");

pub fn verify() !bool {
    const info = handoff.capturedInfo() orelse return error.MissingBootInfo;
    const captured = info.boot_tpm orelse return false;
    const image = info.boot_image orelse return error.MissingBootImage;
    // tpm_info decoding bounds this page-aligned copy to the low identity map;
    // the physical frame allocator retains its complete extent before CRB init.
    const bytes: [*]const u8 = @ptrFromInt(captured.log_address);
    const replayed = try log.replay(bytes[0..captured.log_bytes], image);
    if (!std.mem.eql(u8, &replayed, &captured.pcr11)) return error.BootMeasurementChanged;
    const command = log.pcr.command();
    var response: [log.pcr.RESPONSE_BYTES]u8 = undefined;
    const actual = try log.pcr.parse(try tpm.execute(&command, &response, 2000));
    if (!std.mem.eql(u8, &actual, &captured.pcr11)) return error.BootMeasurementChanged;
    return true;
}
