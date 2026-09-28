//! TCG EFI Protocol 2.0 interface. Measurements use the active SHA-256 bank,
//! record an EV_EVENT_TAG in PCR 11, and retain a bounded pre-exit log snapshot.
//! https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/
const std = @import("std");
const uefi = std.os.uefi;
const image = @import("image_info.zig");
const tpm_info = @import("tpm_info.zig");
const log = tpm_info.log;
const Version = extern struct { major: u8, minor: u8 };
const Capability = extern struct {
    size: u8,
    structure: Version,
    protocol: Version,
    hashes: u32,
    logs: u32,
    present: u8,
    max_command: u16,
    max_response: u16,
    manufacturer: u32,
    banks: u32,
    active: u32,
};
const Protocol = extern struct {
    capability: *const fn (*Protocol, *Capability) callconv(uefi.cc) uefi.Status,
    event_log: *const fn (*Protocol, u32, *u64, *u64, *u8) callconv(uefi.cc) uefi.Status,
    extend: *const fn (*Protocol, u64, u64, u64, [*]const u8) callconv(uefi.cc) uefi.Status,
    submit: *const fn (*Protocol, u32, [*]const u8, u32, [*]u8) callconv(uefi.cc) uefi.Status,
    active_banks: *const fn (*Protocol, *u32) callconv(uefi.cc) uefi.Status,
    set_banks: usize,
    bank_result: usize,

    pub const guid align(8) = uefi.Guid{ .time_low = 0x607f766c, .time_mid = 0x7455, .time_high_and_version = 0x42be, .clock_seq_high_and_reserved = 0x93, .clock_seq_low = 0x0b, .node = .{ 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } };
};

pub const Capture = struct {
    pages: []align(4096) uefi.Page,
    info: tpm_info.Info,
};

pub fn capture(boot: *uefi.tables.BootServices, info: image.Info) !?Capture {
    const protocol = try boot.locateProtocol(Protocol, null) orelse return null;
    var capability: Capability = std.mem.zeroes(Capability);
    capability.size = @sizeOf(Capability);
    if (protocol.capability(protocol, &capability) != .success) return error.TpmCapabilityFailed;
    if (capability.size < @sizeOf(Capability) or capability.structure.major != 1 or capability.structure.minor < 1 or
        capability.protocol.major != 1 or capability.protocol.minor < 1 or capability.present > 1)
        return error.UnsupportedTpmMeasurement;
    if (capability.present == 0) return null;
    if (capability.hashes & 2 == 0 or capability.logs & 2 == 0 or capability.max_command < 20 or capability.max_response < log.pcr.RESPONSE_BYTES)
        return error.UnsupportedTpmMeasurement;
    var active: u32 = 0;
    if (protocol.active_banks(protocol, &active) != .success or active & 2 == 0) return error.UnsupportedTpmMeasurement;
    const pages = try boot.allocatePages(.{ .max_address = @ptrFromInt(image.IDENTITY_LIMIT) }, .loader_data, log.MAX_BYTES / 4096);
    errdefer boot.freePages(pages) catch {};
    const buffer: []u8 = @as([*]u8, @ptrCast(pages.ptr))[0..log.MAX_BYTES];
    const description = log.description(info);
    const event = log.event(info);
    // A failed call may already have extended a PCR. Never retry or report a
    // successful measured boot after a partial operation or a full event log.
    if (protocol.extend(protocol, 0, @intFromPtr(&description), description.len, &event) != .success) return error.TpmMeasurementFailed;
    var start: u64 = 0;
    var last: u64 = 0;
    var truncated: u8 = 1;
    if (protocol.event_log(protocol, 2, &start, &last, &truncated) != .success or truncated != 0 or start == 0 or last <= start)
        return error.InvalidTpmEventLog;
    const source_limit = try availableLogBytes(boot, start, last);
    const source: [*]const u8 = @ptrFromInt(start);
    const used = try log.usedLength(source[0..source_limit], @intCast(last - start));
    @memcpy(buffer[0..used], source[0..used]);
    const expected = try log.replay(buffer[0..used], info);
    const command = log.pcr.command();
    var response: [log.pcr.RESPONSE_BYTES]u8 = @splat(0);
    if (protocol.submit(protocol, command.len, &command, response.len, &response) != .success) return error.TpmPcrReadFailed;
    const response_bytes = std.mem.readInt(u32, response[2..6], .big);
    if (response_bytes > response.len) return error.TpmPcrReadFailed;
    const actual = try log.pcr.parse(response[0..response_bytes]);
    if (!std.mem.eql(u8, &actual, &expected)) return error.TpmMeasurementMismatch;
    return .{ .pages = pages, .info = .{ .log_address = @intFromPtr(pages.ptr), .log_bytes = @intCast(used), .pcr11 = actual } };
}

// Bound all firmware-log reads to its containing allocated memory descriptor.
// GetEventLog supplies a last-entry pointer, not the backing allocation size.
fn availableLogBytes(boot: *uefi.tables.BootServices, start: u64, last: u64) !usize {
    const info = try boot.getMemoryMapInfo();
    const count = try std.math.add(usize, info.len, 16);
    const bytes = try std.math.mul(usize, count, info.descriptor_size);
    const raw = try boot.allocatePool(.loader_data, bytes);
    defer boot.freePool(raw.ptr) catch {};
    const map = try boot.getMemoryMap(@alignCast(raw));
    var iter = map.iterator();
    while (iter.next()) |entry| {
        const length = try std.math.mul(u64, entry.number_of_pages, 4096);
        const end = try std.math.add(u64, entry.physical_start, length);
        if (start < entry.physical_start or start >= end) continue;
        if (entry.type != .boot_services_data and entry.type != .acpi_reclaim_memory and entry.type != .acpi_memory_nvs and entry.type != .loader_data)
            return error.InvalidTpmEventLog;
        const limit = @min(log.MAX_BYTES, end - start);
        if (last - start >= limit) return error.InvalidTpmEventLog;
        return @intCast(limit);
    }
    return error.InvalidTpmEventLog;
}

comptime {
    if (@sizeOf(Capability) != 36 or @offsetOf(Capability, "active") != 32 or @offsetOf(Protocol, "extend") != 16)
        @compileError("invalid x86-64 TCG2 protocol layout");
}
