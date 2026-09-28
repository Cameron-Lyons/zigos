//! TCG EFI Protocol 2.0 interface. Measurements use the active SHA-256 bank,
//! record an EV_EVENT_TAG in PCR 11, and reconcile final events after exit.
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
    final_table: []const u8,
    final_snapshot: log.FinalSnapshot,

    // Call only after successful ExitBootServices, before reclaiming firmware
    // memory or switching page tables. No firmware calls or allocations.
    pub fn finish(self: *Capture, boot_image: image.Info) !void {
        const buffer = @as([*]u8, @ptrCast(self.pages.ptr))[0..log.MAX_BYTES];
        const merged = try self.final_snapshot.merge(buffer, self.info.log_bytes, self.final_table);
        const bytes = buffer[0..merged.bytes];
        if (!std.mem.eql(u8, &(try log.replay(bytes, boot_image)), &self.info.pcr11)) return error.TpmMeasurementMismatch;
        _ = try log.replayExit(bytes, merged.events);
        self.info.log_bytes = @intCast(merged.bytes);
        self.info.final_events = merged.events;
    }
};

const final_guid align(8) = uefi.Guid{ .time_low = 0x1e2ed096, .time_mid = 0x30e2, .time_high_and_version = 0x4254, .clock_seq_high_and_reserved = 0xbd, .clock_seq_low = 0x89, .node = .{ 0x86, 0x3b, 0xbe, 0xf8, 0x23, 0x25 } };

pub fn capture(boot: *uefi.tables.BootServices, system: *const uefi.tables.SystemTable, info: image.Info) !?Capture {
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
    // Allocate and acquire bounds BEFORE GetEventLog. There are no firmware
    // calls between that snapshot and recording its overlapping final events.
    const map_info = try boot.getMemoryMapInfo();
    const count = try std.math.add(usize, map_info.len, 16);
    const map_bytes = try std.math.mul(usize, count, map_info.descriptor_size);
    const raw = try boot.allocatePool(.loader_data, map_bytes);
    defer boot.freePool(raw.ptr) catch {};
    const map = try boot.getMemoryMap(@alignCast(raw));
    var start: u64 = 0;
    var last: u64 = 0;
    var truncated: u8 = 1;
    if (protocol.event_log(protocol, 2, &start, &last, &truncated) != .success or truncated != 0 or start == 0 or last <= start)
        return error.InvalidTpmEventLog;
    const source_limit = try allocatedBytes(map, start);
    if (last - start >= source_limit) return error.InvalidTpmEventLog;
    const source: [*]const u8 = @ptrFromInt(start);
    const used = try log.usedLength(source[0..source_limit], @intCast(last - start));
    @memcpy(buffer[0..used], source[0..used]);
    const final_address = try finalAddress(system);
    const final_limit = try allocatedBytes(map, final_address);
    const final_table = @as([*]const u8, @ptrFromInt(final_address))[0..final_limit];
    const final_snapshot = try log.FinalSnapshot.init(buffer[0..used], final_table);
    const expected = try log.replay(buffer[0..used], info);
    const command = log.pcr.command(log.pcr.INDEX);
    var response: [log.pcr.RESPONSE_BYTES]u8 = @splat(0);
    if (protocol.submit(protocol, command.len, &command, response.len, &response) != .success) return error.TpmPcrReadFailed;
    const response_bytes = std.mem.readInt(u32, response[2..6], .big);
    if (response_bytes > response.len) return error.TpmPcrReadFailed;
    const actual = try log.pcr.parse(log.pcr.INDEX, response[0..response_bytes]);
    if (!std.mem.eql(u8, &actual, &expected)) return error.TpmMeasurementMismatch;
    return .{ .pages = pages, .info = .{ .log_address = @intFromPtr(pages.ptr), .log_bytes = @intCast(used), .final_events = 0, .pcr11 = actual }, .final_table = final_table, .final_snapshot = final_snapshot };
}

fn finalAddress(system: *const uefi.tables.SystemTable) !u64 {
    if (system.number_of_table_entries > 1024) return error.InvalidTpmEventLog;
    var result: ?u64 = null;
    for (system.configuration_table[0..system.number_of_table_entries]) |entry| {
        if (!uefi.Guid.eql(entry.vendor_guid, final_guid)) continue;
        if (result != null) return error.InvalidTpmEventLog;
        result = @intFromPtr(entry.vendor_table);
    }
    return result orelse error.MissingFinalTpmEvents;
}

// Bound all firmware-log reads to its containing allocated memory descriptor.
// GetEventLog supplies a last-entry pointer, not the backing allocation size.
fn allocatedBytes(map: uefi.tables.MemoryMapSlice, start: u64) !usize {
    if (start == 0) return error.InvalidTpmEventLog;
    var iter = map.iterator();
    while (iter.next()) |entry| {
        const length = try std.math.mul(u64, entry.number_of_pages, 4096);
        const end = try std.math.add(u64, entry.physical_start, length);
        if (start < entry.physical_start or start >= end) continue;
        if (entry.type != .boot_services_data and entry.type != .acpi_reclaim_memory and entry.type != .acpi_memory_nvs and
            entry.type != .loader_data and entry.type != .runtime_services_data)
            return error.InvalidTpmEventLog;
        const limit = @min(log.MAX_BYTES, end - start);
        return @intCast(limit);
    }
    return error.InvalidTpmEventLog;
}

comptime {
    if (@sizeOf(Capability) != 36 or @offsetOf(Capability, "active") != 32 or @offsetOf(Protocol, "extend") != 16)
        @compileError("invalid x86-64 TCG2 protocol layout");
}

test "TCG2 firmware log bounds reject free device missing and overflowing memory" {
    var descriptor = uefi.tables.MemoryDescriptor{
        .type = .acpi_memory_nvs,
        .physical_start = 0x4000000,
        .virtual_start = 0,
        .number_of_pages = 128,
        .attribute = @bitCast(@as(u64, 0)),
    };
    const map = uefi.tables.MemoryMapSlice{ .ptr = @ptrCast(&descriptor), .info = .{ .key = @enumFromInt(0), .descriptor_size = @sizeOf(uefi.tables.MemoryDescriptor), .descriptor_version = 1, .len = 1 } };
    try std.testing.expectEqual(@as(usize, log.MAX_BYTES), try allocatedBytes(map, descriptor.physical_start));
    try std.testing.expectEqual(@as(usize, 1), try allocatedBytes(map, descriptor.physical_start + 128 * 4096 - 1));
    for ([_]u64{ 0, descriptor.physical_start - 1, descriptor.physical_start + 128 * 4096 }) |address|
        try std.testing.expectError(error.InvalidTpmEventLog, allocatedBytes(map, address));
    for ([_]uefi.tables.MemoryType{ .conventional_memory, .memory_mapped_io, .reserved_memory_type, .boot_services_code }) |kind| {
        descriptor.type = kind;
        try std.testing.expectError(error.InvalidTpmEventLog, allocatedBytes(map, descriptor.physical_start));
    }
    descriptor.type = .runtime_services_data;
    try std.testing.expectEqual(@as(usize, log.MAX_BYTES), try allocatedBytes(map, descriptor.physical_start));
    descriptor.number_of_pages = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, allocatedBytes(map, descriptor.physical_start));
    descriptor.number_of_pages = 1;
    descriptor.physical_start = std.math.maxInt(u64) - 10;
    try std.testing.expectError(error.Overflow, allocatedBytes(map, descriptor.physical_start));
}

test "TCG2 final table discovery requires one bounded unambiguous firmware entry" {
    var entries = [_]uefi.tables.ConfigurationTable{
        .{ .vendor_guid = final_guid, .vendor_table = @ptrFromInt(0x4000000) },
        .{ .vendor_guid = final_guid, .vendor_table = @ptrFromInt(0x5000000) },
    };
    var system: uefi.tables.SystemTable = undefined;
    system.configuration_table = &entries;
    system.number_of_table_entries = 0;
    try std.testing.expectError(error.MissingFinalTpmEvents, finalAddress(&system));
    system.number_of_table_entries = 1;
    try std.testing.expectEqual(@as(u64, 0x4000000), try finalAddress(&system));
    system.number_of_table_entries = 2;
    try std.testing.expectError(error.InvalidTpmEventLog, finalAddress(&system));
    system.number_of_table_entries = 1025;
    try std.testing.expectError(error.InvalidTpmEventLog, finalAddress(&system));
}
