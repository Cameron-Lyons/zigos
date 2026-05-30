const std = @import("std");

pub const kernel_boundary_role = "bootstrap_xhci_input_inventory_shim";
pub const publishes_full_input_service = false;
pub const usb_input_data_plane_exports_fail_closed = true;

pub const TRB_BYTES: u32 = 16;
pub const RING_ALIGNMENT_BYTES: u64 = 64;

pub const Error = error{
    KernelUsbInputDataPlaneDisabled,
    TooSmall,
    InvalidCapabilityLength,
    UnsupportedVersion,
    MissingPorts,
    MissingInterrupters,
    RingTooSmall,
    RingAddressUnaligned,
};

pub const InputRequest = struct {
    device_id: u64,
    report_len: u16,
};

pub const CapabilityRegisters = struct {
    capability_length: u8,
    interface_version: u16,
    max_device_slots: u8,
    max_interrupters: u16,
    max_ports: u8,
    doorbell_offset: u32,
    runtime_register_offset: u32,
};

pub const RingPlan = struct {
    command_ring_trbs: u32,
    event_ring_trbs: u32,
    command_ring_address: u64,
    event_ring_address: u64,
};

pub fn parseCapabilityRegisters(mmio: []const u8) Error!CapabilityRegisters {
    if (mmio.len < 0x20) return error.TooSmall;
    const capability_length = mmio[0];
    if (capability_length < 0x20) return error.InvalidCapabilityLength;

    const interface_version = readU16Le(mmio[2..4]);
    if (interface_version < 0x0090) return error.UnsupportedVersion;

    const hcsparams1 = readU32Le(mmio[4..8]);
    const max_device_slots: u8 = @truncate(hcsparams1);
    const max_interrupters: u16 = @truncate(hcsparams1 >> 8);
    const max_ports: u8 = @truncate(hcsparams1 >> 24);
    if (max_ports == 0) return error.MissingPorts;
    if (max_interrupters == 0) return error.MissingInterrupters;

    return .{
        .capability_length = capability_length,
        .interface_version = interface_version,
        .max_device_slots = max_device_slots,
        .max_interrupters = max_interrupters,
        .max_ports = max_ports,
        .doorbell_offset = readU32Le(mmio[0x14..0x18]),
        .runtime_register_offset = readU32Le(mmio[0x18..0x1C]),
    };
}

pub fn validateRingPlan(plan: RingPlan) Error!void {
    try validateRing(plan.command_ring_trbs, plan.command_ring_address);
    try validateRing(plan.event_ring_trbs, plan.event_ring_address);
}

pub fn rejectKernelInputReport(_: InputRequest) Error!void {
    return error.KernelUsbInputDataPlaneDisabled;
}

fn validateRing(trbs: u32, address: u64) Error!void {
    if (trbs < 16) return error.RingTooSmall;
    if (!aligned(address, RING_ALIGNMENT_BYTES)) return error.RingAddressUnaligned;
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

fn readU16Le(bytes: []const u8) u16 {
    return @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
}

fn readU32Le(bytes: []const u8) u32 {
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn writeU16Le(bytes: []u8, value: u16) void {
    bytes[0] = @truncate(value);
    bytes[1] = @truncate(value >> 8);
}

fn writeU32Le(bytes: []u8, value: u32) void {
    bytes[0] = @truncate(value);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value >> 16);
    bytes[3] = @truncate(value >> 24);
}

fn validCapabilityRegisters() [0x20]u8 {
    var mmio = [_]u8{0} ** 0x20;
    mmio[0] = 0x40;
    writeU16Le(mmio[2..4], 0x0110);
    writeU32Le(mmio[4..8], @as(u32, 32) | (@as(u32, 8) << 8) | (@as(u32, 12) << 24));
    writeU32Le(mmio[0x14..0x18], 0x2000);
    writeU32Le(mmio[0x18..0x1C], 0x1000);
    return mmio;
}

test "xHCI capability parser extracts controller limits" {
    const mmio = validCapabilityRegisters();
    const caps = try parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(@as(u8, 0x40), caps.capability_length);
    try std.testing.expectEqual(@as(u16, 0x0110), caps.interface_version);
    try std.testing.expectEqual(@as(u8, 32), caps.max_device_slots);
    try std.testing.expectEqual(@as(u16, 8), caps.max_interrupters);
    try std.testing.expectEqual(@as(u8, 12), caps.max_ports);
    try std.testing.expectEqual(@as(u32, 0x2000), caps.doorbell_offset);
    try std.testing.expectEqual(@as(u32, 0x1000), caps.runtime_register_offset);
}

test "xHCI capability parser rejects unsupported controllers" {
    var mmio = validCapabilityRegisters();
    writeU16Le(mmio[2..4], 0x0080);
    try std.testing.expectError(error.UnsupportedVersion, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(mmio[4..8], @as(u32, 32) | (@as(u32, 8) << 8));
    try std.testing.expectError(error.MissingPorts, parseCapabilityRegisters(mmio[0..]));
}

test "xHCI ring plan validates command and event ring alignment" {
    try validateRingPlan(.{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });

    try std.testing.expectError(error.RingAddressUnaligned, validateRingPlan(.{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1001,
        .event_ring_address = 0x2000,
    }));
}

test "xHCI kernel shim rejects direct USB input reports" {
    try std.testing.expectError(error.KernelUsbInputDataPlaneDisabled, rejectKernelInputReport(.{
        .device_id = 0x8086_A0ED_0000,
        .report_len = 8,
    }));
}
