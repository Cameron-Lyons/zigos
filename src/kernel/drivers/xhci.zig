const std = @import("std");

pub const kernel_boundary_role = "bootstrap_xhci_input_inventory_shim";
pub const publishes_full_input_service = false;
pub const usb_input_data_plane_exports_fail_closed = true;

pub const TRB_BYTES: u32 = 16;
pub const RING_ALIGNMENT_BYTES: u64 = 64;
pub const HID_BOOT_KEYBOARD_REPORT_BYTES: usize = 8;
pub const HID_BOOT_KEY_SLOTS: usize = 6;
pub const HID_EVENT_QUEUE_CAPACITY: usize = 8;

pub const Error = error{
    KernelUsbInputDataPlaneDisabled,
    TooSmall,
    InvalidCapabilityLength,
    UnsupportedVersion,
    MissingPorts,
    MissingInterrupters,
    RingTooSmall,
    RingAddressUnaligned,
    ReportTooLarge,
    EventRingFull,
    EventRingEmpty,
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

pub const HidReport = struct {
    device_id: u64,
    endpoint_id: u8,
    report_len: usize,
    report: [HID_BOOT_KEYBOARD_REPORT_BYTES]u8,

    pub fn reportSlice(self: *const HidReport) []const u8 {
        return self.report[0..self.report_len];
    }

    pub fn modifiers(self: *const HidReport) u8 {
        return if (self.report_len == HID_BOOT_KEYBOARD_REPORT_BYTES) self.report[0] else 0;
    }

    pub fn keySlots(self: *const HidReport) []const u8 {
        if (self.report_len != HID_BOOT_KEYBOARD_REPORT_BYTES) return &.{};
        return self.report[2..8];
    }
};

pub const HidController = struct {
    ring_plan: RingPlan,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    reports: [HID_EVENT_QUEUE_CAPACITY]HidReport = [_]HidReport{emptyHidReport()} ** HID_EVENT_QUEUE_CAPACITY,

    pub fn init(ring_plan: RingPlan) Error!HidController {
        try validateRingPlan(ring_plan);
        return .{ .ring_plan = ring_plan };
    }

    pub fn enqueueInterruptReport(self: *HidController, report: HidReport) Error!void {
        if (report.report_len == 0 or report.report_len > report.report.len) return error.ReportTooLarge;
        if (self.count == self.reports.len) return error.EventRingFull;
        self.reports[self.tail] = report;
        self.tail = (self.tail + 1) % self.reports.len;
        self.count += 1;
    }

    pub fn pollHidReport(self: *HidController) Error!HidReport {
        if (self.count == 0) return error.EventRingEmpty;
        const report = self.reports[self.head];
        self.reports[self.head] = emptyHidReport();
        self.head = (self.head + 1) % self.reports.len;
        self.count -= 1;
        return report;
    }
};

pub fn bootKeyboardReport(device_id: u64, endpoint_id: u8, modifiers: u8, keys: []const u8) Error!HidReport {
    if (keys.len > HID_BOOT_KEY_SLOTS) return error.ReportTooLarge;
    var report = HidReport{
        .device_id = device_id,
        .endpoint_id = endpoint_id,
        .report_len = HID_BOOT_KEYBOARD_REPORT_BYTES,
        .report = [_]u8{0} ** HID_BOOT_KEYBOARD_REPORT_BYTES,
    };
    report.report[0] = modifiers;
    @memcpy(report.report[2..][0..keys.len], keys);
    return report;
}

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

fn emptyHidReport() HidReport {
    return .{
        .device_id = 0,
        .endpoint_id = 0,
        .report_len = 0,
        .report = [_]u8{0} ** HID_BOOT_KEYBOARD_REPORT_BYTES,
    };
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

test "xHCI HID controller queues interrupt keyboard reports" {
    var controller = try HidController.init(.{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });
    const report = try bootKeyboardReport(0x8086_A0ED_0001, 1, 0x02, &.{ 0x04, 0x05 });
    try controller.enqueueInterruptReport(report);
    const polled = try controller.pollHidReport();
    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), polled.device_id);
    try std.testing.expectEqual(@as(u8, 0x02), polled.modifiers());
    try std.testing.expectEqual(@as(u8, 0x04), polled.keySlots()[0]);
    try std.testing.expectEqual(@as(u8, 0x05), polled.keySlots()[1]);
    try std.testing.expectError(error.EventRingEmpty, controller.pollHidReport());
}

test "xHCI HID controller rejects oversized reports and full rings" {
    var controller = try HidController.init(.{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });
    try std.testing.expectError(error.ReportTooLarge, bootKeyboardReport(0x8086_A0ED_0001, 1, 0, &.{ 1, 2, 3, 4, 5, 6, 7 }));

    const report = try bootKeyboardReport(0x8086_A0ED_0001, 1, 0, &.{0x04});
    for (0..HID_EVENT_QUEUE_CAPACITY) |_| {
        try controller.enqueueInterruptReport(report);
    }
    try std.testing.expectError(error.EventRingFull, controller.enqueueInterruptReport(report));
}
