//! xHCI host-controller protocol shared by the kernel driver and its models:
//! the register vocabulary and error set, ring-plan validation, the boot
//! keyboard report contract and one namespace per concern.

const std = @import("std");

pub const caps = @import("xhci/caps.zig");
pub const controller = @import("xhci/controller.zig");
pub const trb = @import("xhci/trb.zig");
pub const context = @import("xhci/context.zig");
pub const dma_plan = @import("xhci/dma_plan.zig");
pub const descriptors = @import("usb/descriptors.zig");

const UsbBootKeyboardConfiguration = descriptors.UsbBootKeyboardConfiguration;
const UsbDeviceDescriptor = descriptors.UsbDeviceDescriptor;

pub const TRB_BYTES: u32 = 16;
pub const RING_ALIGNMENT_BYTES: u64 = 64;
pub const ERST_TABLE_ALIGNMENT_BYTES: u64 = 64;
pub const XHCI_PAGE_BYTES: u64 = 4096;
pub const DCBAA_ENTRY_BYTES: u32 = 8;
pub const DEVICE_CONTEXT_ENTRIES: u32 = 32;
pub const INPUT_CONTEXT_ENTRIES: u32 = 33;
pub const SCRATCHPAD_ARRAY_ENTRY_BYTES: u32 = 8;
pub const COMMAND_RING_TRBS: u32 = 64;
pub const EVENT_RING_TRBS: u32 = 64;
pub const TRANSFER_RING_TRBS: u32 = 16;
pub const INTERRUPT_REPORT_BUFFER_STRIDE: u32 = 64;
pub const EVENT_RING_SEGMENT_TABLE_ENTRIES: u32 = 1;
pub const MAX_CONTROLLER_DMA_REGIONS: usize = 8;
pub const HID_BOOT_KEYBOARD_REPORT_BYTES: usize = 8;
pub const HID_BOOT_KEY_SLOTS: usize = 6;
pub const HARDWARE_HID_REPORT_QUEUE_CAPACITY: usize = 64;
pub const BOOT_KEYBOARD_REPORT_PUBLISHER_SIZE_CEILING_BYTES: usize = 1_584;
pub const USB_DESCRIPTOR_DEVICE: u8 = 0x01;
pub const USB_DESCRIPTOR_CONFIGURATION: u8 = 0x02;
pub const USB_DESCRIPTOR_INTERFACE: u8 = 0x04;
pub const USB_DESCRIPTOR_ENDPOINT: u8 = 0x05;
pub const USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION: u8 = 0x30;
pub const USB_DESCRIPTOR_HID: u8 = 0x21;
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_HID_SUBCLASS_BOOT: u8 = 0x01;
pub const USB_HID_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_REQUEST_SET_CONFIGURATION: u8 = 0x09;
pub const USB_REQUEST_SET_PROTOCOL: u8 = 0x0B;
pub const USB_ENDPOINT_DIRECTION_IN: u8 = 0x80;
pub const USB_ENDPOINT_TRANSFER_INTERRUPT: u8 = 0x03;
pub const MAX_DEVICE_SLOTS: usize = 32;
pub const USB_DEVICE_DESCRIPTOR_PREFIX_BYTES: usize = 8;
pub const USB_DEVICE_DESCRIPTOR_BYTES: usize = 18;
pub const USB_CONFIGURATION_DESCRIPTOR_BYTES: usize = 9;
pub const USB_ENUMERATION_BUFFER_BYTES: u32 = 64 * 1024;
pub const XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES: u64 = 64 * 1024;
pub const ENDPOINT_ZERO_DCI: u5 = 1;

pub const CAPABILITY_REGISTERS_BYTES: usize = 0x20;
pub const MAX_EXTENDED_CAPABILITY_OFFSET: u32 = @as(u32, std.math.maxInt(u16)) << 2;
pub const MAX_EXTENDED_CAPABILITIES: usize = 64;
pub const SUPPORTED_PROTOCOLS_SIZE_CEILING_BYTES: usize = 452;
pub const CONTROLLER_HALT_TIMEOUT_MILLISECONDS: u64 = 16;
pub const CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS: u64 = 1_000;

comptime {
    if (HID_BOOT_KEYBOARD_REPORT_BYTES > std.math.maxInt(u8) or
        HARDWARE_HID_REPORT_QUEUE_CAPACITY > std.math.maxInt(u8) or
        MAX_DEVICE_SLOTS > std.math.maxInt(u8))
    {
        @compileError("xHCI input queues no longer fit compact metadata");
    }
}

pub const ContextSize = enum(u8) {
    bytes_32 = 32,
    bytes_64 = 64,

    pub fn byteCount(self: ContextSize) u32 {
        return @backingInt(self);
    }
};

pub const DOORBELL_OFFSET_ALIGNMENT_MASK: u32 = 0x3;
pub const RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK: u32 = 0x1F;
pub const TEST_CAPABILITY_LENGTH: u8 = 0x40;
pub const TEST_INTERFACE_VERSION: u16 = 0x0110;
pub const TEST_MAX_DEVICE_SLOTS: u8 = 32;
pub const TEST_MAX_INTERRUPTERS: u16 = 8;
pub const TEST_MAX_PORTS: u8 = 12;
pub const TEST_MAX_SCRATCHPAD_BUFFERS: u16 = 33;
pub const TEST_CONTEXT_SIZE: ContextSize = .bytes_64;
pub const TEST_DOORBELL_OFFSET: u32 = 0x2000;
pub const TEST_RUNTIME_REGISTER_OFFSET: u32 = 0x1000;
const TEST_RING_TRBS: u32 = COMMAND_RING_TRBS;
const TEST_COMMAND_RING_ADDRESS: u64 = 0x1000;
const TEST_EVENT_RING_ADDRESS: u64 = 0x2000;
const TEST_UNALIGNED_COMMAND_RING_ADDRESS: u64 = TEST_COMMAND_RING_ADDRESS + 1;

pub const Error = error{
    TooSmall,
    InvalidCapabilityLength,
    UnsupportedVersion,
    Unsupported32BitAddressing,
    InvalidScratchpadRestore,
    MissingDeviceSlots,
    MissingPorts,
    MissingInterrupters,
    RingTooSmall,
    RingAddressInvalid,
    RingAddressUnaligned,
    RingAddressOverlap,
    RingAddressOverflow,
    DmaArenaBaseInvalid,
    DmaSlotCountInvalid,
    DmaLayoutOverflow,
    DmaBufferTooSmall,
    DmaAddressOutsidePlan,
    DmaFrameCountOverflow,
    UnsupportedPageSize,
    DmaProgrammingUnavailable,
    DmaRegisterRejected,
    ReportTooLarge,
    EventRingFull,
    EventRingEmpty,
    InvalidUsbDescriptor,
    MissingBootKeyboardInterface,
    MissingInterruptInEndpoint,
    UnknownHidDevice,
    EndpointMismatch,
    EndpointContextStateInvalid,
    InvalidBootKeyboardReport,
    InvalidPort,
    PortNotConnected,
    PortAlreadyAssigned,
    DeviceSlotUnavailable,
    InvalidDeviceSlot,
    DeviceNotAddressed,
    EndpointNotConfigured,
    MissingDoorbellRegisters,
    MissingRuntimeRegisters,
    InvalidDoorbellOffset,
    InvalidRuntimeRegisterOffset,
    ExtendedCapabilityOutOfRange,
    ExtendedCapabilityTraversalLimit,
    MissingSupportedProtocols,
    InvalidSupportedProtocol,
    OverlappingSupportedProtocolPorts,
    MissingPortProtocol,
    InvalidProtocolSpeed,
    InvalidInputContext,
    FirmwareOwnsController,
    FirmwareOwnershipTimeout,
    LegacyCapabilityChanged,
    OwnershipRequestRejected,
    ControllerNotReadyTimeout,
    ControllerHaltTimeout,
    ControllerResetTimeout,
    ControllerResetFailed,
    ControllerStartUnavailable,
    ControllerStartTimeout,
    ControllerStartFailed,
    EventRingStateInvalid,
    CommandRingStateInvalid,
    TrbRingStateInvalid,
    InvalidPortStatus,
    ControllerConfigurationUnavailable,
    DeviceSlotConfigurationRejected,
};

pub const CapabilityRegisters = struct {
    capability_length: u8,
    interface_version: u16,
    max_device_slots: u8,
    max_interrupters: u16,
    max_ports: u8,
    supports_64_bit_addressing: bool,
    context_size: ContextSize,
    max_scratchpad_buffers: u16,
    scratchpad_restore: bool,
    extended_capability_offset: u32,
    doorbell_offset: u32,
    runtime_register_offset: u32,
};

pub const LegacyOwnership = enum(u8) {
    not_present,
    firmware_released,
    os_owned,
};

pub const LegacySupport = struct {
    offset: u32,
    firmware_owned: bool,
    os_owned: bool,
};

pub const RingPlan = struct {
    command_ring_trbs: u32,
    event_ring_trbs: u32,
    command_ring_address: u64,
    event_ring_address: u64,
};

pub const ProtocolKind = enum(u8) {
    usb2,
    usb3,
};

pub const PortProtocol = struct {
    kind: ProtocolKind,
    slot_type: u5,
    speed_ids: u16 = 0,
    low_speed_ids: u16 = 0,
    full_speed_ids: u16 = 0,
    high_speed_ids: u16 = 0,
};

/// Boot keyboard input delivered through a controller's event ring. Consumers
/// only count delivered events.
pub const InputProof = struct {
    port_id: u8,
    slot_id: u8,
    event_count: usize,
};

pub const HardwareBootKeyboardReport = struct {
    sequence: u64 = 0,
    port_id: u8 = 0,
    slot_id: u8 = 0,
    interface_number: u8 = 0,
    endpoint_id: u8 = 0,
    vendor_id: u16 = 0,
    product_id: u16 = 0,
    bytes: [HID_BOOT_KEYBOARD_REPORT_BYTES]u8 = @as([HID_BOOT_KEYBOARD_REPORT_BYTES]u8, @splat(0)),
};

pub const BootKeyboardReportPublisher = struct {
    sequence: u64 = 0,
    latest: ?HardwareBootKeyboardReport = null,
    head: u8 = 0,
    tail: u8 = 0,
    count: u8 = 0,
    reports: [HARDWARE_HID_REPORT_QUEUE_CAPACITY]HardwareBootKeyboardReport =
        @as([HARDWARE_HID_REPORT_QUEUE_CAPACITY]HardwareBootKeyboardReport, @splat(.{})),

    pub fn publish(
        self: *BootKeyboardReportPublisher,
        port_id: u8,
        slot_id: u8,
        keyboard: UsbBootKeyboardConfiguration,
        descriptor: UsbDeviceDescriptor,
        report: []const u8,
    ) Error!HardwareBootKeyboardReport {
        if (port_id == 0 or slot_id == 0 or keyboard.endpoint_id == 0 or
            report.len != HID_BOOT_KEYBOARD_REPORT_BYTES or
            report.len > keyboard.max_packet_size)
        {
            return error.InvalidBootKeyboardReport;
        }
        if (self.count == self.reports.len) return error.EventRingFull;
        self.sequence = if (self.sequence == std.math.maxInt(u64)) 1 else self.sequence + 1;
        var published = HardwareBootKeyboardReport{
            .sequence = self.sequence,
            .port_id = port_id,
            .slot_id = slot_id,
            .interface_number = keyboard.interface_number,
            .endpoint_id = keyboard.endpoint_id,
            .vendor_id = descriptor.vendor_id,
            .product_id = descriptor.product_id,
            .bytes = @as([HID_BOOT_KEYBOARD_REPORT_BYTES]u8, @splat(0)),
        };
        @memcpy(published.bytes[0..], report);
        self.reports[self.tail] = published;
        self.tail = @intCast((@as(usize, self.tail) + 1) % self.reports.len);
        self.count += 1;
        self.latest = published;
        return published;
    }

    pub fn poll(self: *BootKeyboardReportPublisher) ?HardwareBootKeyboardReport {
        if (self.count == 0) return null;
        const report = self.reports[self.head];
        self.reports[self.head] = .{};
        self.head = @intCast((@as(usize, self.head) + 1) % self.reports.len);
        self.count -= 1;
        return report;
    }

    pub fn pendingCount(self: *const BootKeyboardReportPublisher) usize {
        return @intCast(self.count);
    }

    pub fn hasCapacity(self: *const BootKeyboardReportPublisher, additional: usize) bool {
        return additional <= self.reports.len - @as(usize, self.count);
    }

    pub fn latestAfter(
        self: *const BootKeyboardReportPublisher,
        observed_sequence: u64,
    ) ?HardwareBootKeyboardReport {
        const report = self.latest orelse return null;
        return if (report.sequence == observed_sequence) null else report;
    }

    pub fn clearPort(self: *BootKeyboardReportPublisher, port_id: u8) void {
        var retained_reports = @as([HARDWARE_HID_REPORT_QUEUE_CAPACITY]HardwareBootKeyboardReport, @splat(.{}));
        var retained: usize = 0;
        var offset: usize = 0;
        while (offset < @as(usize, self.count)) : (offset += 1) {
            const report = self.reports[(@as(usize, self.head) + offset) % self.reports.len];
            if (report.port_id == port_id) continue;
            retained_reports[retained] = report;
            retained += 1;
        }
        self.reports = retained_reports;
        self.head = 0;
        self.tail = @intCast(retained % self.reports.len);
        self.count = @intCast(retained);
        if (self.latest) |report| {
            if (report.port_id == port_id) {
                self.latest = if (retained == 0) null else self.reports[retained - 1];
            }
        }
    }

    comptime {
        if (@sizeOf(@This()) > BOOT_KEYBOARD_REPORT_PUBLISHER_SIZE_CEILING_BYTES) {
            @compileError("xHCI boot keyboard report publisher exceeds its compact size ceiling");
        }
    }
};

/// A complete boot keyboard configuration descriptor for one interrupt-IN endpoint.
pub fn bootKeyboardConfigurationDescriptor(endpoint_id: u8) [34]u8 {
    return .{
        9, USB_DESCRIPTOR_CONFIGURATION, 34,                                               0,                               1,                              1,             0,                     0x80,                      50,
        9, USB_DESCRIPTOR_INTERFACE,     0,                                                0,                               1,                              USB_CLASS_HID, USB_HID_SUBCLASS_BOOT, USB_HID_PROTOCOL_KEYBOARD, 0,
        9, USB_DESCRIPTOR_HID,           0x11,                                             0x01,                            0,                              1,             0x22,                  63,                        0,
        7, USB_DESCRIPTOR_ENDPOINT,      USB_ENDPOINT_DIRECTION_IN | (endpoint_id & 0x0f), USB_ENDPOINT_TRANSFER_INTERRUPT, HID_BOOT_KEYBOARD_REPORT_BYTES, 0,             10,
    };
}

/// Reference capability layout shared by the modeled controller and tests.
pub fn defaultCapabilityRegisters() CapabilityRegisters {
    return .{
        .capability_length = TEST_CAPABILITY_LENGTH,
        .interface_version = TEST_INTERFACE_VERSION,
        .max_device_slots = TEST_MAX_DEVICE_SLOTS,
        .max_interrupters = TEST_MAX_INTERRUPTERS,
        .max_ports = TEST_MAX_PORTS,
        .supports_64_bit_addressing = true,
        .context_size = TEST_CONTEXT_SIZE,
        .max_scratchpad_buffers = TEST_MAX_SCRATCHPAD_BUFFERS,
        .scratchpad_restore = true,
        .extended_capability_offset = 0,
        .doorbell_offset = TEST_DOORBELL_OFFSET,
        .runtime_register_offset = TEST_RUNTIME_REGISTER_OFFSET,
    };
}

pub fn validateRingPlan(plan: RingPlan) Error!void {
    try validateRing(plan.command_ring_trbs, plan.command_ring_address);
    try validateRing(plan.event_ring_trbs, plan.event_ring_address);
    const command_end = try ringEndAddress(plan.command_ring_address, plan.command_ring_trbs);
    const event_end = try ringEndAddress(plan.event_ring_address, plan.event_ring_trbs);
    if (plan.command_ring_address < event_end and plan.event_ring_address < command_end) {
        return error.RingAddressOverlap;
    }
}

pub fn validateRing(trbs: u32, address: u64) Error!void {
    if (trbs < 16) return error.RingTooSmall;
    if (address == 0) return error.RingAddressInvalid;
    if (!aligned(address, RING_ALIGNMENT_BYTES)) return error.RingAddressUnaligned;
}

pub fn ringEndAddress(address: u64, trbs: u32) Error!u64 {
    return std.math.add(u64, address, ringByteLength(trbs)) catch error.RingAddressOverflow;
}

fn ringByteLength(trbs: u32) u64 {
    return @as(u64, trbs) * TRB_BYTES;
}

pub fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

pub fn maxDeviceSlotsU8() u8 {
    return @intCast(MAX_DEVICE_SLOTS);
}

test "xHCI ring plan validates command and event ring alignment" {
    try validateRingPlan(.{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });

    try std.testing.expectError(error.RingAddressUnaligned, validateRingPlan(.{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_UNALIGNED_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    }));

    try std.testing.expectError(error.RingAddressInvalid, validateRingPlan(.{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = 0,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    }));
    try std.testing.expectError(error.RingAddressOverlap, validateRingPlan(.{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x1200,
    }));
    try std.testing.expectError(error.RingAddressOverflow, validateRingPlan(.{
        .command_ring_trbs = 16,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = std.math.maxInt(u64) - (RING_ALIGNMENT_BYTES - 1),
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    }));
}

test "xHCI hardware keyboard publisher preserves queued port-scoped reports" {
    const keyboard = UsbBootKeyboardConfiguration{
        .configuration_value = 1,
        .interface_number = 4,
        .endpoint_id = 1,
        .device_context_index = 3,
        .max_packet_size = HID_BOOT_KEYBOARD_REPORT_BYTES,
        .max_burst_size = 0,
        .interval = 9,
        .max_esit_payload = HID_BOOT_KEYBOARD_REPORT_BYTES,
    };
    const descriptor = UsbDeviceDescriptor{
        .usb_version_bcd = 0x0200,
        .device_class = 0,
        .device_subclass = 0,
        .device_protocol = 0,
        .endpoint_zero_max_packet_size = 64,
        .vendor_id = 0x046D,
        .product_id = 0xC31C,
        .device_version_bcd = 0x6400,
        .manufacturer_string_index = 1,
        .product_string_index = 2,
        .serial_number_string_index = 0,
        .configuration_count = 1,
    };
    var publisher = BootKeyboardReportPublisher{};
    try std.testing.expect(publisher.latestAfter(0) == null);

    const first_bytes = [_]u8{ 0, 0, 0x04, 0, 0, 0, 0, 0 };
    const first = try publisher.publish(2, 3, keyboard, descriptor, &first_bytes);
    try std.testing.expectEqual(@as(u64, 1), first.sequence);
    try std.testing.expectEqual(@as(u8, 4), first.interface_number);
    try std.testing.expectEqual(@as(u16, 0x046D), first.vendor_id);
    try std.testing.expectEqualSlices(u8, &first_bytes, &first.bytes);
    try std.testing.expect(publisher.latestAfter(first.sequence) == null);

    const second_bytes = [_]u8{ 0x02, 0, 0x05, 0, 0, 0, 0, 0 };
    const second = try publisher.publish(4, 5, keyboard, descriptor, &second_bytes);
    try std.testing.expectEqual(@as(u64, 2), second.sequence);
    try std.testing.expectEqual(@as(usize, 2), publisher.pendingCount());
    try std.testing.expectEqualSlices(
        u8,
        &second_bytes,
        &publisher.latestAfter(first.sequence).?.bytes,
    );
    publisher.clearPort(2);
    try std.testing.expectEqual(@as(usize, 1), publisher.pendingCount());
    try std.testing.expect(publisher.latestAfter(first.sequence) != null);
    try std.testing.expectEqual(second.sequence, publisher.poll().?.sequence);
    try std.testing.expectEqual(@as(usize, 0), publisher.pendingCount());
    try std.testing.expect(publisher.latestAfter(first.sequence) != null);
    publisher.clearPort(4);
    try std.testing.expect(publisher.latestAfter(first.sequence) == null);

    var fallback_publisher = BootKeyboardReportPublisher{};
    const fallback = try fallback_publisher.publish(2, 3, keyboard, descriptor, &first_bytes);
    _ = try fallback_publisher.publish(4, 5, keyboard, descriptor, &second_bytes);
    fallback_publisher.clearPort(4);
    try std.testing.expectEqual(
        fallback.sequence,
        fallback_publisher.latestAfter(0).?.sequence,
    );

    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        publisher.publish(0, 5, keyboard, descriptor, &second_bytes),
    );
    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        publisher.publish(4, 5, keyboard, descriptor, second_bytes[0..7]),
    );

    for (0..HARDWARE_HID_REPORT_QUEUE_CAPACITY) |_| {
        _ = try publisher.publish(4, 5, keyboard, descriptor, &second_bytes);
    }
    try std.testing.expect(!publisher.hasCapacity(1));
    try std.testing.expectError(
        error.EventRingFull,
        publisher.publish(4, 5, keyboard, descriptor, &second_bytes),
    );
    for (0..10) |_| try std.testing.expect(publisher.poll() != null);
    for (0..10) |_| {
        _ = try publisher.publish(2, 3, keyboard, descriptor, &first_bytes);
    }
    publisher.clearPort(2);
    try std.testing.expectEqual(
        @as(usize, HARDWARE_HID_REPORT_QUEUE_CAPACITY - 10),
        publisher.pendingCount(),
    );
    for (0..(HARDWARE_HID_REPORT_QUEUE_CAPACITY - 10)) |_| {
        try std.testing.expectEqual(@as(u8, 4), publisher.poll().?.port_id);
    }
    try std.testing.expect(publisher.poll() == null);
    try std.testing.expect(publisher.hasCapacity(HARDWARE_HID_REPORT_QUEUE_CAPACITY));
}

test "xHCI hardware report queue uses capacity-sized resident metadata" {
    try std.testing.expect(@FieldType(BootKeyboardReportPublisher, "head") == u8);
    try std.testing.expect(@FieldType(BootKeyboardReportPublisher, "tail") == u8);
    try std.testing.expect(@FieldType(BootKeyboardReportPublisher, "count") == u8);
    try std.testing.expectEqual(
        @as(usize, BOOT_KEYBOARD_REPORT_PUBLISHER_SIZE_CEILING_BYTES),
        @sizeOf(BootKeyboardReportPublisher),
    );
}

test {
    _ = caps;
    _ = controller;
    _ = trb;
    _ = context;
    _ = dma_plan;
    _ = descriptors;
}
