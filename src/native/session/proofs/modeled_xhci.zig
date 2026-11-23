//! Software model of a boot keyboard behind an xHCI controller. Only the
//! verification kernel and tests drive permission review with it; the
//! production kernel and its hardware xHCI driver never link it.
const std = @import("std");
const xhci = @import("../../../kernel/drivers/xhci.zig");

const Error = xhci.Error;
const RingPlan = xhci.RingPlan;
const CapabilityRegisters = xhci.CapabilityRegisters;
const validateRingPlan = xhci.validateRingPlan;
const maxDeviceSlotsU8 = xhci.maxDeviceSlotsU8;
const InputProof = xhci.InputProof;
const HID_BOOT_KEYBOARD_REPORT_BYTES = xhci.HID_BOOT_KEYBOARD_REPORT_BYTES;
const HID_BOOT_KEY_SLOTS = xhci.HID_BOOT_KEY_SLOTS;
const MAX_DEVICE_SLOTS = xhci.MAX_DEVICE_SLOTS;
const DEVICE_SLOT_TABLE_ENTRIES: usize = MAX_DEVICE_SLOTS + 1;
const DOORBELL_OFFSET_ALIGNMENT_MASK = xhci.DOORBELL_OFFSET_ALIGNMENT_MASK;
const RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK = xhci.RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK;
const USB_DESCRIPTOR_CONFIGURATION = xhci.USB_DESCRIPTOR_CONFIGURATION;
const USB_DESCRIPTOR_INTERFACE = xhci.USB_DESCRIPTOR_INTERFACE;
const USB_DESCRIPTOR_ENDPOINT = xhci.USB_DESCRIPTOR_ENDPOINT;
const USB_CLASS_HID = xhci.USB_CLASS_HID;
const USB_HID_SUBCLASS_BOOT = xhci.USB_HID_SUBCLASS_BOOT;
const USB_HID_PROTOCOL_KEYBOARD = xhci.USB_HID_PROTOCOL_KEYBOARD;
const USB_ENDPOINT_DIRECTION_IN = xhci.USB_ENDPOINT_DIRECTION_IN;
const USB_ENDPOINT_TRANSFER_INTERRUPT = xhci.USB_ENDPOINT_TRANSFER_INTERRUPT;
pub const bootKeyboardConfigurationDescriptor = xhci.bootKeyboardConfigurationDescriptor;

pub const DEFAULT_BOOT_KEYBOARD_DEVICE_ID: u64 = 0x8086_A0ED_0001;
pub const DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID: u8 = 1;
pub const DEFAULT_BOOT_KEYBOARD_PORT_ID: u8 = 1;
pub const MAX_BOOT_PORTS: usize = 32;
pub const HID_EVENT_QUEUE_CAPACITY: usize = 8;
pub const HID_REPORT_SIZE_CEILING_BYTES: usize = 24;
pub const HID_CONTROLLER_SIZE_CEILING_BYTES: usize = 2_032;

comptime {
    if (HID_EVENT_QUEUE_CAPACITY > std.math.maxInt(u8)) {
        @compileError("modeled xHCI input queue no longer fits compact metadata");
    }
}

const test_ring_plan = RingPlan{
    .command_ring_trbs = xhci.COMMAND_RING_TRBS,
    .event_ring_trbs = xhci.COMMAND_RING_TRBS,
    .command_ring_address = 0x1000,
    .event_ring_address = 0x2000,
};

pub const HidBootKeyboardDevice = struct {
    device_id: u64,
    port_id: u8 = 0,
    slot_id: u8 = 0,
    interface_number: u8,
    endpoint_id: u8,
    max_packet_size: u16,
    interval: u8,
};

pub const PortSpeed = enum(u8) {
    low,
    full,
    high,
    super,
};

pub const PortState = struct {
    connected: bool = false,
    enabled: bool = false,
    speed: PortSpeed = .full,
    assigned_slot: u8 = 0,
};

pub const DeviceSlot = struct {
    enabled: bool = false,
    addressed: bool = false,
    port_id: u8 = 0,
    device_id: u64 = 0,
    boot_keyboard: ?HidBootKeyboardDevice = null,
};

pub const HidReport = struct {
    device_id: u64,
    endpoint_id: u8,
    report_len: u8,
    report: [HID_BOOT_KEYBOARD_REPORT_BYTES]u8,

    pub fn reportSlice(self: *const HidReport) []const u8 {
        return self.report[0..@as(usize, self.report_len)];
    }

    pub fn modifiers(self: *const HidReport) u8 {
        return if (self.report_len == HID_BOOT_KEYBOARD_REPORT_BYTES) self.report[0] else 0;
    }

    pub fn keySlots(self: *const HidReport) []const u8 {
        if (self.report_len != HID_BOOT_KEYBOARD_REPORT_BYTES) return &.{};
        return self.report[2..8];
    }

    comptime {
        if (@sizeOf(@This()) > HID_REPORT_SIZE_CEILING_BYTES) {
            @compileError("xHCI HID report exceeds its compact size ceiling");
        }
    }
};

pub const HidController = struct {
    ring_plan: RingPlan,
    head: u8 = 0,
    tail: u8 = 0,
    count: u8 = 0,
    boot_keyboard: ?HidBootKeyboardDevice = null,
    ports: [MAX_BOOT_PORTS]PortState = @as([MAX_BOOT_PORTS]PortState, @splat(.{})),
    slots: [DEVICE_SLOT_TABLE_ENTRIES]DeviceSlot = @as([DEVICE_SLOT_TABLE_ENTRIES]DeviceSlot, @splat(.{})),
    port_limit: u8 = maxBootPortsU8(),
    device_slot_limit: u8 = maxDeviceSlotsU8(),
    input_events_delivered: usize = 0,
    reports: [HID_EVENT_QUEUE_CAPACITY]HidReport = @as([HID_EVENT_QUEUE_CAPACITY]HidReport, @splat(emptyHidReport())),
    next_unclaimed_slot: u8 = 1,
    recycled_slots: [MAX_DEVICE_SLOTS]u8 = @as([MAX_DEVICE_SLOTS]u8, @splat(0)),
    recycled_slot_count: u8 = 0,

    pub fn initInto(self: *HidController, ring_plan: RingPlan) Error!void {
        try validateRingPlan(ring_plan);
        self.ring_plan = ring_plan;
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        self.boot_keyboard = null;
        for (&self.ports) |*port| port.* = .{};
        for (&self.slots) |*slot| slot.* = .{};
        self.port_limit = maxBootPortsU8();
        self.device_slot_limit = maxDeviceSlotsU8();
        self.input_events_delivered = 0;
        for (&self.reports) |*report| report.* = emptyHidReport();
        self.next_unclaimed_slot = 1;
        @memset(self.recycled_slots[0..], 0);
        self.recycled_slot_count = 0;
    }

    pub fn init(ring_plan: RingPlan) Error!HidController {
        var controller: HidController = undefined;
        try controller.initInto(ring_plan);
        return controller;
    }

    pub fn initWithMmioInto(self: *HidController, capabilities: CapabilityRegisters, ring_plan: RingPlan) Error!void {
        if (!capabilities.supports_64_bit_addressing) return error.Unsupported32BitAddressing;
        if (capabilities.max_scratchpad_buffers == 0 and capabilities.scratchpad_restore) {
            return error.InvalidScratchpadRestore;
        }
        if (capabilities.max_device_slots == 0) return error.MissingDeviceSlots;
        if (capabilities.max_ports == 0) return error.MissingPorts;
        if (capabilities.max_interrupters == 0) return error.MissingInterrupters;
        if (capabilities.doorbell_offset == 0) return error.MissingDoorbellRegisters;
        if (capabilities.runtime_register_offset == 0) return error.MissingRuntimeRegisters;
        if ((capabilities.doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) return error.InvalidDoorbellOffset;
        if ((capabilities.runtime_register_offset & RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK) != 0) {
            return error.InvalidRuntimeRegisterOffset;
        }
        try self.initInto(ring_plan);
        self.port_limit = @min(capabilities.max_ports, maxBootPortsU8());
        self.device_slot_limit = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
    }

    pub fn initWithMmio(capabilities: CapabilityRegisters, ring_plan: RingPlan) Error!HidController {
        var controller: HidController = undefined;
        try controller.initWithMmioInto(capabilities, ring_plan);
        return controller;
    }

    fn enqueueInterruptReport(self: *HidController, report: HidReport) Error!void {
        if (report.report_len == 0 or report.report_len > report.report.len) return error.ReportTooLarge;
        if (self.count == self.reports.len) return error.EventRingFull;
        self.reports[self.tail] = report;
        self.tail = @intCast((@as(usize, self.tail) + 1) % self.reports.len);
        self.count += 1;
    }

    pub fn connectPort(self: *HidController, port_id: u8, speed: PortSpeed) Error!void {
        const port = self.portPtr(port_id) orelse return error.InvalidPort;
        port.connected = true;
        port.enabled = true;
        port.speed = speed;
    }

    pub fn enableDeviceSlot(self: *HidController, port_id: u8) Error!u8 {
        const port = self.portPtr(port_id) orelse return error.InvalidPort;
        if (!port.connected or !port.enabled) return error.PortNotConnected;
        if (port.assigned_slot != 0) return error.PortAlreadyAssigned;

        const slot_id = self.reserveDeviceSlot() orelse return error.DeviceSlotUnavailable;
        const slot = &self.slots[@as(usize, slot_id)];
        slot.* = .{
            .enabled = true,
            .port_id = port_id,
        };
        port.assigned_slot = slot_id;
        return slot_id;
    }

    pub fn disconnectPort(self: *HidController, port_id: u8) Error!void {
        const port = self.portPtr(port_id) orelse return error.InvalidPort;
        if (!port.connected) return error.PortNotConnected;

        if (port.assigned_slot != 0) {
            const slot_id = port.assigned_slot;
            const slot = self.slotPtr(slot_id) orelse return error.InvalidDeviceSlot;
            if (!slot.enabled or slot.port_id != port_id) return error.InvalidDeviceSlot;
            if (slot.boot_keyboard != null) self.resetInputQueue();
            slot.* = .{};
            self.recycleDeviceSlot(slot_id);
        }
        port.* = .{};
    }

    pub fn addressDevice(self: *HidController, slot_id: u8, device_id: u64) Error!void {
        const slot = self.slotPtr(slot_id) orelse return error.InvalidDeviceSlot;
        if (!slot.enabled) return error.InvalidDeviceSlot;
        slot.addressed = true;
        slot.device_id = device_id;
    }

    pub fn configureBootKeyboardEndpoint(
        self: *HidController,
        slot_id: u8,
        configuration_descriptor: []const u8,
    ) Error!HidBootKeyboardDevice {
        const slot = self.slotPtr(slot_id) orelse return error.InvalidDeviceSlot;
        if (!slot.enabled) return error.InvalidDeviceSlot;
        if (!slot.addressed or slot.device_id == 0) return error.DeviceNotAddressed;
        var keyboard = try enumerateBootKeyboard(slot.device_id, configuration_descriptor);
        keyboard.port_id = slot.port_id;
        keyboard.slot_id = slot_id;
        slot.boot_keyboard = keyboard;
        self.boot_keyboard = keyboard;
        return keyboard;
    }

    pub fn attachBootKeyboard(
        self: *HidController,
        device_id: u64,
        configuration_descriptor: []const u8,
    ) Error!HidBootKeyboardDevice {
        try self.connectPort(DEFAULT_BOOT_KEYBOARD_PORT_ID, .high);
        const slot_id = try self.enableDeviceSlot(DEFAULT_BOOT_KEYBOARD_PORT_ID);
        try self.addressDevice(slot_id, device_id);
        return self.configureBootKeyboardEndpoint(slot_id, configuration_descriptor);
    }

    pub fn configuredBootKeyboard(self: *const HidController) ?HidBootKeyboardDevice {
        return self.boot_keyboard;
    }

    pub fn inputProof(self: *const HidController) ?InputProof {
        const keyboard = self.boot_keyboard orelse return null;
        if (keyboard.port_id == 0 or keyboard.slot_id == 0 or self.input_events_delivered == 0) return null;
        return .{
            .port_id = keyboard.port_id,
            .slot_id = keyboard.slot_id,
            .event_count = self.input_events_delivered,
        };
    }

    pub fn enqueueKeyboardInterruptTransfer(
        self: *HidController,
        device_id: u64,
        endpoint_id: u8,
        report_bytes: []const u8,
    ) Error!void {
        const keyboard = self.boot_keyboard orelse return error.MissingBootKeyboardInterface;
        if (keyboard.device_id != device_id) return error.UnknownHidDevice;
        if (keyboard.endpoint_id != endpoint_id) return error.EndpointMismatch;
        if (report_bytes.len != HID_BOOT_KEYBOARD_REPORT_BYTES or report_bytes.len > keyboard.max_packet_size) {
            return error.InvalidBootKeyboardReport;
        }

        var report = HidReport{
            .device_id = device_id,
            .endpoint_id = endpoint_id,
            .report_len = HID_BOOT_KEYBOARD_REPORT_BYTES,
            .report = @as([HID_BOOT_KEYBOARD_REPORT_BYTES]u8, @splat(0)),
        };
        @memcpy(report.report[0..report_bytes.len], report_bytes);
        try self.enqueueInterruptReport(report);
    }

    pub fn submitKeyboardInterruptEvent(
        self: *HidController,
        slot_id: u8,
        endpoint_id: u8,
        report_bytes: []const u8,
    ) Error!void {
        const slot = self.slotPtr(slot_id) orelse return error.InvalidDeviceSlot;
        if (!slot.enabled) return error.InvalidDeviceSlot;
        if (!slot.addressed) return error.DeviceNotAddressed;
        const keyboard = slot.boot_keyboard orelse return error.EndpointNotConfigured;
        if (keyboard.endpoint_id != endpoint_id) return error.EndpointMismatch;
        try self.enqueueKeyboardInterruptTransfer(slot.device_id, endpoint_id, report_bytes);
        self.input_events_delivered += 1;
    }

    pub fn pollHidReport(self: *HidController) Error!HidReport {
        if (self.count == 0) return error.EventRingEmpty;
        const report = self.reports[self.head];
        self.reports[self.head] = emptyHidReport();
        self.head = @intCast((@as(usize, self.head) + 1) % self.reports.len);
        self.count -= 1;
        return report;
    }

    fn portPtr(self: *HidController, port_id: u8) ?*PortState {
        if (port_id == 0 or port_id > self.port_limit) return null;
        return &self.ports[port_id - 1];
    }

    fn slotPtr(self: *HidController, slot_id: u8) ?*DeviceSlot {
        if (slot_id == 0 or slot_id > self.device_slot_limit) return null;
        return &self.slots[slot_id];
    }

    fn reserveDeviceSlot(self: *HidController) ?u8 {
        if (self.recycled_slot_count != 0) {
            self.recycled_slot_count -= 1;
            const slot_id = self.recycled_slots[self.recycled_slot_count];
            self.recycled_slots[self.recycled_slot_count] = 0;
            return slot_id;
        }
        if (self.next_unclaimed_slot == 0 or self.next_unclaimed_slot > self.device_slot_limit) return null;
        const slot_id = self.next_unclaimed_slot;
        self.next_unclaimed_slot += 1;
        return slot_id;
    }

    fn recycleDeviceSlot(self: *HidController, slot_id: u8) void {
        if (self.recycled_slot_count >= self.recycled_slots.len) unreachable;
        self.recycled_slots[self.recycled_slot_count] = slot_id;
        self.recycled_slot_count += 1;
    }

    fn resetInputQueue(self: *HidController) void {
        self.boot_keyboard = null;
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        self.input_events_delivered = 0;
        self.reports = @as([HID_EVENT_QUEUE_CAPACITY]HidReport, @splat(emptyHidReport()));
    }

    comptime {
        if (@sizeOf(@This()) > HID_CONTROLLER_SIZE_CEILING_BYTES) {
            @compileError("xHCI HID controller exceeds its compact size ceiling");
        }
    }
};

pub fn bootKeyboardReport(device_id: u64, endpoint_id: u8, modifiers: u8, keys: []const u8) Error!HidReport {
    if (keys.len > HID_BOOT_KEY_SLOTS) return error.ReportTooLarge;
    var report = HidReport{
        .device_id = device_id,
        .endpoint_id = endpoint_id,
        .report_len = HID_BOOT_KEYBOARD_REPORT_BYTES,
        .report = @as([HID_BOOT_KEYBOARD_REPORT_BYTES]u8, @splat(0)),
    };
    report.report[0] = modifiers;
    @memcpy(report.report[2..][0..keys.len], keys);
    return report;
}

pub fn enumerateBootKeyboard(device_id: u64, configuration_descriptor: []const u8) Error!HidBootKeyboardDevice {
    var offset: usize = 0;
    var active_boot_keyboard_interface: ?u8 = null;
    var saw_boot_keyboard_interface = false;
    while (offset < configuration_descriptor.len) {
        if (offset + 2 > configuration_descriptor.len) return error.InvalidUsbDescriptor;
        const length = configuration_descriptor[offset];
        const descriptor_type = configuration_descriptor[offset + 1];
        if (length < 2 or offset + length > configuration_descriptor.len) return error.InvalidUsbDescriptor;
        const descriptor = configuration_descriptor[offset .. offset + length];

        switch (descriptor_type) {
            USB_DESCRIPTOR_CONFIGURATION => {
                if (length < 9) return error.InvalidUsbDescriptor;
            },
            USB_DESCRIPTOR_INTERFACE => {
                if (length < 9) return error.InvalidUsbDescriptor;
                const interface_number = descriptor[2];
                const interface_class = descriptor[5];
                const interface_subclass = descriptor[6];
                const interface_protocol = descriptor[7];
                if (interface_class == USB_CLASS_HID and
                    interface_subclass == USB_HID_SUBCLASS_BOOT and
                    interface_protocol == USB_HID_PROTOCOL_KEYBOARD)
                {
                    active_boot_keyboard_interface = interface_number;
                    saw_boot_keyboard_interface = true;
                } else {
                    active_boot_keyboard_interface = null;
                }
            },
            USB_DESCRIPTOR_ENDPOINT => {
                if (length < 7) return error.InvalidUsbDescriptor;
                const interface_number = active_boot_keyboard_interface orelse {
                    offset += length;
                    continue;
                };
                const endpoint_address = descriptor[2];
                const attributes = descriptor[3];
                const max_packet_size = std.mem.readInt(u16, descriptor[4..6], .little);
                const interval = descriptor[6];
                const is_interrupt_in = (endpoint_address & USB_ENDPOINT_DIRECTION_IN) != 0 and
                    (attributes & USB_ENDPOINT_TRANSFER_INTERRUPT) == USB_ENDPOINT_TRANSFER_INTERRUPT;
                if (is_interrupt_in and max_packet_size >= HID_BOOT_KEYBOARD_REPORT_BYTES) {
                    return .{
                        .device_id = device_id,
                        .interface_number = interface_number,
                        .endpoint_id = endpoint_address & 0x0f,
                        .max_packet_size = max_packet_size,
                        .interval = interval,
                    };
                }
            },
            else => {},
        }
        offset += length;
    }
    if (saw_boot_keyboard_interface) return error.MissingInterruptInEndpoint;
    return error.MissingBootKeyboardInterface;
}

fn maxBootPortsU8() u8 {
    return @intCast(MAX_BOOT_PORTS);
}

fn emptyHidReport() HidReport {
    return .{
        .device_id = 0,
        .endpoint_id = 0,
        .report_len = 0,
        .report = @as([HID_BOOT_KEYBOARD_REPORT_BYTES]u8, @splat(0)),
    };
}

test "modeled boot keyboard requires doorbell registers and proves delivered events" {
    var missing_doorbell = xhci.defaultCapabilityRegisters();
    missing_doorbell.doorbell_offset = 0;
    try std.testing.expectError(error.MissingDoorbellRegisters, HidController.initWithMmio(missing_doorbell, test_ring_plan));

    var controller = try HidController.initWithMmio(xhci.defaultCapabilityRegisters(), test_ring_plan);
    const descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const keyboard = try controller.attachBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]);
    try std.testing.expect(controller.inputProof() == null);
    const report = try bootKeyboardReport(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, 0, &.{0x04});
    try controller.submitKeyboardInterruptEvent(keyboard.slot_id, keyboard.endpoint_id, report.reportSlice());
    try controller.submitKeyboardInterruptEvent(keyboard.slot_id, keyboard.endpoint_id, report.reportSlice());
    try std.testing.expectEqual(InputProof{ .port_id = DEFAULT_BOOT_KEYBOARD_PORT_ID, .slot_id = keyboard.slot_id, .event_count = 2 }, controller.inputProof().?);
}

test "modeled input queues use capacity-sized resident metadata" {
    try std.testing.expect(@FieldType(HidReport, "report_len") == u8);
    try std.testing.expect(@FieldType(HidController, "head") == u8);
    try std.testing.expect(@FieldType(HidController, "tail") == u8);
    try std.testing.expect(@FieldType(HidController, "count") == u8);
    try std.testing.expect(@FieldType(HidController, "recycled_slot_count") == u8);
    try std.testing.expectEqual(@as(usize, HID_REPORT_SIZE_CEILING_BYTES), @sizeOf(HidReport));
    try std.testing.expect(@sizeOf(HidController) <= HID_CONTROLLER_SIZE_CEILING_BYTES);

    var initialized: HidController = undefined;
    @memset(std.mem.asBytes(&initialized), 0xaa);
    try initialized.initWithMmioInto(xhci.defaultCapabilityRegisters(), test_ring_plan);
    try std.testing.expectEqual(@as(u8, 0), initialized.head);
    try std.testing.expectEqual(@as(u8, 0), initialized.tail);
    try std.testing.expectEqual(@as(u8, 0), initialized.count);
    try std.testing.expectEqual(@as(u8, 1), initialized.next_unclaimed_slot);
    try std.testing.expect(initialized.boot_keyboard == null);
    try std.testing.expect(!initialized.ports[0].connected);
    try std.testing.expect(!initialized.slots[1].enabled);
}

test "modeled controller enumerates HID boot keyboard descriptors" {
    var descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const keyboard = try enumerateBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]);
    try std.testing.expectEqual(@as(u64, DEFAULT_BOOT_KEYBOARD_DEVICE_ID), keyboard.device_id);
    try std.testing.expectEqual(@as(u8, 0), keyboard.interface_number);
    try std.testing.expectEqual(@as(u8, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID), keyboard.endpoint_id);
    try std.testing.expectEqual(@as(u16, HID_BOOT_KEYBOARD_REPORT_BYTES), keyboard.max_packet_size);
    try std.testing.expectEqual(@as(u8, 10), keyboard.interval);

    descriptor[14] = 0xff;
    try std.testing.expectError(error.MissingBootKeyboardInterface, enumerateBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]));

    descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    descriptor[29] = DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID;
    try std.testing.expectError(error.MissingInterruptInEndpoint, enumerateBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]));

    try std.testing.expectError(error.InvalidUsbDescriptor, enumerateBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, &.{ 9, USB_DESCRIPTOR_CONFIGURATION }));
}

test "modeled HID controller validates configured keyboard interrupt transfers" {
    var controller = try HidController.init(test_ring_plan);
    const report = try bootKeyboardReport(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, 0x02, &.{0x04});
    try std.testing.expectError(
        error.MissingBootKeyboardInterface,
        controller.enqueueKeyboardInterruptTransfer(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, report.reportSlice()),
    );

    const descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    _ = try controller.attachBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]);
    try std.testing.expectEqual(@as(u8, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID), controller.configuredBootKeyboard().?.endpoint_id);
    try std.testing.expectError(
        error.UnknownHidDevice,
        controller.enqueueKeyboardInterruptTransfer(DEFAULT_BOOT_KEYBOARD_DEVICE_ID + 1, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, report.reportSlice()),
    );
    try std.testing.expectError(
        error.EndpointMismatch,
        controller.enqueueKeyboardInterruptTransfer(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID + 1, report.reportSlice()),
    );
    try std.testing.expectError(
        error.InvalidBootKeyboardReport,
        controller.enqueueKeyboardInterruptTransfer(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, report.reportSlice()[0..7]),
    );

    try controller.enqueueKeyboardInterruptTransfer(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, report.reportSlice());
    const polled = try controller.pollHidReport();
    try std.testing.expectEqual(@as(u64, DEFAULT_BOOT_KEYBOARD_DEVICE_ID), polled.device_id);
    try std.testing.expectEqual(@as(u8, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID), polled.endpoint_id);
    try std.testing.expectEqual(@as(u8, 0x02), polled.modifiers());
    try std.testing.expectEqual(@as(u8, 0x04), polled.keySlots()[0]);
}

test "modeled HID controller requires port slot address and event delivery for input proof" {
    var controller = try HidController.initWithMmio(xhci.defaultCapabilityRegisters(), test_ring_plan);
    try std.testing.expectError(error.PortNotConnected, controller.enableDeviceSlot(DEFAULT_BOOT_KEYBOARD_PORT_ID));
    try controller.connectPort(DEFAULT_BOOT_KEYBOARD_PORT_ID, .high);
    const slot_id = try controller.enableDeviceSlot(DEFAULT_BOOT_KEYBOARD_PORT_ID);
    try std.testing.expectEqual(@as(u8, 1), slot_id);
    const descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    try std.testing.expectError(error.DeviceNotAddressed, controller.configureBootKeyboardEndpoint(slot_id, descriptor[0..]));
    try controller.addressDevice(slot_id, DEFAULT_BOOT_KEYBOARD_DEVICE_ID);
    const keyboard = try controller.configureBootKeyboardEndpoint(slot_id, descriptor[0..]);
    try std.testing.expectEqual(DEFAULT_BOOT_KEYBOARD_PORT_ID, keyboard.port_id);
    try std.testing.expectEqual(slot_id, keyboard.slot_id);
    try std.testing.expect(controller.inputProof() == null);

    const report = try bootKeyboardReport(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, 0, &.{0x04});
    try std.testing.expectError(
        error.EndpointMismatch,
        controller.submitKeyboardInterruptEvent(slot_id, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID + 1, report.reportSlice()),
    );
    try controller.submitKeyboardInterruptEvent(slot_id, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, report.reportSlice());
    const proof = controller.inputProof().?;
    try std.testing.expectEqual(@as(usize, 1), proof.event_count);
    try std.testing.expectEqual(slot_id, proof.slot_id);
}

test "modeled HID controller exposes all modeled 32 device slot ids" {
    var capabilities = xhci.defaultCapabilityRegisters();
    capabilities.max_device_slots = maxDeviceSlotsU8();
    capabilities.max_ports = maxBootPortsU8();
    var controller = try HidController.initWithMmio(capabilities, test_ring_plan);

    for (1..MAX_DEVICE_SLOTS + 1) |port_value| {
        const port_id: u8 = @intCast(port_value);
        try controller.connectPort(port_id, .high);
        const slot_id = try controller.enableDeviceSlot(port_id);
        try std.testing.expectEqual(port_id, slot_id);
    }

    const last_slot_id = maxDeviceSlotsU8();
    try controller.addressDevice(last_slot_id, DEFAULT_BOOT_KEYBOARD_DEVICE_ID + MAX_DEVICE_SLOTS);
    try std.testing.expectError(error.InvalidDeviceSlot, controller.addressDevice(last_slot_id + 1, DEFAULT_BOOT_KEYBOARD_DEVICE_ID));
}

test "modeled HID controller reuses disconnected slots and discards stale input" {
    var capabilities = xhci.defaultCapabilityRegisters();
    capabilities.max_device_slots = 2;
    capabilities.max_ports = 3;
    var controller = try HidController.initWithMmio(capabilities, test_ring_plan);

    try controller.connectPort(1, .high);
    const keyboard_slot = try controller.enableDeviceSlot(1);
    try controller.addressDevice(keyboard_slot, DEFAULT_BOOT_KEYBOARD_DEVICE_ID);
    const descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const keyboard = try controller.configureBootKeyboardEndpoint(keyboard_slot, descriptor[0..]);
    const report = try bootKeyboardReport(keyboard.device_id, keyboard.endpoint_id, 0, &.{0x04});
    try controller.submitKeyboardInterruptEvent(keyboard.slot_id, keyboard.endpoint_id, report.reportSlice());

    try controller.connectPort(2, .super);
    try std.testing.expectEqual(@as(u8, 2), try controller.enableDeviceSlot(2));
    try controller.connectPort(3, .full);
    try std.testing.expectError(error.DeviceSlotUnavailable, controller.enableDeviceSlot(3));

    try controller.disconnectPort(1);
    try std.testing.expect(controller.configuredBootKeyboard() == null);
    try std.testing.expect(controller.inputProof() == null);
    try std.testing.expectError(error.EventRingEmpty, controller.pollHidReport());
    try std.testing.expectError(error.PortNotConnected, controller.disconnectPort(1));
    try std.testing.expectEqual(keyboard_slot, try controller.enableDeviceSlot(3));
    try std.testing.expect(controller.slots[keyboard_slot].enabled);
    try std.testing.expectEqual(@as(u8, 3), controller.slots[keyboard_slot].port_id);
}

test "modeled HID controller clamps ports and slots to MMIO capabilities" {
    var capabilities = xhci.defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_ports = 2;
    var controller = try HidController.initWithMmio(capabilities, test_ring_plan);

    try controller.connectPort(1, .high);
    try std.testing.expectEqual(@as(u8, 1), try controller.enableDeviceSlot(1));
    try controller.connectPort(2, .high);
    try std.testing.expectError(error.DeviceSlotUnavailable, controller.enableDeviceSlot(2));
    try std.testing.expectError(error.InvalidPort, controller.connectPort(3, .high));
    try std.testing.expectError(error.InvalidDeviceSlot, controller.addressDevice(2, DEFAULT_BOOT_KEYBOARD_DEVICE_ID));
}

test "modeled HID controller queues interrupt keyboard reports" {
    var controller = try HidController.init(test_ring_plan);
    const report = try bootKeyboardReport(0x8086_A0ED_0001, 1, 0x02, &.{ 0x04, 0x05 });
    try controller.enqueueInterruptReport(report);
    const polled = try controller.pollHidReport();
    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), polled.device_id);
    try std.testing.expectEqual(@as(u8, 0x02), polled.modifiers());
    try std.testing.expectEqual(@as(u8, 0x04), polled.keySlots()[0]);
    try std.testing.expectEqual(@as(u8, 0x05), polled.keySlots()[1]);
    try std.testing.expectError(error.EventRingEmpty, controller.pollHidReport());
}

test "modeled HID controller rejects oversized reports and full rings" {
    var controller = try HidController.init(test_ring_plan);
    try std.testing.expectError(error.ReportTooLarge, bootKeyboardReport(0x8086_A0ED_0001, 1, 0, &.{ 1, 2, 3, 4, 5, 6, 7 }));

    const report = try bootKeyboardReport(0x8086_A0ED_0001, 1, 0, &.{0x04});
    for (0..HID_EVENT_QUEUE_CAPACITY) |_| {
        try controller.enqueueInterruptReport(report);
    }
    try std.testing.expectError(error.EventRingFull, controller.enqueueInterruptReport(report));
}
