const std = @import("std");
const endian = @import("../utils/endian.zig");
const spin = @import("../utils/spin.zig");

const readU16Le = endian.readU16Le;
const readU32Le = endian.readU32Le;
const writeU16Le = endian.writeU16Le;
const writeU32Le = endian.writeU32Le;

pub const kernel_boundary_role = "bootstrap_xhci_input_inventory_shim";
pub const publishes_full_input_service = false;
pub const usb_input_data_plane_exports_fail_closed = true;

pub const TRB_BYTES: u32 = 16;
pub const RING_ALIGNMENT_BYTES: u64 = 64;
pub const CONTEXT_BYTES: u32 = 32;
pub const ERST_ENTRY_BYTES: u32 = 16;
pub const HID_BOOT_KEYBOARD_REPORT_BYTES: usize = 8;
pub const HID_BOOT_KEY_SLOTS: usize = 6;
pub const HID_EVENT_QUEUE_CAPACITY: usize = 8;
pub const USB_DESCRIPTOR_CONFIGURATION: u8 = 0x02;
pub const USB_DESCRIPTOR_INTERFACE: u8 = 0x04;
pub const USB_DESCRIPTOR_ENDPOINT: u8 = 0x05;
pub const USB_DESCRIPTOR_HID: u8 = 0x21;
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_HID_SUBCLASS_BOOT: u8 = 0x01;
pub const USB_HID_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_ENDPOINT_DIRECTION_IN: u8 = 0x80;
pub const USB_ENDPOINT_TRANSFER_INTERRUPT: u8 = 0x03;
pub const DEFAULT_BOOT_KEYBOARD_DEVICE_ID: u64 = 0x8086_A0ED_0001;
pub const DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID: u8 = 1;
pub const DEFAULT_BOOT_KEYBOARD_PORT_ID: u8 = 1;
pub const MAX_BOOT_PORTS: usize = 32;
pub const MAX_DEVICE_SLOTS: usize = 32;

pub const CAPABILITY_REGISTERS_BYTES: usize = 0x20;
pub const MAX_EXTENDED_CAPABILITY_OFFSET: u32 = @as(u32, std.math.maxInt(u16)) << 2;
pub const MAX_EXTENDED_CAPABILITIES: usize = 64;
const DEVICE_SLOT_TABLE_ENTRIES: usize = MAX_DEVICE_SLOTS + 1;
const MIN_CAPABILITY_LENGTH: u8 = 0x20;
const MIN_SUPPORTED_INTERFACE_VERSION: u16 = 0x0110;
const CAPABILITY_LENGTH_OFFSET: usize = 0x00;
const INTERFACE_VERSION_OFFSET: usize = 0x02;
const HCSPARAMS1_OFFSET: usize = 0x04;
const HCCPARAMS1_OFFSET: usize = 0x10;
const DOORBELL_OFFSET_OFFSET: usize = 0x14;
const RUNTIME_REGISTER_OFFSET_OFFSET: usize = 0x18;
const DOORBELL_OFFSET_ALIGNMENT_MASK: u32 = 0x3;
const RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK: u32 = 0x1F;
const U16_REGISTER_BYTES: usize = @sizeOf(u16);
const U32_REGISTER_BYTES: usize = @sizeOf(u32);
const HCSPARAMS1_MAX_INTERRUPTERS_SHIFT = 8;
const HCSPARAMS1_MAX_PORTS_SHIFT = 24;
const HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT = 16;
const EXTENDED_CAPABILITY_ID_MASK: u32 = 0xFF;
const EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT = 8;
const EXTENDED_CAPABILITY_NEXT_POINTER_MASK: u32 = 0xFF;
const EXTENDED_CAPABILITY_DWORD_SHIFT = 2;
const USB_LEGACY_SUPPORT_CAPABILITY_ID: u8 = 1;
const USB_LEGACY_BIOS_OWNED_SEMAPHORE: u32 = 1 << 16;
const USB_LEGACY_OS_OWNED_SEMAPHORE: u32 = 1 << 24;
const TEST_CAPABILITY_LENGTH: u8 = 0x40;
const TEST_INTERFACE_VERSION: u16 = 0x0110;
const TEST_UNSUPPORTED_INTERFACE_VERSION: u16 = 0x0080;
const TEST_MAX_DEVICE_SLOTS: u8 = 32;
const TEST_MAX_INTERRUPTERS: u16 = 8;
const TEST_MAX_PORTS: u8 = 12;
const TEST_DOORBELL_OFFSET: u32 = 0x2000;
const TEST_RUNTIME_REGISTER_OFFSET: u32 = 0x1000;
const TEST_RING_TRBS: u32 = 64;
const TEST_COMMAND_RING_ADDRESS: u64 = 0x1000;
const TEST_EVENT_RING_ADDRESS: u64 = 0x2000;
const TEST_UNALIGNED_COMMAND_RING_ADDRESS: u64 = TEST_COMMAND_RING_ADDRESS + 1;
const DEFAULT_TRANSFER_RING_TRBS: u32 = 16;
const DEFAULT_ERST_ENTRIES: u32 = 1;

pub const Error = error{
    KernelUsbInputDataPlaneDisabled,
    TooSmall,
    InvalidCapabilityLength,
    UnsupportedVersion,
    MissingDeviceSlots,
    MissingPorts,
    MissingInterrupters,
    RingTooSmall,
    RingAddressUnaligned,
    ReportTooLarge,
    EventRingFull,
    EventRingEmpty,
    InvalidUsbDescriptor,
    MissingBootKeyboardInterface,
    MissingInterruptInEndpoint,
    UnknownHidDevice,
    EndpointMismatch,
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
    FirmwareOwnsController,
    FirmwareOwnershipTimeout,
    LegacyCapabilityChanged,
    OwnershipRequestRejected,
    MissingMmioInputEvidence,
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

pub const InputEvidenceSource = enum(u8) {
    modeled_mmio,
    hardware_event_ring,
};

pub const HardwareInputEvidence = struct {
    source: InputEvidenceSource = .modeled_mmio,
    controller_event_trbs: u32 = 0,
    event_ring_dma_writes: u32 = 0,
    device_context_reads_by_controller: u32 = 0,
    endpoint_context_reads_by_controller: u32 = 0,
    interrupt_assertions: u32 = 0,
    port_status_change_events: u32 = 0,
    input_report_dma_bytes: u64 = 0,

    pub fn verified(self: HardwareInputEvidence, event_count: usize) bool {
        if (event_count > std.math.maxInt(u32)) return false;
        const expected_events: u32 = @intCast(event_count);
        const expected_report_bytes = std.math.mul(u64, expected_events, HID_BOOT_KEYBOARD_REPORT_BYTES) catch return false;
        return self.source == .hardware_event_ring and
            expected_events > 0 and
            self.controller_event_trbs >= expected_events and
            self.event_ring_dma_writes >= expected_events and
            self.device_context_reads_by_controller != 0 and
            self.endpoint_context_reads_by_controller != 0 and
            self.interrupt_assertions >= expected_events and
            self.port_status_change_events != 0 and
            self.input_report_dma_bytes >= expected_report_bytes;
    }
};

pub const InputProof = struct {
    keyboard: HidBootKeyboardDevice,
    event_count: usize,
    mmio: MmioInputProof,

    pub fn verified(self: InputProof) bool {
        return self.keyboard.device_id != 0 and
            self.keyboard.port_id != 0 and
            self.keyboard.slot_id != 0 and
            self.keyboard.max_packet_size >= HID_BOOT_KEYBOARD_REPORT_BYTES and
            self.event_count > 0 and
            self.mmio.verified(self.keyboard, self.event_count);
    }

    pub fn productionHardwareVerified(self: InputProof) bool {
        return self.verified() and self.mmio.hardwareVerified(self.keyboard, self.event_count);
    }
};

pub const MmioInputProof = struct {
    doorbell_offset: u32,
    runtime_register_offset: u32,
    command_ring_address: u64,
    event_ring_address: u64,
    device_context_base_address: u64,
    input_context_address: u64,
    transfer_ring_address: u64,
    event_ring_segment_table_address: u64,
    device_context_bytes: u32,
    input_context_bytes: u32,
    transfer_ring_trbs: u32,
    event_ring_segment_table_entries: u32,
    command_doorbells: u32,
    transfer_doorbells: u32,
    device_context_writes: u32,
    endpoint_context_writes: u32,
    event_ring_segment_table_writes: u32,
    event_ring_dequeue_count: u32,
    interrupt_events: u32,
    interrupter_id: u16,
    max_device_slots: u8,
    max_ports: u8,
    hardware_input: HardwareInputEvidence = .{},

    pub fn verified(self: MmioInputProof, keyboard: HidBootKeyboardDevice, event_count: usize) bool {
        return self.doorbell_offset != 0 and
            self.runtime_register_offset != 0 and
            aligned(self.command_ring_address, RING_ALIGNMENT_BYTES) and
            aligned(self.event_ring_address, RING_ALIGNMENT_BYTES) and
            aligned(self.device_context_base_address, RING_ALIGNMENT_BYTES) and
            aligned(self.input_context_address, RING_ALIGNMENT_BYTES) and
            aligned(self.transfer_ring_address, RING_ALIGNMENT_BYTES) and
            aligned(self.event_ring_segment_table_address, RING_ALIGNMENT_BYTES) and
            self.device_context_bytes >= @as(u32, self.max_device_slots) * CONTEXT_BYTES and
            self.input_context_bytes >= CONTEXT_BYTES * 2 and
            self.transfer_ring_trbs >= 16 and
            self.event_ring_segment_table_entries > 0 and
            self.command_doorbells >= 3 and
            self.transfer_doorbells > 0 and
            self.device_context_writes >= 2 and
            self.endpoint_context_writes > 0 and
            self.event_ring_segment_table_writes >= self.event_ring_segment_table_entries and
            self.event_ring_dequeue_count >= self.interrupt_events and
            self.interrupt_events > 0 and
            event_count <= std.math.maxInt(u32) and
            self.interrupt_events == @as(u32, @intCast(event_count)) and
            self.interrupter_id != 0 and
            keyboard.slot_id != 0 and
            keyboard.port_id != 0 and
            keyboard.endpoint_id != 0 and
            keyboard.slot_id <= self.max_device_slots and
            keyboard.port_id <= self.max_ports;
    }

    pub fn hardwareVerified(self: MmioInputProof, keyboard: HidBootKeyboardDevice, event_count: usize) bool {
        return self.verified(keyboard, event_count) and self.hardware_input.verified(event_count);
    }
};

const MmioState = struct {
    capabilities: CapabilityRegisters,
    device_context_base_address: u64,
    input_context_address: u64,
    transfer_ring_address: u64,
    event_ring_segment_table_address: u64,
    device_context_bytes: u32,
    input_context_bytes: u32,
    transfer_ring_trbs: u32,
    event_ring_segment_table_entries: u32,
    command_doorbells: u32 = 0,
    transfer_doorbells: u32 = 0,
    device_context_writes: u32 = 0,
    endpoint_context_writes: u32 = 0,
    event_ring_segment_table_writes: u32 = DEFAULT_ERST_ENTRIES,
    event_ring_dequeue_count: u32 = 0,
    interrupt_events: u32 = 0,
    interrupter_id: u16 = 1,

    fn proof(self: MmioState, ring_plan: RingPlan) MmioInputProof {
        return .{
            .doorbell_offset = self.capabilities.doorbell_offset,
            .runtime_register_offset = self.capabilities.runtime_register_offset,
            .command_ring_address = ring_plan.command_ring_address,
            .event_ring_address = ring_plan.event_ring_address,
            .device_context_base_address = self.device_context_base_address,
            .input_context_address = self.input_context_address,
            .transfer_ring_address = self.transfer_ring_address,
            .event_ring_segment_table_address = self.event_ring_segment_table_address,
            .device_context_bytes = self.device_context_bytes,
            .input_context_bytes = self.input_context_bytes,
            .transfer_ring_trbs = self.transfer_ring_trbs,
            .event_ring_segment_table_entries = self.event_ring_segment_table_entries,
            .command_doorbells = self.command_doorbells,
            .transfer_doorbells = self.transfer_doorbells,
            .device_context_writes = self.device_context_writes,
            .endpoint_context_writes = self.endpoint_context_writes,
            .event_ring_segment_table_writes = self.event_ring_segment_table_writes,
            .event_ring_dequeue_count = self.event_ring_dequeue_count,
            .interrupt_events = self.interrupt_events,
            .interrupter_id = self.interrupter_id,
            .max_device_slots = self.capabilities.max_device_slots,
            .max_ports = self.capabilities.max_ports,
        };
    }
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
    boot_keyboard: ?HidBootKeyboardDevice = null,
    ports: [MAX_BOOT_PORTS]PortState = [_]PortState{.{}} ** MAX_BOOT_PORTS,
    slots: [DEVICE_SLOT_TABLE_ENTRIES]DeviceSlot = [_]DeviceSlot{.{}} ** DEVICE_SLOT_TABLE_ENTRIES,
    port_limit: u8 = maxBootPortsU8(),
    device_slot_limit: u8 = maxDeviceSlotsU8(),
    input_events_delivered: usize = 0,
    reports: [HID_EVENT_QUEUE_CAPACITY]HidReport = [_]HidReport{emptyHidReport()} ** HID_EVENT_QUEUE_CAPACITY,
    mmio: ?MmioState = null,
    next_unclaimed_slot: u8 = 1,
    recycled_slots: [MAX_DEVICE_SLOTS]u8 = [_]u8{0} ** MAX_DEVICE_SLOTS,
    recycled_slot_count: usize = 0,

    pub fn init(ring_plan: RingPlan) Error!HidController {
        try validateRingPlan(ring_plan);
        return .{ .ring_plan = ring_plan };
    }

    pub fn initWithMmio(capabilities: CapabilityRegisters, ring_plan: RingPlan) Error!HidController {
        if (capabilities.max_device_slots == 0) return error.MissingDeviceSlots;
        if (capabilities.max_ports == 0) return error.MissingPorts;
        if (capabilities.max_interrupters == 0) return error.MissingInterrupters;
        if (capabilities.doorbell_offset == 0) return error.MissingDoorbellRegisters;
        if (capabilities.runtime_register_offset == 0) return error.MissingRuntimeRegisters;
        if ((capabilities.doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) return error.InvalidDoorbellOffset;
        if ((capabilities.runtime_register_offset & RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK) != 0) {
            return error.InvalidRuntimeRegisterOffset;
        }
        var controller = try HidController.init(ring_plan);
        controller.port_limit = @min(capabilities.max_ports, maxBootPortsU8());
        controller.device_slot_limit = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
        const device_context_bytes = @as(u32, capabilities.max_device_slots) * CONTEXT_BYTES;
        const input_context_bytes = CONTEXT_BYTES * 2;
        const device_context_base_address = alignForward(
            ring_plan.command_ring_address + ringByteLength(ring_plan.command_ring_trbs),
            RING_ALIGNMENT_BYTES,
        );
        const input_context_address = alignForward(
            device_context_base_address + device_context_bytes,
            RING_ALIGNMENT_BYTES,
        );
        const transfer_ring_address = alignForward(
            ring_plan.event_ring_address + ringByteLength(ring_plan.event_ring_trbs),
            RING_ALIGNMENT_BYTES,
        );
        const event_ring_segment_table_address = alignForward(
            transfer_ring_address + ringByteLength(DEFAULT_TRANSFER_RING_TRBS),
            RING_ALIGNMENT_BYTES,
        );
        controller.mmio = .{
            .capabilities = capabilities,
            .device_context_base_address = device_context_base_address,
            .input_context_address = input_context_address,
            .transfer_ring_address = transfer_ring_address,
            .event_ring_segment_table_address = event_ring_segment_table_address,
            .device_context_bytes = device_context_bytes,
            .input_context_bytes = input_context_bytes,
            .transfer_ring_trbs = DEFAULT_TRANSFER_RING_TRBS,
            .event_ring_segment_table_entries = DEFAULT_ERST_ENTRIES,
        };
        return controller;
    }

    fn enqueueInterruptReport(self: *HidController, report: HidReport) Error!void {
        if (report.report_len == 0 or report.report_len > report.report.len) return error.ReportTooLarge;
        if (self.count == self.reports.len) return error.EventRingFull;
        self.reports[self.tail] = report;
        self.tail = (self.tail + 1) % self.reports.len;
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
        if (self.mmio) |*mmio| {
            mmio.command_doorbells += 1;
            mmio.device_context_writes += 1;
        }
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
            if (self.mmio) |*mmio| mmio.command_doorbells += 1;
        }
        port.* = .{};
    }

    pub fn addressDevice(self: *HidController, slot_id: u8, device_id: u64) Error!void {
        const slot = self.slotPtr(slot_id) orelse return error.InvalidDeviceSlot;
        if (!slot.enabled) return error.InvalidDeviceSlot;
        slot.addressed = true;
        slot.device_id = device_id;
        if (self.mmio) |*mmio| {
            mmio.command_doorbells += 1;
            mmio.device_context_writes += 1;
        }
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
        if (self.mmio) |*mmio| {
            mmio.command_doorbells += 1;
            mmio.endpoint_context_writes += 1;
        }
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
        const mmio = self.mmio orelse return null;
        const mmio_proof = mmio.proof(self.ring_plan);
        return .{
            .keyboard = keyboard,
            .event_count = self.input_events_delivered,
            .mmio = mmio_proof,
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
            .report = [_]u8{0} ** HID_BOOT_KEYBOARD_REPORT_BYTES,
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
        if (self.mmio) |*mmio| {
            mmio.transfer_doorbells += 1;
            mmio.event_ring_dequeue_count += 1;
            mmio.interrupt_events += 1;
        }
    }

    pub fn pollHidReport(self: *HidController) Error!HidReport {
        if (self.count == 0) return error.EventRingEmpty;
        const report = self.reports[self.head];
        self.reports[self.head] = emptyHidReport();
        self.head = (self.head + 1) % self.reports.len;
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
        self.reports = [_]HidReport{emptyHidReport()} ** HID_EVENT_QUEUE_CAPACITY;
        if (self.mmio) |*mmio| {
            mmio.transfer_doorbells = 0;
            mmio.event_ring_dequeue_count = 0;
            mmio.interrupt_events = 0;
        }
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

pub fn bootKeyboardConfigurationDescriptor(endpoint_id: u8) [34]u8 {
    return .{
        9, USB_DESCRIPTOR_CONFIGURATION, 34,                                               0,                               1,                              1,             0,                     0x80,                      50,
        9, USB_DESCRIPTOR_INTERFACE,     0,                                                0,                               1,                              USB_CLASS_HID, USB_HID_SUBCLASS_BOOT, USB_HID_PROTOCOL_KEYBOARD, 0,
        9, USB_DESCRIPTOR_HID,           0x11,                                             0x01,                            0,                              1,             0x22,                  63,                        0,
        7, USB_DESCRIPTOR_ENDPOINT,      USB_ENDPOINT_DIRECTION_IN | (endpoint_id & 0x0f), USB_ENDPOINT_TRANSFER_INTERRUPT, HID_BOOT_KEYBOARD_REPORT_BYTES, 0,             10,
    };
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
                const max_packet_size = readU16Le(descriptor[4..6]);
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

pub fn parseCapabilityRegisters(mmio: []const u8) Error!CapabilityRegisters {
    if (mmio.len < CAPABILITY_REGISTERS_BYTES) return error.TooSmall;
    const capability_length = mmio[CAPABILITY_LENGTH_OFFSET];
    if (capability_length < MIN_CAPABILITY_LENGTH) return error.InvalidCapabilityLength;

    const interface_version = readU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES]);
    if (interface_version < MIN_SUPPORTED_INTERFACE_VERSION) return error.UnsupportedVersion;

    const hcsparams1 = readU32Le(mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES]);
    const max_device_slots: u8 = @truncate(hcsparams1);
    const max_interrupters: u16 = @truncate(hcsparams1 >> HCSPARAMS1_MAX_INTERRUPTERS_SHIFT);
    const max_ports: u8 = @truncate(hcsparams1 >> HCSPARAMS1_MAX_PORTS_SHIFT);
    if (max_device_slots == 0) return error.MissingDeviceSlots;
    if (max_ports == 0) return error.MissingPorts;
    if (max_interrupters == 0) return error.MissingInterrupters;

    const hccparams1 = readU32Le(mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES]);
    const extended_capability_offset =
        (hccparams1 >> HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT) << EXTENDED_CAPABILITY_DWORD_SHIFT;

    const doorbell_offset = readU32Le(mmio[DOORBELL_OFFSET_OFFSET .. DOORBELL_OFFSET_OFFSET + U32_REGISTER_BYTES]);
    if (doorbell_offset == 0) return error.MissingDoorbellRegisters;
    if ((doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) return error.InvalidDoorbellOffset;
    const runtime_register_offset = readU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET .. RUNTIME_REGISTER_OFFSET_OFFSET + U32_REGISTER_BYTES]);
    if (runtime_register_offset == 0) return error.MissingRuntimeRegisters;
    if ((runtime_register_offset & RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK) != 0) {
        return error.InvalidRuntimeRegisterOffset;
    }

    return .{
        .capability_length = capability_length,
        .interface_version = interface_version,
        .max_device_slots = max_device_slots,
        .max_interrupters = max_interrupters,
        .max_ports = max_ports,
        .extended_capability_offset = extended_capability_offset,
        .doorbell_offset = doorbell_offset,
        .runtime_register_offset = runtime_register_offset,
    };
}

pub fn findLegacySupport(first_offset: u32, reader: anytype) Error!?LegacySupport {
    if (first_offset == 0) return null;
    if ((first_offset & (@sizeOf(u32) - 1)) != 0 or first_offset > MAX_EXTENDED_CAPABILITY_OFFSET) {
        return error.ExtendedCapabilityOutOfRange;
    }

    var offset = first_offset;
    var visited: usize = 0;
    while (visited < MAX_EXTENDED_CAPABILITIES) : (visited += 1) {
        const header = reader.readDword(offset);
        const capability_id: u8 = @truncate(header & EXTENDED_CAPABILITY_ID_MASK);
        if (capability_id == USB_LEGACY_SUPPORT_CAPABILITY_ID) {
            return .{
                .offset = offset,
                .firmware_owned = firmwareOwned(header),
                .os_owned = osOwned(header),
            };
        }

        const next_dwords = (header >> EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) &
            EXTENDED_CAPABILITY_NEXT_POINTER_MASK;
        if (next_dwords == 0) return null;
        const delta = next_dwords << EXTENDED_CAPABILITY_DWORD_SHIFT;
        if (offset > MAX_EXTENDED_CAPABILITY_OFFSET - delta) {
            return error.ExtendedCapabilityOutOfRange;
        }
        offset += delta;
    }
    return error.ExtendedCapabilityTraversalLimit;
}

pub fn inspectLegacyOwnership(first_offset: u32, reader: anytype) Error!LegacyOwnership {
    const legacy = try findLegacySupport(first_offset, reader) orelse return .not_present;
    if (legacy.firmware_owned) return error.FirmwareOwnsController;
    return if (legacy.os_owned) .os_owned else .firmware_released;
}

pub fn claimLegacyOwnership(
    legacy: LegacySupport,
    reader: anytype,
    deadline: anytype,
) Error!LegacyOwnership {
    if (!legacy.os_owned) reader.writeOsOwnedByte(legacy.offset, 1);

    while (true) {
        const header = reader.readDword(legacy.offset);
        const capability_id: u8 = @truncate(header & EXTENDED_CAPABILITY_ID_MASK);
        if (capability_id != USB_LEGACY_SUPPORT_CAPABILITY_ID) {
            return error.LegacyCapabilityChanged;
        }
        if (!osOwned(header)) return error.OwnershipRequestRejected;
        if (!firmwareOwned(header)) return .os_owned;
        if (deadline.expired()) return error.FirmwareOwnershipTimeout;
        spin.hint();
    }
}

fn firmwareOwned(header: u32) bool {
    return (header & USB_LEGACY_BIOS_OWNED_SEMAPHORE) != 0;
}

fn osOwned(header: u32) bool {
    return (header & USB_LEGACY_OS_OWNED_SEMAPHORE) != 0;
}

pub fn defaultCapabilityRegisters() CapabilityRegisters {
    return .{
        .capability_length = TEST_CAPABILITY_LENGTH,
        .interface_version = TEST_INTERFACE_VERSION,
        .max_device_slots = TEST_MAX_DEVICE_SLOTS,
        .max_interrupters = TEST_MAX_INTERRUPTERS,
        .max_ports = TEST_MAX_PORTS,
        .extended_capability_offset = 0,
        .doorbell_offset = TEST_DOORBELL_OFFSET,
        .runtime_register_offset = TEST_RUNTIME_REGISTER_OFFSET,
    };
}

pub fn validateRingPlan(plan: RingPlan) Error!void {
    try validateRing(plan.command_ring_trbs, plan.command_ring_address);
    try validateRing(plan.event_ring_trbs, plan.event_ring_address);
}

pub fn rejectKernelInputReport(_: InputRequest) Error!void {
    return error.KernelUsbInputDataPlaneDisabled;
}

pub fn withHardwareInputEvidence(proof: InputProof, evidence: HardwareInputEvidence) InputProof {
    var upgraded = proof;
    upgraded.mmio.hardware_input = evidence;
    return upgraded;
}

fn validateRing(trbs: u32, address: u64) Error!void {
    if (trbs < 16) return error.RingTooSmall;
    if (!aligned(address, RING_ALIGNMENT_BYTES)) return error.RingAddressUnaligned;
}

fn ringByteLength(trbs: u32) u64 {
    return @as(u64, trbs) * TRB_BYTES;
}

fn alignForward(address: u64, alignment: u64) u64 {
    if (alignment == 0) return address;
    const remainder = address % alignment;
    return if (remainder == 0) address else address + (alignment - remainder);
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

fn maxBootPortsU8() u8 {
    return @intCast(MAX_BOOT_PORTS);
}

fn maxDeviceSlotsU8() u8 {
    return @intCast(MAX_DEVICE_SLOTS);
}

fn emptyHidReport() HidReport {
    return .{
        .device_id = 0,
        .endpoint_id = 0,
        .report_len = 0,
        .report = [_]u8{0} ** HID_BOOT_KEYBOARD_REPORT_BYTES,
    };
}

fn validCapabilityRegisters() [CAPABILITY_REGISTERS_BYTES]u8 {
    var mmio = [_]u8{0} ** CAPABILITY_REGISTERS_BYTES;
    mmio[CAPABILITY_LENGTH_OFFSET] = TEST_CAPABILITY_LENGTH;
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], TEST_INTERFACE_VERSION);
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, TEST_MAX_DEVICE_SLOTS) |
            (@as(u32, TEST_MAX_INTERRUPTERS) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) |
            (@as(u32, TEST_MAX_PORTS) << HCSPARAMS1_MAX_PORTS_SHIFT),
    );
    writeU32Le(mmio[DOORBELL_OFFSET_OFFSET .. DOORBELL_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_DOORBELL_OFFSET);
    writeU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET .. RUNTIME_REGISTER_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_RUNTIME_REGISTER_OFFSET);
    return mmio;
}

test "xHCI capability parser extracts controller limits" {
    const mmio = validCapabilityRegisters();
    const caps = try parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(TEST_CAPABILITY_LENGTH, caps.capability_length);
    try std.testing.expectEqual(TEST_INTERFACE_VERSION, caps.interface_version);
    try std.testing.expectEqual(TEST_MAX_DEVICE_SLOTS, caps.max_device_slots);
    try std.testing.expectEqual(TEST_MAX_INTERRUPTERS, caps.max_interrupters);
    try std.testing.expectEqual(TEST_MAX_PORTS, caps.max_ports);
    try std.testing.expectEqual(@as(u32, 0), caps.extended_capability_offset);
    try std.testing.expectEqual(TEST_DOORBELL_OFFSET, caps.doorbell_offset);
    try std.testing.expectEqual(TEST_RUNTIME_REGISTER_OFFSET, caps.runtime_register_offset);
}

const TestExtendedCapabilityReader = struct {
    bytes: []const u8,

    fn readDword(self: @This(), offset: u32) u32 {
        const start: usize = @intCast(offset);
        return readU32Le(self.bytes[start .. start + @sizeOf(u32)]);
    }
};

const EndlessExtendedCapabilityReader = struct {
    fn readDword(_: @This(), _: u32) u32 {
        return @as(u32, 0x7F) | (@as(u32, 1) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT);
    }
};

test "xHCI capability parser extracts the extended capability pointer" {
    var mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, 0x2000) << HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT,
    );
    const caps = try parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(@as(u32, 0x8000), caps.extended_capability_offset);
}

test "xHCI legacy ownership accepts absent and firmware-released capabilities" {
    var registers = [_]u8{0} ** 0x80;
    var reader = TestExtendedCapabilityReader{ .bytes = &registers };
    try std.testing.expectEqual(LegacyOwnership.not_present, try inspectLegacyOwnership(0, reader));

    writeU32Le(registers[0x40..0x44], @as(u32, 0x7F) | (@as(u32, 4) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT));
    writeU32Le(registers[0x50..0x54], USB_LEGACY_SUPPORT_CAPABILITY_ID);
    reader = .{ .bytes = &registers };
    try std.testing.expectEqual(LegacyOwnership.firmware_released, try inspectLegacyOwnership(0x40, reader));

    writeU32Le(registers[0x50..0x54], USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_OS_OWNED_SEMAPHORE);
    reader = .{ .bytes = &registers };
    try std.testing.expectEqual(LegacyOwnership.os_owned, try inspectLegacyOwnership(0x40, reader));
}

test "xHCI legacy ownership rejects firmware-owned and malformed chains" {
    var registers = [_]u8{0} ** 0x80;
    writeU32Le(
        registers[0x40..0x44],
        USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
    );
    const reader = TestExtendedCapabilityReader{ .bytes = &registers };
    try std.testing.expectError(error.FirmwareOwnsController, inspectLegacyOwnership(0x40, reader));

    const terminal_reader = EndlessExtendedCapabilityReader{};
    try std.testing.expectError(
        error.ExtendedCapabilityOutOfRange,
        inspectLegacyOwnership(MAX_EXTENDED_CAPABILITY_OFFSET, terminal_reader),
    );
    try std.testing.expectError(
        error.ExtendedCapabilityTraversalLimit,
        inspectLegacyOwnership(0x40, terminal_reader),
    );
}

const MockOwnershipReader = struct {
    header: u32,
    release_after_reads: ?usize = null,
    accept_os_write: bool = true,
    read_count: usize = 0,
    os_write_count: usize = 0,
    last_write_offset: u32 = 0,
    last_write_value: u8 = 0,

    pub fn readDword(self: *@This(), _: u32) u32 {
        self.read_count += 1;
        if (self.os_write_count != 0) {
            if (self.release_after_reads) |release_after| {
                if (self.read_count >= release_after) self.header &= ~USB_LEGACY_BIOS_OWNED_SEMAPHORE;
            }
        }
        return self.header;
    }

    pub fn writeOsOwnedByte(self: *@This(), offset: u32, value: u8) void {
        self.os_write_count += 1;
        self.last_write_offset = offset;
        self.last_write_value = value;
        if (self.accept_os_write and value == 1) self.header |= USB_LEGACY_OS_OWNED_SEMAPHORE;
    }
};

const MockOwnershipDeadline = struct {
    remaining_checks: usize,

    pub fn expired(self: *@This()) bool {
        if (self.remaining_checks == 0) return true;
        self.remaining_checks -= 1;
        return false;
    }
};

test "xHCI ownership handoff writes only the OS semaphore and waits for firmware release" {
    var reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
        .release_after_reads = 3,
    };
    const legacy = (try findLegacySupport(0x40, &reader)).?;
    var deadline = MockOwnershipDeadline{ .remaining_checks = 4 };
    try std.testing.expectEqual(LegacyOwnership.os_owned, try claimLegacyOwnership(legacy, &reader, &deadline));
    try std.testing.expectEqual(@as(usize, 1), reader.os_write_count);
    try std.testing.expectEqual(@as(u32, 0x40), reader.last_write_offset);
    try std.testing.expectEqual(@as(u8, 1), reader.last_write_value);
    try std.testing.expect((reader.header & USB_LEGACY_OS_OWNED_SEMAPHORE) != 0);
    try std.testing.expect((reader.header & USB_LEGACY_BIOS_OWNED_SEMAPHORE) == 0);
}

test "xHCI ownership handoff accepts an already OS-owned controller" {
    var reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_OS_OWNED_SEMAPHORE,
    };
    const legacy = (try findLegacySupport(0x40, &reader)).?;
    var deadline = MockOwnershipDeadline{ .remaining_checks = 0 };
    try std.testing.expectEqual(LegacyOwnership.os_owned, try claimLegacyOwnership(legacy, &reader, &deadline));
    try std.testing.expectEqual(@as(usize, 0), reader.os_write_count);
}

test "xHCI ownership handoff rejects failed requests, changed capabilities, and timeouts" {
    var rejected_reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
        .accept_os_write = false,
    };
    const rejected_legacy = (try findLegacySupport(0x40, &rejected_reader)).?;
    var deadline = MockOwnershipDeadline{ .remaining_checks = 0 };
    try std.testing.expectError(
        error.OwnershipRequestRejected,
        claimLegacyOwnership(rejected_legacy, &rejected_reader, &deadline),
    );

    var changed_reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_OS_OWNED_SEMAPHORE,
    };
    const changed_legacy = (try findLegacySupport(0x40, &changed_reader)).?;
    changed_reader.header = @as(u32, 2) | USB_LEGACY_OS_OWNED_SEMAPHORE;
    try std.testing.expectError(
        error.LegacyCapabilityChanged,
        claimLegacyOwnership(changed_legacy, &changed_reader, &deadline),
    );

    var timeout_reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
    };
    const timeout_legacy = (try findLegacySupport(0x40, &timeout_reader)).?;
    deadline = .{ .remaining_checks = 2 };
    try std.testing.expectError(
        error.FirmwareOwnershipTimeout,
        claimLegacyOwnership(timeout_legacy, &timeout_reader, &deadline),
    );
}

test "xHCI capability parser rejects unsupported controllers" {
    var mmio = validCapabilityRegisters();
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], TEST_UNSUPPORTED_INTERFACE_VERSION);
    try std.testing.expectError(error.UnsupportedVersion, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], 0x0100);
    try std.testing.expectError(error.UnsupportedVersion, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        (@as(u32, TEST_MAX_INTERRUPTERS) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) |
            (@as(u32, TEST_MAX_PORTS) << HCSPARAMS1_MAX_PORTS_SHIFT),
    );
    try std.testing.expectError(error.MissingDeviceSlots, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, 32) | (@as(u32, 8) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT),
    );
    try std.testing.expectError(error.MissingPorts, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(mmio[DOORBELL_OFFSET_OFFSET .. DOORBELL_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_DOORBELL_OFFSET + 1);
    try std.testing.expectError(error.InvalidDoorbellOffset, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET .. RUNTIME_REGISTER_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_RUNTIME_REGISTER_OFFSET + 4);
    try std.testing.expectError(error.InvalidRuntimeRegisterOffset, parseCapabilityRegisters(mmio[0..]));
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
}

test "xHCI controller binds MMIO command doorbells and event ring input proof" {
    try std.testing.expectError(error.MissingDoorbellRegisters, HidController.initWithMmio(.{
        .capability_length = TEST_CAPABILITY_LENGTH,
        .interface_version = TEST_INTERFACE_VERSION,
        .max_device_slots = TEST_MAX_DEVICE_SLOTS,
        .max_interrupters = TEST_MAX_INTERRUPTERS,
        .max_ports = TEST_MAX_PORTS,
        .extended_capability_offset = 0,
        .doorbell_offset = 0,
        .runtime_register_offset = TEST_RUNTIME_REGISTER_OFFSET,
    }, .{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    }));

    var controller = try HidController.initWithMmio(defaultCapabilityRegisters(), .{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });
    const descriptor = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const keyboard = try controller.attachBootKeyboard(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]);
    const report = try bootKeyboardReport(DEFAULT_BOOT_KEYBOARD_DEVICE_ID, DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, 0, &.{0x04});
    try controller.submitKeyboardInterruptEvent(keyboard.slot_id, keyboard.endpoint_id, report.reportSlice());

    const proof = controller.inputProof().?;
    try std.testing.expect(proof.verified());
    try std.testing.expect(!proof.productionHardwareVerified());
    try std.testing.expect(proof.mmio.command_doorbells >= 3);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.transfer_doorbells);
    try std.testing.expectEqual(@as(u32, 2), proof.mmio.device_context_writes);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.endpoint_context_writes);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.event_ring_segment_table_writes);
    try std.testing.expectEqual(@as(u32, TEST_MAX_DEVICE_SLOTS) * CONTEXT_BYTES, proof.mmio.device_context_bytes);
    try std.testing.expectEqual(CONTEXT_BYTES * 2, proof.mmio.input_context_bytes);
    try std.testing.expectEqual(@as(u32, DEFAULT_TRANSFER_RING_TRBS), proof.mmio.transfer_ring_trbs);
    try std.testing.expectEqual(@as(u32, DEFAULT_ERST_ENTRIES), proof.mmio.event_ring_segment_table_entries);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.event_ring_dequeue_count);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.interrupt_events);

    var malformed = proof;
    malformed.mmio.endpoint_context_writes = 0;
    try std.testing.expect(!malformed.verified());

    const hardware_proof = withHardwareInputEvidence(proof, .{
        .source = .hardware_event_ring,
        .controller_event_trbs = 1,
        .event_ring_dma_writes = 1,
        .device_context_reads_by_controller = 1,
        .endpoint_context_reads_by_controller = 1,
        .interrupt_assertions = 1,
        .port_status_change_events = 1,
        .input_report_dma_bytes = HID_BOOT_KEYBOARD_REPORT_BYTES,
    });
    try std.testing.expect(hardware_proof.productionHardwareVerified());

    var missing_event_dma = hardware_proof;
    missing_event_dma.mmio.hardware_input.event_ring_dma_writes = 0;
    try std.testing.expect(!missing_event_dma.productionHardwareVerified());
}

test "xHCI kernel shim rejects direct USB input reports" {
    try std.testing.expectError(error.KernelUsbInputDataPlaneDisabled, rejectKernelInputReport(.{
        .device_id = 0x8086_A0ED_0000,
        .report_len = 8,
    }));
}

test "xHCI enumerates HID boot keyboard descriptors" {
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

test "xHCI HID controller validates configured keyboard interrupt transfers" {
    var controller = try HidController.init(.{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });
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

test "xHCI HID controller requires port slot address and event delivery for input proof" {
    var controller = try HidController.initWithMmio(defaultCapabilityRegisters(), .{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });
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
    try std.testing.expect(proof.verified());
    try std.testing.expectEqual(@as(usize, 1), proof.event_count);
    try std.testing.expectEqual(slot_id, proof.keyboard.slot_id);
    try std.testing.expectEqual(@as(u32, 2), proof.mmio.device_context_writes);
    try std.testing.expectEqual(@as(u32, 1), proof.mmio.endpoint_context_writes);
}

test "xHCI HID controller exposes all modeled 32 device slot ids" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = maxDeviceSlotsU8();
    capabilities.max_ports = maxBootPortsU8();
    var controller = try HidController.initWithMmio(capabilities, .{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });

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

test "xHCI HID controller reuses disconnected slots and discards stale input" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 2;
    capabilities.max_ports = 3;
    var controller = try HidController.initWithMmio(capabilities, .{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });

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

test "xHCI HID controller clamps ports and slots to MMIO capabilities" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_ports = 2;
    var controller = try HidController.initWithMmio(capabilities, .{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });

    try controller.connectPort(1, .high);
    try std.testing.expectEqual(@as(u8, 1), try controller.enableDeviceSlot(1));
    try controller.connectPort(2, .high);
    try std.testing.expectError(error.DeviceSlotUnavailable, controller.enableDeviceSlot(2));
    try std.testing.expectError(error.InvalidPort, controller.connectPort(3, .high));
    try std.testing.expectError(error.InvalidDeviceSlot, controller.addressDevice(2, DEFAULT_BOOT_KEYBOARD_DEVICE_ID));
}

test "xHCI HID controller queues interrupt keyboard reports" {
    var controller = try HidController.init(.{
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
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
        .command_ring_trbs = TEST_RING_TRBS,
        .event_ring_trbs = TEST_RING_TRBS,
        .command_ring_address = TEST_COMMAND_RING_ADDRESS,
        .event_ring_address = TEST_EVENT_RING_ADDRESS,
    });
    try std.testing.expectError(error.ReportTooLarge, bootKeyboardReport(0x8086_A0ED_0001, 1, 0, &.{ 1, 2, 3, 4, 5, 6, 7 }));

    const report = try bootKeyboardReport(0x8086_A0ED_0001, 1, 0, &.{0x04});
    for (0..HID_EVENT_QUEUE_CAPACITY) |_| {
        try controller.enqueueInterruptReport(report);
    }
    try std.testing.expectError(error.EventRingFull, controller.enqueueInterruptReport(report));
}
