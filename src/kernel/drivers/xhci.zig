const std = @import("std");
const endian = @import("../utils/endian.zig");
const spin = @import("../utils/spin.zig");

const readU16Le = endian.readU16Le;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU16Le = endian.writeU16Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const kernel_boundary_role = "bootstrap_xhci_input_inventory_shim";
pub const publishes_full_input_service = false;
pub const usb_input_data_plane_exports_fail_closed = true;

pub const TRB_BYTES: u32 = 16;
pub const RING_ALIGNMENT_BYTES: u64 = 64;
pub const ERST_ENTRY_BYTES: u32 = 16;
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
pub const HID_EVENT_QUEUE_CAPACITY: usize = 8;
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
pub const USB_ENDPOINT_DIRECTION_IN: u8 = 0x80;
pub const USB_ENDPOINT_TRANSFER_INTERRUPT: u8 = 0x03;
pub const DEFAULT_BOOT_KEYBOARD_DEVICE_ID: u64 = 0x8086_A0ED_0001;
pub const DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID: u8 = 1;
pub const DEFAULT_BOOT_KEYBOARD_PORT_ID: u8 = 1;
pub const MAX_BOOT_PORTS: usize = 32;
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
pub const CONTROLLER_HALT_TIMEOUT_MILLISECONDS: u64 = 16;
pub const CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS: u64 = 1_000;
pub const ContextSize = enum(u8) {
    bytes_32 = 32,
    bytes_64 = 64,

    pub fn byteCount(self: ContextSize) u32 {
        return @intFromEnum(self);
    }
};

const DEVICE_SLOT_TABLE_ENTRIES: usize = MAX_DEVICE_SLOTS + 1;
const MIN_CAPABILITY_LENGTH: u8 = 0x20;
const MIN_SUPPORTED_INTERFACE_VERSION: u16 = 0x0110;
const CAPABILITY_LENGTH_OFFSET: usize = 0x00;
const INTERFACE_VERSION_OFFSET: usize = 0x02;
const HCSPARAMS1_OFFSET: usize = 0x04;
const HCSPARAMS2_OFFSET: usize = 0x08;
const HCCPARAMS1_OFFSET: usize = 0x10;
const DOORBELL_OFFSET_OFFSET: usize = 0x14;
const RUNTIME_REGISTER_OFFSET_OFFSET: usize = 0x18;
const DOORBELL_OFFSET_ALIGNMENT_MASK: u32 = 0x3;
const RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK: u32 = 0x1F;
const U16_REGISTER_BYTES: usize = @sizeOf(u16);
const U32_REGISTER_BYTES: usize = @sizeOf(u32);
const HCSPARAMS1_MAX_INTERRUPTERS_SHIFT = 8;
const HCSPARAMS1_MAX_INTERRUPTERS_MASK: u32 = 0x7FF;
const HCSPARAMS1_MAX_PORTS_SHIFT = 24;
const HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT = 21;
const HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT = 27;
const HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK: u32 = 0x1F;
const HCSPARAMS2_SCRATCHPAD_RESTORE: u32 = 1 << 26;
const HCCPARAMS1_64_BIT_ADDRESSING: u32 = 1 << 0;
const HCCPARAMS1_CONTEXT_SIZE: u32 = 1 << 2;
const HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT = 16;
const EXTENDED_CAPABILITY_ID_MASK: u32 = 0xFF;
const EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT = 8;
const EXTENDED_CAPABILITY_NEXT_POINTER_MASK: u32 = 0xFF;
const EXTENDED_CAPABILITY_DWORD_SHIFT = 2;
const USB_LEGACY_SUPPORT_CAPABILITY_ID: u8 = 1;
const SUPPORTED_PROTOCOL_CAPABILITY_ID: u8 = 2;
const SUPPORTED_PROTOCOL_COMPATIBLE_PORTS_OFFSET: u32 = 0x08;
const SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET: u32 = 0x0C;
const SUPPORTED_PROTOCOL_SPEED_IDS_OFFSET: u32 = 0x10;
const SUPPORTED_PROTOCOL_USB_NAME_STRING: u32 = 0x2042_5355;
const SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT: u5 = 24;
const SUPPORTED_PROTOCOL_MINOR_REVISION_SHIFT: u5 = 16;
const SUPPORTED_PROTOCOL_PORT_COUNT_SHIFT: u5 = 8;
const SUPPORTED_PROTOCOL_SPEED_ID_COUNT_SHIFT: u5 = 28;
const USB_LEGACY_BIOS_OWNED_SEMAPHORE: u32 = 1 << 16;
const USB_LEGACY_OS_OWNED_SEMAPHORE: u32 = 1 << 24;
const OPERATIONAL_USB_COMMAND_OFFSET: u32 = 0x00;
const OPERATIONAL_USB_STATUS_OFFSET: u32 = 0x04;
const OPERATIONAL_PAGE_SIZE_OFFSET: u32 = 0x08;
const OPERATIONAL_COMMAND_RING_CONTROL_OFFSET: u32 = 0x18;
const OPERATIONAL_DEVICE_CONTEXT_BASE_ARRAY_POINTER_OFFSET: u32 = 0x30;
const OPERATIONAL_CONFIGURE_OFFSET: u32 = 0x38;
const OPERATIONAL_PORT_REGISTER_BASE_OFFSET: u32 = 0x400;
const OPERATIONAL_PORT_REGISTER_STRIDE: u32 = 0x10;
const USB_COMMAND_RUN_STOP: u32 = 1 << 0;
const USB_COMMAND_HOST_CONTROLLER_RESET: u32 = 1 << 1;
const USB_COMMAND_INTERRUPTER_ENABLE: u32 = 1 << 2;
const USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE: u32 = 1 << 3;
const USB_STATUS_HOST_CONTROLLER_HALTED: u32 = 1 << 0;
const USB_STATUS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const USB_STATUS_CONTROLLER_NOT_READY: u32 = 1 << 11;
const USB_STATUS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;
const PAGE_SIZE_4K_SUPPORTED: u32 = 1 << 0;
const COMMAND_RING_RUNNING: u64 = 1 << 3;
const COMMAND_RING_INITIAL_CYCLE_STATE: u64 = 1;
const PRIMARY_INTERRUPTER_OFFSET: u32 = 0x20;
const INTERRUPTER_MANAGEMENT_OFFSET: u32 = 0x00;
const INTERRUPTER_MODERATION_OFFSET: u32 = 0x04;
const EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET: u32 = 0x08;
const EVENT_RING_SEGMENT_TABLE_BASE_OFFSET: u32 = 0x10;
const EVENT_RING_DEQUEUE_POINTER_OFFSET: u32 = 0x18;
const INTERRUPTER_PENDING: u32 = 1 << 0;
const INTERRUPTER_ENABLE: u32 = 1 << 1;
const EVENT_HANDLER_BUSY: u64 = 1 << 3;
const INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS: u32 = 500;
const ADDRESS_64_BYTE_ALIGNMENT_MASK: u64 = RING_ALIGNMENT_BYTES - 1;
const EVENT_RING_DEQUEUE_POINTER_MASK: u64 = ~@as(u64, 0xF);
const LINK_TRB_TYPE: u32 = 6;
const LINK_TRB_TOGGLE_CYCLE: u32 = 1 << 1;
const SETUP_STAGE_TRB_TYPE: u32 = 2;
const DATA_STAGE_TRB_TYPE: u32 = 3;
const STATUS_STAGE_TRB_TYPE: u32 = 4;
const ENABLE_SLOT_COMMAND_TRB_TYPE: u32 = 9;
const DISABLE_SLOT_COMMAND_TRB_TYPE: u32 = 10;
const ADDRESS_DEVICE_COMMAND_TRB_TYPE: u32 = 11;
const CONFIGURE_ENDPOINT_COMMAND_TRB_TYPE: u32 = 12;
const EVALUATE_CONTEXT_COMMAND_TRB_TYPE: u32 = 13;
const TRB_TYPE_SHIFT: u5 = 10;
const TRB_TYPE_MASK: u32 = 0x3F;
const TRB_INTERRUPT_ON_SHORT_PACKET: u32 = 1 << 2;
const TRB_INTERRUPT_ON_COMPLETION: u32 = 1 << 5;
const TRB_IMMEDIATE_DATA: u32 = 1 << 6;
const CONTROL_TRANSFER_DIRECTION_IN: u32 = 1 << 16;
const STATUS_STAGE_DIRECTION_IN: u32 = 1 << 16;
const SETUP_TRANSFER_TYPE_IN: u32 = 3 << 16;
const EVENT_TRB_TRANSFER: u6 = 32;
const EVENT_TRB_COMMAND_COMPLETION: u6 = 33;
const EVENT_TRB_PORT_STATUS_CHANGE: u6 = 34;
const EVENT_TRB_BANDWIDTH_REQUEST: u6 = 35;
const EVENT_TRB_DOORBELL: u6 = 36;
const EVENT_TRB_HOST_CONTROLLER: u6 = 37;
const EVENT_TRB_DEVICE_NOTIFICATION: u6 = 38;
const EVENT_TRB_MFINDEX_WRAP: u6 = 39;
const EVENT_TRB_VENDOR_FIRST: u6 = 48;
const EVENT_TRB_VENDOR_LAST: u6 = 63;
const COMPLETION_CODE_SUCCESS: u8 = 1;
const ENDPOINT_TYPE_CONTROL: u32 = 4;
const ENDPOINT_TYPE_INTERRUPT_IN: u32 = 7;
const DEFAULT_ENDPOINT_ERROR_COUNT: u32 = 3;
const CONTROL_ENDPOINT_AVERAGE_TRB_LENGTH: u32 = 8;
const INTERRUPT_ENDPOINT_AVERAGE_TRB_LENGTH: u32 = 1024;
const USB_SETUP_PACKET_BYTES: u32 = 8;
const ADDRESS_DEVICE_ADD_CONTEXT_FLAGS: u32 = 0b11;
const EVALUATE_ENDPOINT_ZERO_ADD_CONTEXT_FLAGS: u32 = 0b10;
const ADDRESS_DEVICE_CONTEXT_ENTRIES: u32 = 1;
const USB_DEVICE_DESCRIPTOR_MAX_PACKET_SIZE_OFFSET: usize = 7;
const PORT_CURRENT_CONNECT_STATUS: u32 = 1 << 0;
const PORT_ENABLED_DISABLED: u32 = 1 << 1;
const PORT_OVER_CURRENT_ACTIVE: u32 = 1 << 3;
const PORT_RESET: u32 = 1 << 4;
const PORT_LINK_STATE_SHIFT: u5 = 5;
const PORT_LINK_STATE_MASK: u32 = 0xF;
const PORT_POWER: u32 = 1 << 9;
const PORT_SPEED_SHIFT: u5 = 10;
const PORT_SPEED_MASK: u32 = 0xF;
const PORT_COLD_ATTACH_STATUS: u32 = 1 << 24;
const PORT_WAKE_ENABLE_MASK: u32 = 0x7 << 25;
const PORT_INDICATOR_CONTROL_MASK: u32 = 0x3 << 14;
const PORT_CHANGE_MASK: u32 = 0x7F << 17;
const PORT_READ_WRITE_STICKY_MASK: u32 =
    (PORT_LINK_STATE_MASK << PORT_LINK_STATE_SHIFT) |
    PORT_POWER |
    PORT_INDICATOR_CONTROL_MASK |
    PORT_WAKE_ENABLE_MASK;
const CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK: u32 = 0xFF;
const TEST_CAPABILITY_LENGTH: u8 = 0x40;
const TEST_INTERFACE_VERSION: u16 = 0x0110;
const TEST_UNSUPPORTED_INTERFACE_VERSION: u16 = 0x0080;
const TEST_MAX_DEVICE_SLOTS: u8 = 32;
const TEST_MAX_INTERRUPTERS: u16 = 8;
const TEST_MAX_PORTS: u8 = 12;
const TEST_MAX_SCRATCHPAD_BUFFERS: u16 = 33;
const TEST_CONTEXT_SIZE: ContextSize = .bytes_64;
const TEST_DOORBELL_OFFSET: u32 = 0x2000;
const TEST_RUNTIME_REGISTER_OFFSET: u32 = 0x1000;
const TEST_RING_TRBS: u32 = COMMAND_RING_TRBS;
const TEST_COMMAND_RING_ADDRESS: u64 = 0x1000;
const TEST_EVENT_RING_ADDRESS: u64 = 0x2000;
const TEST_UNALIGNED_COMMAND_RING_ADDRESS: u64 = TEST_COMMAND_RING_ADDRESS + 1;

pub const Error = error{
    KernelUsbInputDataPlaneDisabled,
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

pub const EventType = enum(u8) {
    transfer,
    command_completion,
    port_status_change,
    bandwidth_request,
    doorbell,
    host_controller,
    device_notification,
    mfindex_wrap,
    vendor_defined,
    unknown,
};

pub const Event = struct {
    parameter: u64,
    kind: EventType,
    type_id: u6,
    transfer_length: u24,
    completion_code: u8,
    port_id: u8,
    slot_id: u8,
    endpoint_id: u5,
    event_data: bool,

    pub fn succeeded(self: Event) bool {
        return self.completion_code == COMPLETION_CODE_SUCCESS;
    }
};

pub const EventRingConsumer = struct {
    dequeue_index: u32 = 0,
    cycle_state: u1 = 1,

    pub fn ready(self: EventRingConsumer, control: u32) bool {
        return @as(u1, @truncate(control)) == self.cycle_state;
    }

    pub fn consume(
        self: *EventRingConsumer,
        words: [4]u32,
        ring_trbs: u32,
    ) Error!?Event {
        if (ring_trbs == 0 or self.dequeue_index >= ring_trbs) {
            return error.EventRingStateInvalid;
        }
        if (!self.ready(words[3])) return null;

        const event = decodeEvent(words);
        self.dequeue_index += 1;
        if (self.dequeue_index == ring_trbs) {
            self.dequeue_index = 0;
            self.cycle_state ^= 1;
        }
        return event;
    }

    pub fn dequeueAddress(
        self: EventRingConsumer,
        ring_address: u64,
        ring_trbs: u32,
    ) Error!u64 {
        if (ring_trbs == 0 or self.dequeue_index >= ring_trbs) {
            return error.EventRingStateInvalid;
        }
        const offset = std.math.mul(u64, self.dequeue_index, TRB_BYTES) catch
            return error.EventRingStateInvalid;
        return std.math.add(u64, ring_address, offset) catch
            return error.EventRingStateInvalid;
    }
};

pub fn decodeEvent(words: [4]u32) Event {
    const type_id: u6 = @truncate((words[3] >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK);
    const kind: EventType = switch (type_id) {
        EVENT_TRB_TRANSFER => .transfer,
        EVENT_TRB_COMMAND_COMPLETION => .command_completion,
        EVENT_TRB_PORT_STATUS_CHANGE => .port_status_change,
        EVENT_TRB_BANDWIDTH_REQUEST => .bandwidth_request,
        EVENT_TRB_DOORBELL => .doorbell,
        EVENT_TRB_HOST_CONTROLLER => .host_controller,
        EVENT_TRB_DEVICE_NOTIFICATION => .device_notification,
        EVENT_TRB_MFINDEX_WRAP => .mfindex_wrap,
        EVENT_TRB_VENDOR_FIRST...EVENT_TRB_VENDOR_LAST => .vendor_defined,
        else => .unknown,
    };
    return .{
        .parameter = @as(u64, words[0]) | (@as(u64, words[1]) << 32),
        .kind = kind,
        .type_id = type_id,
        .transfer_length = @truncate(words[2]),
        .completion_code = @truncate(words[2] >> 24),
        .port_id = @truncate(words[0] >> 24),
        .slot_id = @truncate(words[3] >> 24),
        .endpoint_id = @truncate(words[3] >> 16),
        .event_data = (words[3] & (1 << 2)) != 0,
    };
}

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

pub const UsbDeviceDescriptor = struct {
    usb_version_bcd: u16,
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    endpoint_zero_max_packet_size: u16,
    vendor_id: u16,
    product_id: u16,
    device_version_bcd: u16,
    manufacturer_string_index: u8,
    product_string_index: u8,
    serial_number_string_index: u8,
    configuration_count: u8,
};

pub const UsbConfigurationDescriptor = struct {
    total_length: u16,
    interface_count: u8,
    configuration_value: u8,
    string_index: u8,
    self_powered: bool,
    remote_wakeup: bool,
    max_power_milliamps: u16,
};

pub const UsbBootKeyboardConfiguration = struct {
    configuration_value: u8,
    interface_number: u8,
    endpoint_id: u8,
    device_context_index: u5,
    max_packet_size: u16,
    max_burst_size: u8,
    interval: u8,
    max_esit_payload: u16,
};

pub const UsbBootKeyboardSelection = struct {
    configuration: UsbConfigurationDescriptor,
    keyboard: UsbBootKeyboardConfiguration,
};

const PendingBootKeyboardEndpoint = struct {
    interface_number: u8,
    endpoint_id: u8,
    raw_max_packet_size: u16,
    descriptor_interval: u8,
};

pub const ConfigurationDescriptorParser = struct {
    protocol: PortProtocol,
    speed_id: ?u4 = null,
    header: ?UsbConfigurationDescriptor = null,
    bytes_consumed: usize = 0,
    interface_numbers: [4]u64 = [_]u64{0} ** 4,
    distinct_interface_count: u16 = 0,
    active_interface: bool = false,
    expected_endpoint_count: u8 = 0,
    seen_endpoint_count: u8 = 0,
    expects_superspeed_companion: bool = false,
    active_boot_keyboard_interface: ?u8 = null,
    saw_boot_keyboard_interface: bool = false,
    pending_boot_keyboard_endpoint: ?PendingBootKeyboardEndpoint = null,
    boot_keyboard: ?UsbBootKeyboardConfiguration = null,

    pub fn init(protocol: PortProtocol) ConfigurationDescriptorParser {
        return .{ .protocol = protocol };
    }

    pub fn initForPort(protocol: PortProtocol, speed_id: u4) ConfigurationDescriptorParser {
        return .{ .protocol = protocol, .speed_id = speed_id };
    }

    pub fn consume(self: *ConfigurationDescriptorParser, descriptor: []const u8) Error!void {
        if (descriptor.len < 2 or descriptor.len != descriptor[0]) {
            return error.InvalidUsbDescriptor;
        }
        const descriptor_type = descriptor[1];
        if (self.header == null) {
            if (descriptor_type != USB_DESCRIPTOR_CONFIGURATION) {
                return error.InvalidUsbDescriptor;
            }
            self.header = try parseUsbConfigurationDescriptorHeader(self.protocol, descriptor);
            self.bytes_consumed = descriptor.len;
            return;
        }
        if (descriptor_type == USB_DESCRIPTOR_CONFIGURATION) {
            return error.InvalidUsbDescriptor;
        }
        if (self.expects_superspeed_companion) {
            if (descriptor_type != USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION or
                descriptor.len != 6)
            {
                return error.InvalidUsbDescriptor;
            }
            if (self.pending_boot_keyboard_endpoint) |endpoint| {
                self.boot_keyboard = try superspeedBootKeyboardConfiguration(
                    self.protocol,
                    self.header.?.configuration_value,
                    endpoint,
                    descriptor,
                    self.speed_id orelse return error.InvalidProtocolSpeed,
                );
                self.pending_boot_keyboard_endpoint = null;
            }
            self.expects_superspeed_companion = false;
            self.bytes_consumed = std.math.add(
                usize,
                self.bytes_consumed,
                descriptor.len,
            ) catch return error.InvalidUsbDescriptor;
            return;
        }
        switch (descriptor_type) {
            USB_DESCRIPTOR_INTERFACE => {
                try self.finishActiveInterface();
                if (descriptor.len < USB_CONFIGURATION_DESCRIPTOR_BYTES or descriptor[5] == 0) {
                    return error.InvalidUsbDescriptor;
                }
                const header = self.header.?;
                const interface_number = descriptor[2];
                if (interface_number >= header.interface_count) return error.InvalidUsbDescriptor;
                const word_index: usize = interface_number / 64;
                const bit = @as(u64, 1) << @intCast(interface_number % 64);
                if ((self.interface_numbers[word_index] & bit) == 0) {
                    self.interface_numbers[word_index] |= bit;
                    self.distinct_interface_count += 1;
                }
                self.active_interface = true;
                self.expected_endpoint_count = descriptor[4];
                self.seen_endpoint_count = 0;
                const is_default_boot_keyboard = descriptor[3] == 0 and
                    descriptor[5] == USB_CLASS_HID and
                    descriptor[6] == USB_HID_SUBCLASS_BOOT and
                    descriptor[7] == USB_HID_PROTOCOL_KEYBOARD;
                self.active_boot_keyboard_interface = if (is_default_boot_keyboard)
                    interface_number
                else
                    null;
                self.saw_boot_keyboard_interface = self.saw_boot_keyboard_interface or
                    is_default_boot_keyboard;
            },
            USB_DESCRIPTOR_ENDPOINT => {
                if (!self.active_interface or descriptor.len < 7 or
                    self.seen_endpoint_count >= self.expected_endpoint_count)
                {
                    return error.InvalidUsbDescriptor;
                }
                const endpoint_address = descriptor[2];
                const transfer_type = descriptor[3] & 0x03;
                const packet_payload_bytes = readU16Le(descriptor[4..6]) & 0x07FF;
                if ((endpoint_address & 0x70) != 0 or (endpoint_address & 0x0F) == 0 or
                    (transfer_type != 1 and packet_payload_bytes == 0))
                {
                    return error.InvalidUsbDescriptor;
                }
                self.seen_endpoint_count += 1;
                if (self.speed_id != null and self.boot_keyboard == null and
                    self.active_boot_keyboard_interface != null and
                    (endpoint_address & USB_ENDPOINT_DIRECTION_IN) != 0 and
                    transfer_type == USB_ENDPOINT_TRANSFER_INTERRUPT)
                {
                    const endpoint = PendingBootKeyboardEndpoint{
                        .interface_number = self.active_boot_keyboard_interface.?,
                        .endpoint_id = endpoint_address & 0x0F,
                        .raw_max_packet_size = readU16Le(descriptor[4..6]),
                        .descriptor_interval = descriptor[6],
                    };
                    switch (self.protocol.kind) {
                        .usb2 => self.boot_keyboard = try usb2BootKeyboardConfiguration(
                            self.protocol,
                            self.speed_id.?,
                            self.header.?.configuration_value,
                            endpoint,
                        ),
                        .usb3 => self.pending_boot_keyboard_endpoint = endpoint,
                    }
                }
                self.expects_superspeed_companion = self.protocol.kind == .usb3;
            },
            USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION => {
                return error.InvalidUsbDescriptor;
            },
            else => {},
        }
        self.bytes_consumed = std.math.add(
            usize,
            self.bytes_consumed,
            descriptor.len,
        ) catch return error.InvalidUsbDescriptor;
    }

    pub fn finish(
        self: *ConfigurationDescriptorParser,
        expected_bytes: usize,
    ) Error!UsbConfigurationDescriptor {
        try self.finishActiveInterface();
        if (self.expects_superspeed_companion) return error.InvalidUsbDescriptor;
        const header = self.header orelse return error.InvalidUsbDescriptor;
        if (self.bytes_consumed != expected_bytes or
            expected_bytes != header.total_length or
            self.distinct_interface_count != header.interface_count)
        {
            return error.InvalidUsbDescriptor;
        }
        return header;
    }

    pub fn finishBootKeyboard(
        self: *ConfigurationDescriptorParser,
        expected_bytes: usize,
    ) Error!UsbBootKeyboardSelection {
        const configuration = try self.finish(expected_bytes);
        const keyboard = self.boot_keyboard orelse {
            if (self.saw_boot_keyboard_interface) return error.MissingInterruptInEndpoint;
            return error.MissingBootKeyboardInterface;
        };
        return .{ .configuration = configuration, .keyboard = keyboard };
    }

    fn finishActiveInterface(self: *ConfigurationDescriptorParser) Error!void {
        if (self.active_interface and self.seen_endpoint_count != self.expected_endpoint_count) {
            return error.InvalidUsbDescriptor;
        }
    }
};

pub fn interruptInDeviceContextIndex(endpoint_id: u8) Error!u5 {
    if (endpoint_id == 0 or endpoint_id > 15) return error.InvalidUsbDescriptor;
    return @intCast(@as(u16, endpoint_id) * 2 + 1);
}

fn usb2BootKeyboardConfiguration(
    protocol: PortProtocol,
    speed_id: u4,
    configuration_value: u8,
    endpoint: PendingBootKeyboardEndpoint,
) Error!UsbBootKeyboardConfiguration {
    if (protocol.kind != .usb2 or speed_id == 0 or
        (protocol.speed_ids & (@as(u16, 1) << speed_id)) == 0 or
        (endpoint.raw_max_packet_size & 0xE000) != 0 or
        endpoint.descriptor_interval == 0)
    {
        return error.InvalidUsbDescriptor;
    }
    const max_packet_size = endpoint.raw_max_packet_size & 0x07FF;
    const additional_transactions: u8 = @truncate(endpoint.raw_max_packet_size >> 11);
    if (max_packet_size < HID_BOOT_KEYBOARD_REPORT_BYTES) {
        return error.InvalidUsbDescriptor;
    }
    const speed_bit = @as(u16, 1) << speed_id;
    const interval: u8 = if ((protocol.high_speed_ids & speed_bit) != 0) high_speed: {
        if (max_packet_size > 1024 or additional_transactions > 2 or
            endpoint.descriptor_interval > 16)
        {
            return error.InvalidUsbDescriptor;
        }
        break :high_speed endpoint.descriptor_interval - 1;
    } else if ((protocol.full_speed_ids & speed_bit) != 0) full_speed: {
        if (max_packet_size > 64 or additional_transactions != 0) {
            return error.InvalidUsbDescriptor;
        }
        break :full_speed fullOrLowSpeedInterruptInterval(endpoint.descriptor_interval);
    } else if ((protocol.low_speed_ids & speed_bit) != 0) low_speed: {
        if (max_packet_size > HID_BOOT_KEYBOARD_REPORT_BYTES or additional_transactions != 0) {
            return error.InvalidUsbDescriptor;
        }
        break :low_speed fullOrLowSpeedInterruptInterval(endpoint.descriptor_interval);
    } else return error.InvalidProtocolSpeed;
    const max_esit_payload = std.math.mul(
        u16,
        max_packet_size,
        @as(u16, additional_transactions) + 1,
    ) catch return error.InvalidUsbDescriptor;
    return .{
        .configuration_value = configuration_value,
        .interface_number = endpoint.interface_number,
        .endpoint_id = endpoint.endpoint_id,
        .device_context_index = try interruptInDeviceContextIndex(endpoint.endpoint_id),
        .max_packet_size = max_packet_size,
        .max_burst_size = additional_transactions,
        .interval = interval,
        .max_esit_payload = max_esit_payload,
    };
}

fn superspeedBootKeyboardConfiguration(
    protocol: PortProtocol,
    configuration_value: u8,
    endpoint: PendingBootKeyboardEndpoint,
    companion: []const u8,
    speed_id: u4,
) Error!UsbBootKeyboardConfiguration {
    if (protocol.kind != .usb3 or speed_id == 0 or
        (protocol.speed_ids & (@as(u16, 1) << speed_id)) == 0 or
        companion.len != 6 or companion[2] > 15 or
        companion[3] != 0 or endpoint.descriptor_interval == 0 or
        endpoint.descriptor_interval > 16 or
        (endpoint.raw_max_packet_size & 0xF800) != 0)
    {
        return error.InvalidUsbDescriptor;
    }
    const max_packet_size = endpoint.raw_max_packet_size & 0x07FF;
    const max_esit_payload = readU16Le(companion[4..6]);
    const maximum_payload = std.math.mul(
        u16,
        max_packet_size,
        @as(u16, companion[2]) + 1,
    ) catch return error.InvalidUsbDescriptor;
    if (max_packet_size < HID_BOOT_KEYBOARD_REPORT_BYTES or max_packet_size > 1024 or
        max_esit_payload < HID_BOOT_KEYBOARD_REPORT_BYTES or
        max_esit_payload > maximum_payload)
    {
        return error.InvalidUsbDescriptor;
    }
    return .{
        .configuration_value = configuration_value,
        .interface_number = endpoint.interface_number,
        .endpoint_id = endpoint.endpoint_id,
        .device_context_index = try interruptInDeviceContextIndex(endpoint.endpoint_id),
        .max_packet_size = max_packet_size,
        .max_burst_size = companion[2],
        .interval = endpoint.descriptor_interval - 1,
        .max_esit_payload = max_esit_payload,
    };
}

fn fullOrLowSpeedInterruptInterval(descriptor_interval: u8) u8 {
    var units: u16 = @as(u16, descriptor_interval) * 8;
    var interval: u8 = 0;
    while (units > 1) : (units >>= 1) interval += 1;
    return interval;
}

pub const SupportedProtocols = struct {
    ports: [256]?PortProtocol = [_]?PortProtocol{null} ** 256,

    pub fn forPort(self: *const SupportedProtocols, port_id: u8) ?PortProtocol {
        if (port_id == 0) return null;
        return self.ports[port_id];
    }
};

pub const PortStatus = struct {
    connected: bool,
    enabled: bool,
    over_current: bool,
    reset_active: bool,
    link_state: u4,
    powered: bool,
    speed: u4,
    cold_attach: bool,
    change_bits: u7,
};

pub const CommandKind = enum(u8) {
    enable_slot,
    disable_slot,
    address_device,
    configure_endpoint,
    evaluate_context,
};

pub const TrbRingProducer = struct {
    enqueue_index: u32 = 0,
    cycle_state: u1 = 1,

    pub fn trbAddress(self: TrbRingProducer, ring_address: u64, ring_trbs: u32) Error!u64 {
        if (ring_address == 0 or !aligned(ring_address, RING_ALIGNMENT_BYTES) or
            ring_trbs < 2 or self.enqueue_index >= ring_trbs - 1)
        {
            return error.TrbRingStateInvalid;
        }
        const offset = std.math.mul(u64, self.enqueue_index, TRB_BYTES) catch
            return error.TrbRingStateInvalid;
        return std.math.add(u64, ring_address, offset) catch
            return error.TrbRingStateInvalid;
    }

    pub fn linkAddress(self: TrbRingProducer, ring_address: u64, ring_trbs: u32) Error!u64 {
        _ = self;
        if (ring_address == 0 or !aligned(ring_address, RING_ALIGNMENT_BYTES) or ring_trbs < 2) {
            return error.TrbRingStateInvalid;
        }
        const offset = std.math.mul(u64, ring_trbs - 1, TRB_BYTES) catch
            return error.TrbRingStateInvalid;
        return std.math.add(u64, ring_address, offset) catch
            return error.TrbRingStateInvalid;
    }

    pub fn advance(self: *TrbRingProducer, ring_trbs: u32) Error!bool {
        if (ring_trbs < 2 or self.enqueue_index >= ring_trbs - 1) {
            return error.TrbRingStateInvalid;
        }
        self.enqueue_index += 1;
        if (self.enqueue_index == ring_trbs - 1) {
            self.enqueue_index = 0;
            self.cycle_state ^= 1;
            return true;
        }
        return false;
    }
};

pub fn decodePortStatus(value: u32) PortStatus {
    return .{
        .connected = (value & PORT_CURRENT_CONNECT_STATUS) != 0,
        .enabled = (value & PORT_ENABLED_DISABLED) != 0,
        .over_current = (value & PORT_OVER_CURRENT_ACTIVE) != 0,
        .reset_active = (value & PORT_RESET) != 0,
        .link_state = @truncate((value >> PORT_LINK_STATE_SHIFT) & PORT_LINK_STATE_MASK),
        .powered = (value & PORT_POWER) != 0,
        .speed = @truncate((value >> PORT_SPEED_SHIFT) & PORT_SPEED_MASK),
        .cold_attach = (value & PORT_COLD_ATTACH_STATUS) != 0,
        .change_bits = @truncate((value & PORT_CHANGE_MASK) >> 17),
    };
}

pub fn portStatusAcknowledge(value: u32) u32 {
    return (value & PORT_READ_WRITE_STICKY_MASK) | (value & PORT_CHANGE_MASK);
}

pub fn portResetWrite(value: u32, protocol: PortProtocol) u32 {
    return portStatusAcknowledge(value) |
        (if (protocol.kind == .usb2) PORT_RESET else @as(u32, 1) << 31);
}

pub fn portRegisterOffset(capabilities: CapabilityRegisters, port_id: u8) Error!u32 {
    if (port_id == 0 or port_id > capabilities.max_ports) return error.InvalidPort;
    const relative = std.math.mul(
        u32,
        @as(u32, port_id - 1),
        OPERATIONAL_PORT_REGISTER_STRIDE,
    ) catch return error.InvalidPort;
    return std.math.add(
        u32,
        @as(u32, capabilities.capability_length) + OPERATIONAL_PORT_REGISTER_BASE_OFFSET,
        relative,
    ) catch return error.InvalidPort;
}

pub fn enableSlotCommand(slot_type: u5, cycle_state: u1) [4]u32 {
    return .{
        0,
        0,
        0,
        (@as(u32, slot_type) << 16) |
            (ENABLE_SLOT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            cycle_state,
    };
}

pub fn disableSlotCommand(slot_id: u8, cycle_state: u1) Error![4]u32 {
    if (slot_id == 0) return error.InvalidDeviceSlot;
    return .{
        0,
        0,
        0,
        (@as(u32, slot_id) << 24) |
            (DISABLE_SLOT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            cycle_state,
    };
}

pub fn ringLinkControl(cycle_state: u1) u32 {
    return (LINK_TRB_TYPE << TRB_TYPE_SHIFT) | LINK_TRB_TOGGLE_CYCLE | cycle_state;
}

pub fn ringCommandDoorbell(capabilities: CapabilityRegisters, mmio: anytype) Error!void {
    if (capabilities.doorbell_offset == 0) return error.MissingDoorbellRegisters;
    if ((capabilities.doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) {
        return error.InvalidDoorbellOffset;
    }
    mmio.writeReg32(capabilities.doorbell_offset, 0);
}

pub fn ringDeviceDoorbell(
    capabilities: CapabilityRegisters,
    slot_id: u8,
    endpoint_id: u5,
    mmio: anytype,
) Error!void {
    if (capabilities.doorbell_offset == 0) return error.MissingDoorbellRegisters;
    if ((capabilities.doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) {
        return error.InvalidDoorbellOffset;
    }
    if (slot_id == 0 or slot_id > capabilities.max_device_slots or
        slot_id > maxDeviceSlotsU8())
    {
        return error.InvalidDeviceSlot;
    }
    if (endpoint_id == 0) return error.EndpointMismatch;
    const slot_offset = std.math.mul(u32, slot_id, @sizeOf(u32)) catch
        return error.InvalidDoorbellOffset;
    const offset = std.math.add(u32, capabilities.doorbell_offset, slot_offset) catch
        return error.InvalidDoorbellOffset;
    mmio.writeReg32(offset, endpoint_id);
}

pub fn endpointZeroMaxPacketSize(protocol: PortProtocol, speed_id: u4) Error!u16 {
    if (speed_id == 0 or (protocol.speed_ids & (@as(u16, 1) << speed_id)) == 0) {
        return error.InvalidProtocolSpeed;
    }
    return switch (protocol.kind) {
        .usb2 => if ((protocol.high_speed_ids & (@as(u16, 1) << speed_id)) != 0) 64 else 8,
        .usb3 => 512,
    };
}

pub fn deviceDescriptorEndpointZeroMaxPacketSize(
    protocol: PortProtocol,
    speed_id: u4,
    descriptor_prefix: []const u8,
) Error!u16 {
    _ = try endpointZeroMaxPacketSize(protocol, speed_id);
    if (descriptor_prefix.len < USB_DEVICE_DESCRIPTOR_PREFIX_BYTES or
        descriptor_prefix[0] != USB_DEVICE_DESCRIPTOR_BYTES or
        descriptor_prefix[1] != USB_DESCRIPTOR_DEVICE)
    {
        return error.InvalidUsbDescriptor;
    }
    const encoded = descriptor_prefix[USB_DEVICE_DESCRIPTOR_MAX_PACKET_SIZE_OFFSET];
    return switch (protocol.kind) {
        .usb3 => if (encoded == 9) 512 else error.InvalidUsbDescriptor,
        .usb2 => packet_size: {
            const speed_bit = @as(u16, 1) << speed_id;
            if ((protocol.low_speed_ids & speed_bit) != 0) {
                if (encoded != 8) return error.InvalidUsbDescriptor;
                break :packet_size 8;
            }
            if ((protocol.high_speed_ids & speed_bit) != 0) {
                if (encoded != 64) return error.InvalidUsbDescriptor;
                break :packet_size 64;
            }
            if ((protocol.full_speed_ids & speed_bit) == 0) {
                return error.InvalidProtocolSpeed;
            }
            break :packet_size switch (encoded) {
                8, 16, 32, 64 => encoded,
                else => return error.InvalidUsbDescriptor,
            };
        },
    };
}

pub fn parseUsbDeviceDescriptor(
    protocol: PortProtocol,
    speed_id: u4,
    descriptor: []const u8,
) Error!UsbDeviceDescriptor {
    if (descriptor.len < USB_DEVICE_DESCRIPTOR_BYTES or
        descriptor[0] != USB_DEVICE_DESCRIPTOR_BYTES or
        descriptor[1] != USB_DESCRIPTOR_DEVICE)
    {
        return error.InvalidUsbDescriptor;
    }
    const usb_version_bcd = readU16Le(descriptor[2..4]);
    const device_class = descriptor[4];
    const device_subclass = descriptor[5];
    const device_version_bcd = readU16Le(descriptor[12..14]);
    const configuration_count = descriptor[17];
    if (!validBcd(usb_version_bcd) or !validBcd(device_version_bcd) or
        (device_class == 0 and device_subclass != 0) or configuration_count == 0)
    {
        return error.InvalidUsbDescriptor;
    }
    switch (protocol.kind) {
        .usb2 => if (usb_version_bcd < 0x0100 or usb_version_bcd >= 0x0300) {
            return error.InvalidUsbDescriptor;
        },
        .usb3 => if (usb_version_bcd < 0x0300 or usb_version_bcd >= 0x0400) {
            return error.InvalidUsbDescriptor;
        },
    }
    return .{
        .usb_version_bcd = usb_version_bcd,
        .device_class = device_class,
        .device_subclass = device_subclass,
        .device_protocol = descriptor[6],
        .endpoint_zero_max_packet_size = try deviceDescriptorEndpointZeroMaxPacketSize(
            protocol,
            speed_id,
            descriptor,
        ),
        .vendor_id = readU16Le(descriptor[8..10]),
        .product_id = readU16Le(descriptor[10..12]),
        .device_version_bcd = device_version_bcd,
        .manufacturer_string_index = descriptor[14],
        .product_string_index = descriptor[15],
        .serial_number_string_index = descriptor[16],
        .configuration_count = configuration_count,
    };
}

pub fn parseUsbConfigurationDescriptorHeader(
    protocol: PortProtocol,
    descriptor: []const u8,
) Error!UsbConfigurationDescriptor {
    if (descriptor.len < USB_CONFIGURATION_DESCRIPTOR_BYTES or
        descriptor[0] != USB_CONFIGURATION_DESCRIPTOR_BYTES or
        descriptor[1] != USB_DESCRIPTOR_CONFIGURATION)
    {
        return error.InvalidUsbDescriptor;
    }
    const total_length = readU16Le(descriptor[2..4]);
    const interface_count = descriptor[4];
    const configuration_value = descriptor[5];
    const attributes = descriptor[7];
    if (total_length < descriptor[0] or interface_count == 0 or
        configuration_value == 0 or (attributes & 0x9F) != 0x80)
    {
        return error.InvalidUsbDescriptor;
    }
    const power_unit_milliamps: u16 = switch (protocol.kind) {
        .usb2 => 2,
        .usb3 => 8,
    };
    return .{
        .total_length = total_length,
        .interface_count = interface_count,
        .configuration_value = configuration_value,
        .string_index = descriptor[6],
        .self_powered = (attributes & 0x40) != 0,
        .remote_wakeup = (attributes & 0x20) != 0,
        .max_power_milliamps = @as(u16, descriptor[8]) * power_unit_milliamps,
    };
}

pub fn parseUsbConfigurationDescriptor(
    protocol: PortProtocol,
    descriptors: []const u8,
) Error!UsbConfigurationDescriptor {
    var parser = ConfigurationDescriptorParser.init(protocol);
    var offset: usize = 0;
    while (offset < descriptors.len) {
        if (offset + 2 > descriptors.len) return error.InvalidUsbDescriptor;
        const descriptor_length: usize = descriptors[offset];
        const end = std.math.add(usize, offset, descriptor_length) catch
            return error.InvalidUsbDescriptor;
        if (descriptor_length < 2 or end > descriptors.len) {
            return error.InvalidUsbDescriptor;
        }
        try parser.consume(descriptors[offset..end]);
        offset = end;
    }
    return parser.finish(descriptors.len);
}

pub fn parseUsbBootKeyboardConfiguration(
    protocol: PortProtocol,
    speed_id: u4,
    descriptors: []const u8,
) Error!UsbBootKeyboardSelection {
    var parser = ConfigurationDescriptorParser.initForPort(protocol, speed_id);
    var offset: usize = 0;
    while (offset < descriptors.len) {
        if (offset + 2 > descriptors.len) return error.InvalidUsbDescriptor;
        const descriptor_length: usize = descriptors[offset];
        const end = std.math.add(usize, offset, descriptor_length) catch
            return error.InvalidUsbDescriptor;
        if (descriptor_length < 2 or end > descriptors.len) {
            return error.InvalidUsbDescriptor;
        }
        try parser.consume(descriptors[offset..end]);
        offset = end;
    }
    return parser.finishBootKeyboard(descriptors.len);
}

fn validBcd(value: u16) bool {
    return (value & 0x000F) <= 9 and
        ((value >> 4) & 0x000F) <= 9 and
        ((value >> 8) & 0x000F) <= 9 and
        ((value >> 12) & 0x000F) <= 9;
}

pub fn getDescriptorSetupStage(
    descriptor_type: u8,
    descriptor_index: u8,
    descriptor_length: u16,
    cycle_state: u1,
) Error![4]u32 {
    if (descriptor_type == 0 or descriptor_length == 0) return error.InvalidUsbDescriptor;
    return .{
        0x0000_0680 |
            (@as(u32, descriptor_index) << 16) |
            (@as(u32, descriptor_type) << 24),
        @as(u32, descriptor_length) << 16,
        USB_SETUP_PACKET_BYTES,
        SETUP_TRANSFER_TYPE_IN |
            (SETUP_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_IMMEDIATE_DATA |
            cycle_state,
    };
}

pub fn setConfigurationSetupStage(
    configuration_value: u8,
    cycle_state: u1,
) Error![4]u32 {
    if (configuration_value == 0) return error.InvalidUsbDescriptor;
    return .{
        (@as(u32, configuration_value) << 16) |
            (@as(u32, USB_REQUEST_SET_CONFIGURATION) << 8),
        0,
        USB_SETUP_PACKET_BYTES,
        (SETUP_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_IMMEDIATE_DATA |
            cycle_state,
    };
}

pub fn controlInDataStage(
    buffer_address: u64,
    transfer_bytes: u17,
    cycle_state: u1,
) Error![4]u32 {
    if (buffer_address == 0 or transfer_bytes == 0) return error.DmaAddressOutsidePlan;
    const boundary_offset = buffer_address & (XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES - 1);
    if (boundary_offset + transfer_bytes > XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) {
        return error.DmaAddressOutsidePlan;
    }
    return .{
        @truncate(buffer_address),
        @truncate(buffer_address >> 32),
        transfer_bytes,
        CONTROL_TRANSFER_DIRECTION_IN |
            (DATA_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_SHORT_PACKET |
            cycle_state,
    };
}

pub fn controlOutStatusStage(cycle_state: u1) [4]u32 {
    return .{
        0,
        0,
        0,
        (STATUS_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_COMPLETION |
            cycle_state,
    };
}

pub fn controlInStatusStage(cycle_state: u1) [4]u32 {
    return .{
        0,
        0,
        0,
        STATUS_STAGE_DIRECTION_IN |
            (STATUS_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_COMPLETION |
            cycle_state,
    };
}

pub fn addressDeviceCommand(
    input_context_address: u64,
    slot_id: u8,
    cycle_state: u1,
) Error![4]u32 {
    if (input_context_address == 0 or (input_context_address & 0xF) != 0) {
        return error.InvalidInputContext;
    }
    if (slot_id == 0) return error.InvalidDeviceSlot;
    return .{
        @truncate(input_context_address),
        @truncate(input_context_address >> 32),
        0,
        (@as(u32, slot_id) << 24) |
            (ADDRESS_DEVICE_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            cycle_state,
    };
}

pub fn configureEndpointCommand(
    input_context_address: u64,
    slot_id: u8,
    cycle_state: u1,
) Error![4]u32 {
    if (input_context_address == 0 or (input_context_address & 0xF) != 0) {
        return error.InvalidInputContext;
    }
    if (slot_id == 0) return error.InvalidDeviceSlot;
    return .{
        @truncate(input_context_address),
        @truncate(input_context_address >> 32),
        0,
        (@as(u32, slot_id) << 24) |
            (CONFIGURE_ENDPOINT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            cycle_state,
    };
}

pub fn evaluateContextCommand(
    input_context_address: u64,
    slot_id: u8,
    cycle_state: u1,
) Error![4]u32 {
    if (input_context_address == 0 or (input_context_address & 0xF) != 0) {
        return error.InvalidInputContext;
    }
    if (slot_id == 0) return error.InvalidDeviceSlot;
    return .{
        @truncate(input_context_address),
        @truncate(input_context_address >> 32),
        0,
        (@as(u32, slot_id) << 24) |
            (EVALUATE_CONTEXT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            cycle_state,
    };
}

pub fn initializeAddressDeviceInputContext(
    context_size: ContextSize,
    port_id: u8,
    speed_id: u4,
    max_packet_size: u16,
    control_transfer_ring_address: u64,
    input_context: []u8,
) Error!void {
    if (port_id == 0 or speed_id == 0 or
        (max_packet_size != 8 and max_packet_size != 64 and max_packet_size != 512) or
        control_transfer_ring_address == 0 or
        !aligned(control_transfer_ring_address, RING_ALIGNMENT_BYTES))
    {
        return error.InvalidInputContext;
    }
    const entry_bytes: usize = context_size.byteCount();
    const required_bytes = std.math.mul(usize, INPUT_CONTEXT_ENTRIES, entry_bytes) catch
        return error.InvalidInputContext;
    if (input_context.len < required_bytes) return error.InvalidInputContext;
    @memset(input_context[0..required_bytes], 0);

    writeU32Le(input_context[4..8], ADDRESS_DEVICE_ADD_CONTEXT_FLAGS);
    const slot_context = input_context[entry_bytes..][0..entry_bytes];
    writeU32Le(
        slot_context[0..4],
        (@as(u32, speed_id) << 20) | (ADDRESS_DEVICE_CONTEXT_ENTRIES << 27),
    );
    writeU32Le(slot_context[4..8], @as(u32, port_id) << 16);

    const endpoint_context = input_context[2 * entry_bytes ..][0..entry_bytes];
    writeU32Le(
        endpoint_context[4..8],
        (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
            (ENDPOINT_TYPE_CONTROL << 3) |
            (@as(u32, max_packet_size) << 16),
    );
    writeU64Le(endpoint_context[8..16], control_transfer_ring_address | 1);
    writeU32Le(endpoint_context[16..20], CONTROL_ENDPOINT_AVERAGE_TRB_LENGTH);
}

pub fn initializeEvaluateEndpointZeroInputContext(
    context_size: ContextSize,
    max_packet_size: u16,
    input_context: []u8,
) Error!void {
    if (max_packet_size != 8 and max_packet_size != 16 and
        max_packet_size != 32 and max_packet_size != 64 and max_packet_size != 512)
    {
        return error.InvalidInputContext;
    }
    const entry_bytes: usize = context_size.byteCount();
    const required_bytes = std.math.mul(usize, INPUT_CONTEXT_ENTRIES, entry_bytes) catch
        return error.InvalidInputContext;
    if (input_context.len < required_bytes) return error.InvalidInputContext;
    @memset(input_context[0..required_bytes], 0);
    writeU32Le(input_context[4..8], EVALUATE_ENDPOINT_ZERO_ADD_CONTEXT_FLAGS);
    const endpoint_context = input_context[2 * entry_bytes ..][0..entry_bytes];
    writeU32Le(endpoint_context[4..8], @as(u32, max_packet_size) << 16);
}

pub fn initializeConfigureInterruptInEndpointInputContext(
    context_size: ContextSize,
    keyboard: UsbBootKeyboardConfiguration,
    interrupt_transfer_ring_address: u64,
    input_context: []u8,
) Error!void {
    const expected_dci = try interruptInDeviceContextIndex(keyboard.endpoint_id);
    const maximum_payload = std.math.mul(
        u16,
        keyboard.max_packet_size,
        @as(u16, keyboard.max_burst_size) + 1,
    ) catch return error.InvalidInputContext;
    if (keyboard.configuration_value == 0 or
        keyboard.device_context_index != expected_dci or
        keyboard.max_packet_size < HID_BOOT_KEYBOARD_REPORT_BYTES or
        keyboard.max_packet_size > 1024 or keyboard.max_burst_size > 15 or
        keyboard.interval > 15 or
        keyboard.max_esit_payload < HID_BOOT_KEYBOARD_REPORT_BYTES or
        keyboard.max_esit_payload > maximum_payload or
        interrupt_transfer_ring_address == 0 or
        !aligned(interrupt_transfer_ring_address, RING_ALIGNMENT_BYTES))
    {
        return error.InvalidInputContext;
    }
    const entry_bytes: usize = context_size.byteCount();
    const required_bytes = std.math.mul(usize, INPUT_CONTEXT_ENTRIES, entry_bytes) catch
        return error.InvalidInputContext;
    if (input_context.len < required_bytes) return error.InvalidInputContext;
    @memset(input_context[0..required_bytes], 0);

    writeU32Le(
        input_context[4..8],
        (@as(u32, 1) << 0) | (@as(u32, 1) << keyboard.device_context_index),
    );
    const slot_context = input_context[entry_bytes..][0..entry_bytes];
    writeU32Le(
        slot_context[0..4],
        @as(u32, keyboard.device_context_index) << 27,
    );

    const endpoint_offset = (@as(usize, keyboard.device_context_index) + 1) * entry_bytes;
    const endpoint_context = input_context[endpoint_offset..][0..entry_bytes];
    writeU32Le(endpoint_context[0..4], @as(u32, keyboard.interval) << 16);
    writeU32Le(
        endpoint_context[4..8],
        (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
            (ENDPOINT_TYPE_INTERRUPT_IN << 3) |
            (@as(u32, keyboard.max_burst_size) << 8) |
            (@as(u32, keyboard.max_packet_size) << 16),
    );
    writeU64Le(endpoint_context[8..16], interrupt_transfer_ring_address | 1);
    writeU32Le(
        endpoint_context[16..20],
        INTERRUPT_ENDPOINT_AVERAGE_TRB_LENGTH |
            (@as(u32, keyboard.max_esit_payload) << 16),
    );
}

pub const DmaArenaPlan = struct {
    base_address: u64,
    total_bytes: u64,
    enabled_device_slots: u8,
    dcbaa_address: u64,
    dcbaa_bytes: u32,
    scratchpad_array_address: u64,
    scratchpad_array_bytes: u64,
    scratchpad_buffers_address: u64,
    scratchpad_buffers_bytes: u64,
    device_contexts_address: u64,
    device_context_stride: u32,
    device_contexts_bytes: u64,
    enumeration_buffer_address: u64,
    enumeration_buffer_bytes: u32,
    input_context_address: u64,
    input_context_bytes: u32,
    control_transfer_rings_address: u64,
    control_transfer_ring_stride: u32,
    control_transfer_ring_trbs: u32,
    control_transfer_rings_bytes: u64,
    interrupt_transfer_rings_address: u64,
    interrupt_transfer_ring_stride: u32,
    interrupt_transfer_ring_trbs: u32,
    interrupt_transfer_rings_bytes: u64,
    interrupt_report_buffers_address: u64,
    interrupt_report_buffer_stride: u32,
    interrupt_report_buffers_bytes: u64,

    pub fn deviceContextAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        if (slot_id == 0 or slot_id > self.enabled_device_slots) return error.InvalidDeviceSlot;
        const offset = std.math.mul(
            u64,
            @as(u64, slot_id - 1),
            @as(u64, self.device_context_stride),
        ) catch return error.DmaLayoutOverflow;
        return std.math.add(u64, self.device_contexts_address, offset) catch
            return error.DmaLayoutOverflow;
    }

    pub fn controlTransferRingAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        if (slot_id == 0 or slot_id > self.enabled_device_slots) return error.InvalidDeviceSlot;
        const offset = std.math.mul(
            u64,
            @as(u64, slot_id - 1),
            @as(u64, self.control_transfer_ring_stride),
        ) catch return error.DmaLayoutOverflow;
        return std.math.add(u64, self.control_transfer_rings_address, offset) catch
            return error.DmaLayoutOverflow;
    }

    pub fn interruptTransferRingAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        if (slot_id == 0 or slot_id > self.enabled_device_slots) return error.InvalidDeviceSlot;
        const offset = std.math.mul(
            u64,
            @as(u64, slot_id - 1),
            @as(u64, self.interrupt_transfer_ring_stride),
        ) catch return error.DmaLayoutOverflow;
        return std.math.add(u64, self.interrupt_transfer_rings_address, offset) catch
            return error.DmaLayoutOverflow;
    }

    pub fn interruptReportBufferAddress(self: DmaArenaPlan, slot_id: u8) Error!u64 {
        if (slot_id == 0 or slot_id > self.enabled_device_slots) return error.InvalidDeviceSlot;
        const offset = std.math.mul(
            u64,
            @as(u64, slot_id - 1),
            @as(u64, self.interrupt_report_buffer_stride),
        ) catch return error.DmaLayoutOverflow;
        return std.math.add(u64, self.interrupt_report_buffers_address, offset) catch
            return error.DmaLayoutOverflow;
    }
};

pub const ControllerDmaPlan = struct {
    base_address: u64,
    total_bytes: u64,
    ring_plan: RingPlan,
    event_ring_segment_table_address: u64,
    event_ring_segment_table_bytes: u32,
    event_ring_segment_table_entries: u32,
    arena: DmaArenaPlan,

    pub fn frameCount(self: ControllerDmaPlan) Error!u32 {
        if (self.total_bytes == 0 or self.total_bytes % XHCI_PAGE_BYTES != 0) {
            return error.DmaLayoutOverflow;
        }
        return std.math.cast(u32, self.total_bytes / XHCI_PAGE_BYTES) orelse
            error.DmaFrameCountOverflow;
    }
};

pub const DmaAccessRegion = struct {
    address: u64,
    bytes: u64,
    device_readable: bool,
    device_writable: bool,
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
    context_size: ContextSize,
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
    enabled_device_slots: u8,
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
            self.enabled_device_slots > 0 and
            self.device_context_bytes >= @as(u32, self.enabled_device_slots) *
                DEVICE_CONTEXT_ENTRIES * self.context_size.byteCount() and
            self.input_context_bytes >= INPUT_CONTEXT_ENTRIES * self.context_size.byteCount() and
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
            keyboard.slot_id <= self.enabled_device_slots and
            keyboard.port_id <= self.max_ports;
    }

    pub fn hardwareVerified(self: MmioInputProof, keyboard: HidBootKeyboardDevice, event_count: usize) bool {
        return self.verified(keyboard, event_count) and self.hardware_input.verified(event_count);
    }
};

const MmioState = struct {
    capabilities: CapabilityRegisters,
    dma_plan: ControllerDmaPlan,
    command_doorbells: u32 = 0,
    transfer_doorbells: u32 = 0,
    device_context_writes: u32 = 0,
    endpoint_context_writes: u32 = 0,
    event_ring_segment_table_writes: u32 = EVENT_RING_SEGMENT_TABLE_ENTRIES,
    event_ring_dequeue_count: u32 = 0,
    interrupt_events: u32 = 0,
    interrupter_id: u16 = 1,

    fn proof(self: MmioState, ring_plan: RingPlan) MmioInputProof {
        return .{
            .doorbell_offset = self.capabilities.doorbell_offset,
            .runtime_register_offset = self.capabilities.runtime_register_offset,
            .command_ring_address = ring_plan.command_ring_address,
            .event_ring_address = ring_plan.event_ring_address,
            .device_context_base_address = self.dma_plan.arena.device_contexts_address,
            .input_context_address = self.dma_plan.arena.input_context_address,
            .transfer_ring_address = self.dma_plan.arena.control_transfer_rings_address,
            .event_ring_segment_table_address = self.dma_plan.event_ring_segment_table_address,
            .context_size = self.capabilities.context_size,
            .device_context_bytes = @intCast(self.dma_plan.arena.device_contexts_bytes),
            .input_context_bytes = self.dma_plan.arena.input_context_bytes,
            .transfer_ring_trbs = self.dma_plan.arena.control_transfer_ring_trbs,
            .event_ring_segment_table_entries = self.dma_plan.event_ring_segment_table_entries,
            .command_doorbells = self.command_doorbells,
            .transfer_doorbells = self.transfer_doorbells,
            .device_context_writes = self.device_context_writes,
            .endpoint_context_writes = self.endpoint_context_writes,
            .event_ring_segment_table_writes = self.event_ring_segment_table_writes,
            .event_ring_dequeue_count = self.event_ring_dequeue_count,
            .interrupt_events = self.interrupt_events,
            .interrupter_id = self.interrupter_id,
            .enabled_device_slots = self.dma_plan.arena.enabled_device_slots,
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
        var controller = try HidController.init(ring_plan);
        controller.port_limit = @min(capabilities.max_ports, maxBootPortsU8());
        controller.device_slot_limit = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
        const dma_plan = try planControllerDmaFromRings(
            capabilities,
            controller.device_slot_limit,
            ring_plan,
        );
        controller.mmio = .{
            .capabilities = capabilities,
            .dma_plan = dma_plan,
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

    pub fn dmaArenaPlan(self: *const HidController) ?DmaArenaPlan {
        const mmio = self.mmio orelse return null;
        return mmio.dma_plan.arena;
    }

    pub fn controllerDmaPlan(self: *const HidController) ?ControllerDmaPlan {
        const mmio = self.mmio orelse return null;
        return mmio.dma_plan;
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
    if (capability_length < MIN_CAPABILITY_LENGTH or
        (capability_length & (@sizeOf(u32) - 1)) != 0)
    {
        return error.InvalidCapabilityLength;
    }

    const interface_version = readU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES]);
    if (interface_version < MIN_SUPPORTED_INTERFACE_VERSION) return error.UnsupportedVersion;

    const hcsparams1 = readU32Le(mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES]);
    const max_device_slots: u8 = @truncate(hcsparams1);
    const max_interrupters: u16 = @intCast(
        (hcsparams1 >> HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) & HCSPARAMS1_MAX_INTERRUPTERS_MASK,
    );
    const max_ports: u8 = @truncate(hcsparams1 >> HCSPARAMS1_MAX_PORTS_SHIFT);
    if (max_device_slots == 0) return error.MissingDeviceSlots;
    if (max_ports == 0) return error.MissingPorts;
    if (max_interrupters == 0) return error.MissingInterrupters;

    const hcsparams2 = readU32Le(mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES]);
    const scratchpad_hi: u16 = @intCast(
        (hcsparams2 >> HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT) &
            HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK,
    );
    const scratchpad_lo: u16 = @intCast(
        (hcsparams2 >> HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT) &
            HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK,
    );
    const max_scratchpad_buffers = (scratchpad_hi << 5) | scratchpad_lo;
    const scratchpad_restore = (hcsparams2 & HCSPARAMS2_SCRATCHPAD_RESTORE) != 0;
    if (max_scratchpad_buffers == 0 and scratchpad_restore) return error.InvalidScratchpadRestore;

    const hccparams1 = readU32Le(mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES]);
    const supports_64_bit_addressing = (hccparams1 & HCCPARAMS1_64_BIT_ADDRESSING) != 0;
    if (!supports_64_bit_addressing) return error.Unsupported32BitAddressing;
    const context_size: ContextSize = if ((hccparams1 & HCCPARAMS1_CONTEXT_SIZE) != 0)
        .bytes_64
    else
        .bytes_32;
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
        .supports_64_bit_addressing = supports_64_bit_addressing,
        .context_size = context_size,
        .max_scratchpad_buffers = max_scratchpad_buffers,
        .scratchpad_restore = scratchpad_restore,
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

pub fn parseSupportedProtocols(
    capabilities: CapabilityRegisters,
    first_offset: u32,
    reader: anytype,
) Error!SupportedProtocols {
    if (first_offset == 0) return error.MissingSupportedProtocols;
    if ((first_offset & (@sizeOf(u32) - 1)) != 0 or first_offset > MAX_EXTENDED_CAPABILITY_OFFSET) {
        return error.ExtendedCapabilityOutOfRange;
    }

    var protocols = SupportedProtocols{};
    var found = false;
    var terminal = false;
    var offset = first_offset;
    var visited: usize = 0;
    while (visited < MAX_EXTENDED_CAPABILITIES) : (visited += 1) {
        const header = reader.readDword(offset);
        const capability_id: u8 = @truncate(header & EXTENDED_CAPABILITY_ID_MASK);
        var minimum_next_dwords: u32 = 1;
        if (capability_id == SUPPORTED_PROTOCOL_CAPABILITY_ID) {
            const extent_end = @as(u64, offset) + SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET +
                @sizeOf(u32);
            if (extent_end > @as(u64, MAX_EXTENDED_CAPABILITY_OFFSET) + @sizeOf(u32)) {
                return error.ExtendedCapabilityOutOfRange;
            }
            if (reader.readDword(offset + @sizeOf(u32)) != SUPPORTED_PROTOCOL_USB_NAME_STRING) {
                return error.InvalidSupportedProtocol;
            }
            const major_revision: u8 = @truncate(header >> SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT);
            const minor_revision: u8 = @truncate(header >> SUPPORTED_PROTOCOL_MINOR_REVISION_SHIFT);
            const kind: ProtocolKind = switch (major_revision) {
                2 => if (minor_revision == 0) .usb2 else return error.InvalidSupportedProtocol,
                3 => switch (minor_revision) {
                    0x00, 0x10, 0x20 => .usb3,
                    else => return error.InvalidSupportedProtocol,
                },
                else => return error.InvalidSupportedProtocol,
            };
            const compatible_ports = reader.readDword(
                offset + SUPPORTED_PROTOCOL_COMPATIBLE_PORTS_OFFSET,
            );
            const first_port: u8 = @truncate(compatible_ports);
            const port_count: u8 = @truncate(
                compatible_ports >> SUPPORTED_PROTOCOL_PORT_COUNT_SHIFT,
            );
            const speed_id_count: u8 = @truncate(
                compatible_ports >> SUPPORTED_PROTOCOL_SPEED_ID_COUNT_SHIFT,
            );
            const capability_end = @as(u64, offset) +
                SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET + @sizeOf(u32) +
                @as(u64, speed_id_count) * @sizeOf(u32);
            if (capability_end > @as(u64, MAX_EXTENDED_CAPABILITY_OFFSET) + @sizeOf(u32)) {
                return error.ExtendedCapabilityOutOfRange;
            }
            minimum_next_dwords = 4 + speed_id_count;
            if (first_port == 0 or port_count == 0 or
                @as(u16, first_port) + @as(u16, port_count) - 1 > capabilities.max_ports)
            {
                return error.InvalidSupportedProtocol;
            }
            const slot_type: u5 = @truncate(reader.readDword(
                offset + SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET,
            ));
            var speed_ids: u16 = 0;
            var low_speed_ids: u16 = 0;
            var full_speed_ids: u16 = 0;
            var high_speed_ids: u16 = 0;
            if (speed_id_count == 0) {
                switch (kind) {
                    .usb2 => {
                        speed_ids = (@as(u16, 1) << 1) |
                            (@as(u16, 1) << 2) |
                            (@as(u16, 1) << 3);
                        full_speed_ids = @as(u16, 1) << 1;
                        low_speed_ids = @as(u16, 1) << 2;
                        high_speed_ids = @as(u16, 1) << 3;
                    },
                    .usb3 => {
                        const highest_speed_id: u4 = switch (minor_revision) {
                            0x00 => 4,
                            0x10 => 5,
                            0x20 => 7,
                            else => unreachable,
                        };
                        var speed_id: u4 = 4;
                        while (speed_id <= highest_speed_id) : (speed_id += 1) {
                            speed_ids |= @as(u16, 1) << speed_id;
                        }
                    },
                }
            } else {
                var pending_asymmetric_rx: ?u4 = null;
                var speed_index: u8 = 0;
                while (speed_index < speed_id_count) : (speed_index += 1) {
                    const psi = reader.readDword(
                        offset + SUPPORTED_PROTOCOL_SPEED_IDS_OFFSET +
                            @as(u32, speed_index) * @sizeOf(u32),
                    );
                    const speed_id: u4 = @truncate(psi);
                    const exponent: u2 = @truncate(psi >> 4);
                    const psi_type: u2 = @truncate(psi >> 6);
                    const link_protocol: u2 = @truncate(psi >> 14);
                    const mantissa: u16 = @truncate(psi >> 16);
                    if (speed_id == 0 or mantissa == 0 or
                        (kind == .usb2 and link_protocol != 0))
                    {
                        return error.InvalidSupportedProtocol;
                    }
                    const speed_bit = @as(u16, 1) << speed_id;
                    switch (psi_type) {
                        0 => {
                            if (pending_asymmetric_rx != null or (speed_ids & speed_bit) != 0) {
                                return error.InvalidSupportedProtocol;
                            }
                        },
                        2 => {
                            if (pending_asymmetric_rx != null or (speed_ids & speed_bit) != 0) {
                                return error.InvalidSupportedProtocol;
                            }
                            pending_asymmetric_rx = speed_id;
                        },
                        3 => {
                            if (pending_asymmetric_rx == null or pending_asymmetric_rx.? != speed_id) {
                                return error.InvalidSupportedProtocol;
                            }
                            pending_asymmetric_rx = null;
                        },
                        else => return error.InvalidSupportedProtocol,
                    }
                    speed_ids |= speed_bit;
                    const scale = ([_]u64{ 1, 1_000, 1_000_000, 1_000_000_000 })[exponent];
                    const bits_per_second = @as(u64, mantissa) * scale;
                    if (kind == .usb2) {
                        const classified = low_speed_ids | full_speed_ids | high_speed_ids;
                        const speed_class: enum { low, full, high } =
                            if (bits_per_second <= 1_500_000)
                                .low
                            else if (bits_per_second >= 480_000_000)
                                .high
                            else
                                .full;
                        if ((classified & speed_bit) != 0) {
                            const same_class = switch (speed_class) {
                                .low => (low_speed_ids & speed_bit) != 0,
                                .full => (full_speed_ids & speed_bit) != 0,
                                .high => (high_speed_ids & speed_bit) != 0,
                            };
                            if (!same_class) return error.InvalidSupportedProtocol;
                        }
                        switch (speed_class) {
                            .low => low_speed_ids |= speed_bit,
                            .full => full_speed_ids |= speed_bit,
                            .high => high_speed_ids |= speed_bit,
                        }
                    }
                }
                if (pending_asymmetric_rx != null) return error.InvalidSupportedProtocol;
            }
            var port: u16 = first_port;
            const port_end = @as(u16, first_port) + port_count;
            while (port < port_end) : (port += 1) {
                const index: usize = port;
                if (protocols.ports[index] != null) {
                    return error.OverlappingSupportedProtocolPorts;
                }
                protocols.ports[index] = .{
                    .kind = kind,
                    .slot_type = slot_type,
                    .speed_ids = speed_ids,
                    .low_speed_ids = low_speed_ids,
                    .full_speed_ids = full_speed_ids,
                    .high_speed_ids = high_speed_ids,
                };
            }
            found = true;
        }

        const next_dwords = (header >> EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) &
            EXTENDED_CAPABILITY_NEXT_POINTER_MASK;
        if (next_dwords == 0) {
            terminal = true;
            break;
        }
        if (next_dwords < minimum_next_dwords) return error.InvalidSupportedProtocol;
        const delta = next_dwords << EXTENDED_CAPABILITY_DWORD_SHIFT;
        if (offset > MAX_EXTENDED_CAPABILITY_OFFSET - delta) {
            return error.ExtendedCapabilityOutOfRange;
        }
        offset += delta;
    }
    if (!terminal) return error.ExtendedCapabilityTraversalLimit;
    if (!found) return error.MissingSupportedProtocols;
    return protocols;
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

pub fn resetOwnedController(
    capability_length: u8,
    mmio: anytype,
    clock: anytype,
) Error!void {
    const operational_base: u32 = capability_length;
    const command_offset = operational_base + OPERATIONAL_USB_COMMAND_OFFSET;
    const status_offset = operational_base + OPERATIONAL_USB_STATUS_OFFSET;

    var initial_ready_deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    var status = mmio.readReg32(status_offset);
    while ((status & USB_STATUS_CONTROLLER_NOT_READY) != 0) {
        if (initial_ready_deadline.expired()) return error.ControllerNotReadyTimeout;
        spin.hint();
        status = mmio.readReg32(status_offset);
    }

    const quiesce_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    if ((status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0) {
        var halt_deadline = clock.afterMilliseconds(CONTROLLER_HALT_TIMEOUT_MILLISECONDS);
        const command = mmio.readReg32(command_offset);
        mmio.writeReg32(command_offset, command & ~quiesce_mask);
        status = mmio.readReg32(status_offset);
        while ((status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0) {
            if (halt_deadline.expired()) return error.ControllerHaltTimeout;
            spin.hint();
            status = mmio.readReg32(status_offset);
        }
    }

    var reset_deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    const command = mmio.readReg32(command_offset);
    mmio.writeReg32(
        command_offset,
        (command & ~quiesce_mask) | USB_COMMAND_HOST_CONTROLLER_RESET,
    );
    var reset_command = mmio.readReg32(command_offset);
    while ((reset_command & USB_COMMAND_HOST_CONTROLLER_RESET) != 0) {
        if (reset_deadline.expired()) return error.ControllerResetTimeout;
        spin.hint();
        reset_command = mmio.readReg32(command_offset);
    }

    var post_reset_ready_deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    status = mmio.readReg32(status_offset);
    while ((status & USB_STATUS_CONTROLLER_NOT_READY) != 0) {
        if (post_reset_ready_deadline.expired()) return error.ControllerNotReadyTimeout;
        spin.hint();
        status = mmio.readReg32(status_offset);
    }
    if ((status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0 or
        (status & USB_STATUS_HOST_CONTROLLER_ERROR) != 0)
    {
        return error.ControllerResetFailed;
    }
}

pub fn startOwnedController(
    capabilities: CapabilityRegisters,
    mmio: anytype,
    clock: anytype,
) Error!void {
    const operational_base: u32 = capabilities.capability_length;
    const command_offset = operational_base + OPERATIONAL_USB_COMMAND_OFFSET;
    const status_offset = operational_base + OPERATIONAL_USB_STATUS_OFFSET;
    const fatal_status = USB_STATUS_HOST_SYSTEM_ERROR | USB_STATUS_HOST_CONTROLLER_ERROR;
    const initial_status = mmio.readReg32(status_offset);
    if ((initial_status & (USB_STATUS_CONTROLLER_NOT_READY | fatal_status)) != 0 or
        (initial_status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0)
    {
        return error.ControllerStartUnavailable;
    }
    errdefer quiesceOwnedController(capabilities, mmio);

    const primary_interrupter = std.math.add(
        u32,
        capabilities.runtime_register_offset,
        PRIMARY_INTERRUPTER_OFFSET,
    ) catch return error.DmaLayoutOverflow;
    const iman_offset = primary_interrupter + INTERRUPTER_MANAGEMENT_OFFSET;
    const iman = mmio.readReg32(iman_offset);
    mmio.writeReg32(
        iman_offset,
        (iman & ~INTERRUPTER_PENDING) | INTERRUPTER_ENABLE,
    );
    if ((mmio.readReg32(iman_offset) & INTERRUPTER_ENABLE) == 0) {
        return error.ControllerStartFailed;
    }

    const enable_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    const command = mmio.readReg32(command_offset);
    mmio.writeReg32(command_offset, command | enable_mask);

    var deadline = clock.afterMilliseconds(CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS);
    var status = mmio.readReg32(status_offset);
    while ((status & USB_STATUS_HOST_CONTROLLER_HALTED) != 0) {
        if ((status & (USB_STATUS_CONTROLLER_NOT_READY | fatal_status)) != 0) {
            return error.ControllerStartFailed;
        }
        if (deadline.expired()) return error.ControllerStartTimeout;
        spin.hint();
        status = mmio.readReg32(status_offset);
    }
    if ((status & (USB_STATUS_CONTROLLER_NOT_READY | fatal_status)) != 0 or
        (mmio.readReg32(command_offset) & enable_mask) != enable_mask)
    {
        return error.ControllerStartFailed;
    }
}

pub fn quiesceOwnedController(
    capabilities: CapabilityRegisters,
    mmio: anytype,
) void {
    const primary_interrupter = capabilities.runtime_register_offset + PRIMARY_INTERRUPTER_OFFSET;
    const iman_offset = primary_interrupter + INTERRUPTER_MANAGEMENT_OFFSET;
    const iman = mmio.readReg32(iman_offset);
    mmio.writeReg32(
        iman_offset,
        iman & ~(INTERRUPTER_PENDING | INTERRUPTER_ENABLE),
    );

    const command_offset = @as(u32, capabilities.capability_length) + OPERATIONAL_USB_COMMAND_OFFSET;
    const command = mmio.readReg32(command_offset);
    const enable_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    mmio.writeReg32(command_offset, command & ~enable_mask);
}

pub fn controllerRunningHealthy(
    capabilities: CapabilityRegisters,
    mmio: anytype,
) bool {
    const operational_base: u32 = capabilities.capability_length;
    const status = mmio.readReg32(operational_base + OPERATIONAL_USB_STATUS_OFFSET);
    const fatal_status = USB_STATUS_HOST_SYSTEM_ERROR |
        USB_STATUS_CONTROLLER_NOT_READY |
        USB_STATUS_HOST_CONTROLLER_ERROR;
    if ((status & (USB_STATUS_HOST_CONTROLLER_HALTED | fatal_status)) != 0) return false;
    return (mmio.readReg32(operational_base + OPERATIONAL_USB_COMMAND_OFFSET) &
        USB_COMMAND_RUN_STOP) != 0;
}

pub fn acknowledgePrimaryEventRing(
    capabilities: CapabilityRegisters,
    dequeue_address: u64,
    mmio: anytype,
) Error!void {
    if ((dequeue_address & ~EVENT_RING_DEQUEUE_POINTER_MASK) != 0) {
        return error.EventRingStateInvalid;
    }
    const primary_interrupter = std.math.add(
        u32,
        capabilities.runtime_register_offset,
        PRIMARY_INTERRUPTER_OFFSET,
    ) catch return error.DmaLayoutOverflow;
    const erdp_offset = primary_interrupter + EVENT_RING_DEQUEUE_POINTER_OFFSET;
    mmio.writeReg64(erdp_offset, dequeue_address | EVENT_HANDLER_BUSY);
    if ((mmio.readReg64(erdp_offset) & EVENT_RING_DEQUEUE_POINTER_MASK) != dequeue_address) {
        return error.DmaRegisterRejected;
    }
}

pub fn configureDeviceSlots(
    capabilities: CapabilityRegisters,
    mmio: anytype,
) Error!u8 {
    const operational_base: u32 = capabilities.capability_length;
    const status = mmio.readReg32(operational_base + OPERATIONAL_USB_STATUS_OFFSET);
    if ((status & (USB_STATUS_CONTROLLER_NOT_READY | USB_STATUS_HOST_CONTROLLER_ERROR)) != 0 or
        (status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0)
    {
        return error.ControllerConfigurationUnavailable;
    }

    const enabled_slots = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
    if (enabled_slots == 0) return error.MissingDeviceSlots;

    const configure_offset = operational_base + OPERATIONAL_CONFIGURE_OFFSET;
    const current = mmio.readReg32(configure_offset);
    const desired = (current & ~CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK) | @as(u32, enabled_slots);
    mmio.writeReg32(configure_offset, desired);
    const readback = mmio.readReg32(configure_offset);
    if ((readback & CONFIG_MAX_DEVICE_SLOTS_ENABLED_MASK) != enabled_slots) {
        return error.DeviceSlotConfigurationRejected;
    }
    return enabled_slots;
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

pub fn planControllerDma(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
    base_address: u64,
) Error!ControllerDmaPlan {
    if (base_address == 0 or !aligned(base_address, XHCI_PAGE_BYTES)) {
        return error.DmaArenaBaseInvalid;
    }
    const event_ring_address = checkedAdd(base_address, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    return planControllerDmaFromRings(capabilities, enabled_device_slots, .{
        .command_ring_trbs = COMMAND_RING_TRBS,
        .event_ring_trbs = EVENT_RING_TRBS,
        .command_ring_address = base_address,
        .event_ring_address = event_ring_address,
    });
}

pub fn controllerDmaFrameCount(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
) Error!u32 {
    var maximum_frames: u32 = 0;
    var base_address = XHCI_PAGE_BYTES;
    while (base_address <= XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) : (base_address += XHCI_PAGE_BYTES) {
        maximum_frames = @max(
            maximum_frames,
            try (try planControllerDma(
                capabilities,
                enabled_device_slots,
                base_address,
            )).frameCount(),
        );
    }
    return maximum_frames;
}

fn planControllerDmaFromRings(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
    ring_plan: RingPlan,
) Error!ControllerDmaPlan {
    try validateRingPlan(ring_plan);
    const event_ring_end = try ringEndAddress(
        ring_plan.event_ring_address,
        ring_plan.event_ring_trbs,
    );
    const event_ring_segment_table_address = alignForwardChecked(
        event_ring_end,
        ERST_TABLE_ALIGNMENT_BYTES,
    ) catch return error.DmaLayoutOverflow;
    const event_ring_segment_table_bytes = std.math.cast(
        u32,
        ERST_TABLE_ALIGNMENT_BYTES,
    ) orelse return error.DmaLayoutOverflow;
    const arena_start = checkedAdd(
        event_ring_segment_table_address,
        event_ring_segment_table_bytes,
    ) catch return error.DmaLayoutOverflow;
    const arena_base = alignForwardChecked(arena_start, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    const arena = try planDmaArena(capabilities, enabled_device_slots, arena_base);
    const plan_base = @min(ring_plan.command_ring_address, ring_plan.event_ring_address);
    const plan_end = checkedAdd(arena.base_address, arena.total_bytes) catch
        return error.DmaLayoutOverflow;
    if (plan_end <= plan_base) return error.DmaLayoutOverflow;
    return .{
        .base_address = plan_base,
        .total_bytes = plan_end - plan_base,
        .ring_plan = ring_plan,
        .event_ring_segment_table_address = event_ring_segment_table_address,
        .event_ring_segment_table_bytes = event_ring_segment_table_bytes,
        .event_ring_segment_table_entries = EVENT_RING_SEGMENT_TABLE_ENTRIES,
        .arena = arena,
    };
}

pub fn planDmaArena(
    capabilities: CapabilityRegisters,
    enabled_device_slots: u8,
    base_address: u64,
) Error!DmaArenaPlan {
    if (base_address == 0 or !aligned(base_address, XHCI_PAGE_BYTES)) {
        return error.DmaArenaBaseInvalid;
    }
    const slot_limit = @min(capabilities.max_device_slots, maxDeviceSlotsU8());
    if (enabled_device_slots == 0 or enabled_device_slots > slot_limit) {
        return error.DmaSlotCountInvalid;
    }

    const dcbaa_bytes: u32 = (@as(u32, enabled_device_slots) + 1) * DCBAA_ENTRY_BYTES;
    var cursor = checkedAdd(base_address, XHCI_PAGE_BYTES) catch return error.DmaLayoutOverflow;

    var scratchpad_array_address: u64 = 0;
    var scratchpad_array_bytes: u64 = 0;
    var scratchpad_buffers_address: u64 = 0;
    var scratchpad_buffers_bytes: u64 = 0;
    if (capabilities.max_scratchpad_buffers != 0) {
        scratchpad_array_address = cursor;
        scratchpad_array_bytes = std.math.mul(
            u64,
            capabilities.max_scratchpad_buffers,
            SCRATCHPAD_ARRAY_ENTRY_BYTES,
        ) catch return error.DmaLayoutOverflow;
        cursor = try advancePageRounded(cursor, scratchpad_array_bytes);

        scratchpad_buffers_address = cursor;
        scratchpad_buffers_bytes = std.math.mul(
            u64,
            capabilities.max_scratchpad_buffers,
            XHCI_PAGE_BYTES,
        ) catch return error.DmaLayoutOverflow;
        cursor = checkedAdd(cursor, scratchpad_buffers_bytes) catch return error.DmaLayoutOverflow;
    }

    const device_context_stride = std.math.mul(
        u32,
        DEVICE_CONTEXT_ENTRIES,
        capabilities.context_size.byteCount(),
    ) catch return error.DmaLayoutOverflow;
    const device_contexts_address = cursor;
    const device_contexts_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        device_context_stride,
    ) catch return error.DmaLayoutOverflow;
    cursor = checkedAdd(cursor, device_contexts_bytes) catch return error.DmaLayoutOverflow;
    cursor = alignForwardChecked(cursor, XHCI_PAGE_BYTES) catch return error.DmaLayoutOverflow;

    cursor = alignForwardChecked(cursor, XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) catch
        return error.DmaLayoutOverflow;
    const enumeration_buffer_address = cursor;
    const enumeration_buffer_bytes = USB_ENUMERATION_BUFFER_BYTES;
    cursor = checkedAdd(cursor, enumeration_buffer_bytes) catch return error.DmaLayoutOverflow;

    const input_context_address = cursor;
    const input_context_bytes = std.math.mul(
        u32,
        INPUT_CONTEXT_ENTRIES,
        capabilities.context_size.byteCount(),
    ) catch return error.DmaLayoutOverflow;
    cursor = checkedAdd(cursor, input_context_bytes) catch return error.DmaLayoutOverflow;
    cursor = alignForwardChecked(cursor, XHCI_PAGE_BYTES) catch return error.DmaLayoutOverflow;

    const control_transfer_ring_stride = std.math.mul(
        u32,
        TRANSFER_RING_TRBS,
        TRB_BYTES,
    ) catch return error.DmaLayoutOverflow;
    const control_transfer_rings_address = cursor;
    const control_transfer_rings_used_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        control_transfer_ring_stride,
    ) catch return error.DmaLayoutOverflow;
    cursor = try advancePageRounded(cursor, control_transfer_rings_used_bytes);
    const control_transfer_rings_bytes = cursor - control_transfer_rings_address;

    const interrupt_transfer_ring_stride = control_transfer_ring_stride;
    const interrupt_transfer_rings_address = cursor;
    const interrupt_transfer_rings_used_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        interrupt_transfer_ring_stride,
    ) catch return error.DmaLayoutOverflow;
    cursor = try advancePageRounded(cursor, interrupt_transfer_rings_used_bytes);
    const interrupt_transfer_rings_bytes = cursor - interrupt_transfer_rings_address;

    const interrupt_report_buffers_address = cursor;
    const interrupt_report_buffers_used_bytes = std.math.mul(
        u64,
        enabled_device_slots,
        INTERRUPT_REPORT_BUFFER_STRIDE,
    ) catch return error.DmaLayoutOverflow;
    cursor = try advancePageRounded(cursor, interrupt_report_buffers_used_bytes);
    const interrupt_report_buffers_bytes = cursor - interrupt_report_buffers_address;

    return .{
        .base_address = base_address,
        .total_bytes = cursor - base_address,
        .enabled_device_slots = enabled_device_slots,
        .dcbaa_address = base_address,
        .dcbaa_bytes = dcbaa_bytes,
        .scratchpad_array_address = scratchpad_array_address,
        .scratchpad_array_bytes = scratchpad_array_bytes,
        .scratchpad_buffers_address = scratchpad_buffers_address,
        .scratchpad_buffers_bytes = scratchpad_buffers_bytes,
        .device_contexts_address = device_contexts_address,
        .device_context_stride = device_context_stride,
        .device_contexts_bytes = device_contexts_bytes,
        .enumeration_buffer_address = enumeration_buffer_address,
        .enumeration_buffer_bytes = enumeration_buffer_bytes,
        .input_context_address = input_context_address,
        .input_context_bytes = input_context_bytes,
        .control_transfer_rings_address = control_transfer_rings_address,
        .control_transfer_ring_stride = control_transfer_ring_stride,
        .control_transfer_ring_trbs = TRANSFER_RING_TRBS,
        .control_transfer_rings_bytes = control_transfer_rings_bytes,
        .interrupt_transfer_rings_address = interrupt_transfer_rings_address,
        .interrupt_transfer_ring_stride = interrupt_transfer_ring_stride,
        .interrupt_transfer_ring_trbs = TRANSFER_RING_TRBS,
        .interrupt_transfer_rings_bytes = interrupt_transfer_rings_bytes,
        .interrupt_report_buffers_address = interrupt_report_buffers_address,
        .interrupt_report_buffer_stride = INTERRUPT_REPORT_BUFFER_STRIDE,
        .interrupt_report_buffers_bytes = interrupt_report_buffers_bytes,
    };
}

pub fn initializeControllerDma(
    plan: ControllerDmaPlan,
    memory: []u8,
) Error!void {
    const total_bytes = std.math.cast(usize, plan.total_bytes) orelse
        return error.DmaBufferTooSmall;
    if (memory.len < total_bytes) return error.DmaBufferTooSmall;
    @memset(memory[0..total_bytes], 0);

    try initializeLinkTrb(
        plan,
        memory,
        plan.ring_plan.command_ring_address,
        plan.ring_plan.command_ring_trbs,
    );
    var slot_id: u16 = 1;
    while (slot_id <= plan.arena.enabled_device_slots) : (slot_id += 1) {
        try initializeLinkTrb(
            plan,
            memory,
            try plan.arena.controlTransferRingAddress(@intCast(slot_id)),
            plan.arena.control_transfer_ring_trbs,
        );
        try initializeLinkTrb(
            plan,
            memory,
            try plan.arena.interruptTransferRingAddress(@intCast(slot_id)),
            plan.arena.interrupt_transfer_ring_trbs,
        );
    }

    const erst = try dmaBytes(
        plan,
        memory,
        plan.event_ring_segment_table_address,
        plan.event_ring_segment_table_bytes,
    );
    writeU64Le(erst[0..8], plan.ring_plan.event_ring_address);
    writeU32Le(erst[8..12], plan.ring_plan.event_ring_trbs);

    const dcbaa = try dmaBytes(
        plan,
        memory,
        plan.arena.dcbaa_address,
        plan.arena.dcbaa_bytes,
    );
    if (plan.arena.scratchpad_array_address != 0) {
        writeU64Le(dcbaa[0..8], plan.arena.scratchpad_array_address);
        const scratchpad_array = try dmaBytes(
            plan,
            memory,
            plan.arena.scratchpad_array_address,
            plan.arena.scratchpad_array_bytes,
        );
        var index: u64 = 0;
        while (index < plan.arena.scratchpad_array_bytes / SCRATCHPAD_ARRAY_ENTRY_BYTES) : (index += 1) {
            const entry_offset: usize = @intCast(index * SCRATCHPAD_ARRAY_ENTRY_BYTES);
            const buffer_address = checkedAdd(
                plan.arena.scratchpad_buffers_address,
                index * XHCI_PAGE_BYTES,
            ) catch return error.DmaLayoutOverflow;
            writeU64Le(scratchpad_array[entry_offset..][0..8], buffer_address);
        }
    }
}

pub fn controllerDmaAccessRegions(
    plan: ControllerDmaPlan,
    storage: *[MAX_CONTROLLER_DMA_REGIONS]DmaAccessRegion,
) Error![]const DmaAccessRegion {
    const command_page_end = checkedAdd(plan.ring_plan.command_ring_address, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    const event_page_end = checkedAdd(plan.ring_plan.event_ring_address, XHCI_PAGE_BYTES) catch
        return error.DmaLayoutOverflow;
    const command_ring_end = try ringEndAddress(
        plan.ring_plan.command_ring_address,
        plan.ring_plan.command_ring_trbs,
    );
    const event_ring_end = try ringEndAddress(
        plan.ring_plan.event_ring_address,
        plan.ring_plan.event_ring_trbs,
    );
    const erst_end = checkedAdd(
        plan.event_ring_segment_table_address,
        plan.event_ring_segment_table_bytes,
    ) catch return error.DmaLayoutOverflow;
    const plan_end = checkedAdd(plan.base_address, plan.total_bytes) catch
        return error.DmaLayoutOverflow;
    const control_transfer_rings_end = checkedAdd(
        plan.arena.control_transfer_rings_address,
        plan.arena.control_transfer_rings_bytes,
    ) catch return error.DmaLayoutOverflow;
    const interrupt_transfer_rings_end = checkedAdd(
        plan.arena.interrupt_transfer_rings_address,
        plan.arena.interrupt_transfer_rings_bytes,
    ) catch return error.DmaLayoutOverflow;
    const interrupt_report_buffers_end = checkedAdd(
        plan.arena.interrupt_report_buffers_address,
        plan.arena.interrupt_report_buffers_bytes,
    ) catch return error.DmaLayoutOverflow;
    if (plan.ring_plan.command_ring_address != plan.base_address or
        !aligned(plan.ring_plan.command_ring_address, XHCI_PAGE_BYTES) or
        !aligned(plan.ring_plan.event_ring_address, XHCI_PAGE_BYTES) or
        command_ring_end > command_page_end or
        event_ring_end > event_page_end or
        plan.event_ring_segment_table_address < event_ring_end or
        erst_end > event_page_end or
        !aligned(plan.arena.control_transfer_rings_address, XHCI_PAGE_BYTES) or
        control_transfer_rings_end != plan.arena.interrupt_transfer_rings_address or
        !aligned(plan.arena.interrupt_transfer_rings_address, XHCI_PAGE_BYTES) or
        interrupt_transfer_rings_end != plan.arena.interrupt_report_buffers_address or
        !aligned(plan.arena.interrupt_report_buffers_address, XHCI_PAGE_BYTES) or
        interrupt_report_buffers_end != plan_end)
    {
        return error.DmaAddressOutsidePlan;
    }

    var count: usize = 0;
    storage[count] = .{
        .address = plan.ring_plan.command_ring_address,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = false,
    };
    count += 1;
    storage[count] = .{
        .address = plan.ring_plan.event_ring_address,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = true,
    };
    count += 1;
    storage[count] = .{
        .address = plan.arena.dcbaa_address,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = false,
    };
    count += 1;
    if (plan.arena.scratchpad_array_address != 0) {
        if (plan.arena.scratchpad_buffers_address <= plan.arena.scratchpad_array_address) {
            return error.DmaAddressOutsidePlan;
        }
        storage[count] = .{
            .address = plan.arena.scratchpad_array_address,
            .bytes = plan.arena.scratchpad_buffers_address - plan.arena.scratchpad_array_address,
            .device_readable = true,
            .device_writable = false,
        };
        count += 1;
        storage[count] = .{
            .address = plan.arena.scratchpad_buffers_address,
            .bytes = plan.arena.scratchpad_buffers_bytes,
            .device_readable = true,
            .device_writable = true,
        };
        count += 1;
    }
    const enumeration_buffer_end = checkedAdd(
        plan.arena.enumeration_buffer_address,
        plan.arena.enumeration_buffer_bytes,
    ) catch return error.DmaLayoutOverflow;
    if (plan.arena.enumeration_buffer_address <= plan.arena.device_contexts_address or
        enumeration_buffer_end != plan.arena.input_context_address)
    {
        return error.DmaAddressOutsidePlan;
    }
    storage[count] = .{
        .address = plan.arena.device_contexts_address,
        .bytes = plan.arena.input_context_address - plan.arena.device_contexts_address,
        .device_readable = true,
        .device_writable = true,
    };
    count += 1;
    storage[count] = .{
        .address = plan.arena.input_context_address,
        .bytes = plan.arena.interrupt_report_buffers_address -
            plan.arena.input_context_address,
        .device_readable = true,
        .device_writable = false,
    };
    count += 1;
    storage[count] = .{
        .address = plan.arena.interrupt_report_buffers_address,
        .bytes = plan.arena.interrupt_report_buffers_bytes,
        .device_readable = false,
        .device_writable = true,
    };
    count += 1;

    for (storage[0..count]) |region| {
        const region_end = checkedAdd(region.address, region.bytes) catch
            return error.DmaLayoutOverflow;
        if (!aligned(region.address, XHCI_PAGE_BYTES) or
            region.bytes == 0 or region.bytes % XHCI_PAGE_BYTES != 0 or
            region.address < plan.base_address or region_end > plan_end)
        {
            return error.DmaAddressOutsidePlan;
        }
    }
    return storage[0..count];
}

pub fn programControllerDmaRegisters(
    capabilities: CapabilityRegisters,
    plan: ControllerDmaPlan,
    mmio: anytype,
) Error!void {
    const operational_base: u32 = capabilities.capability_length;
    const status = mmio.readReg32(operational_base + OPERATIONAL_USB_STATUS_OFFSET);
    if ((status & (USB_STATUS_CONTROLLER_NOT_READY | USB_STATUS_HOST_CONTROLLER_ERROR)) != 0 or
        (status & USB_STATUS_HOST_CONTROLLER_HALTED) == 0)
    {
        return error.DmaProgrammingUnavailable;
    }
    if ((mmio.readReg32(operational_base + OPERATIONAL_PAGE_SIZE_OFFSET) &
        PAGE_SIZE_4K_SUPPORTED) == 0)
    {
        return error.UnsupportedPageSize;
    }
    const command_ring_control_offset = operational_base + OPERATIONAL_COMMAND_RING_CONTROL_OFFSET;
    if ((mmio.readReg64(command_ring_control_offset) & COMMAND_RING_RUNNING) != 0) {
        return error.DmaProgrammingUnavailable;
    }

    const dcbaap_offset = operational_base + OPERATIONAL_DEVICE_CONTEXT_BASE_ARRAY_POINTER_OFFSET;
    mmio.writeReg64(dcbaap_offset, plan.arena.dcbaa_address);
    mmio.writeReg64(
        command_ring_control_offset,
        plan.ring_plan.command_ring_address | COMMAND_RING_INITIAL_CYCLE_STATE,
    );

    const primary_interrupter = std.math.add(
        u32,
        capabilities.runtime_register_offset,
        PRIMARY_INTERRUPTER_OFFSET,
    ) catch return error.DmaLayoutOverflow;
    const iman_offset = primary_interrupter + INTERRUPTER_MANAGEMENT_OFFSET;
    mmio.writeReg32(iman_offset, mmio.readReg32(iman_offset) & ~INTERRUPTER_ENABLE);
    mmio.writeReg32(
        primary_interrupter + INTERRUPTER_MODERATION_OFFSET,
        INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS,
    );
    mmio.writeReg32(
        primary_interrupter + EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET,
        plan.event_ring_segment_table_entries,
    );
    mmio.writeReg64(
        primary_interrupter + EVENT_RING_SEGMENT_TABLE_BASE_OFFSET,
        plan.event_ring_segment_table_address,
    );
    mmio.writeReg64(
        primary_interrupter + EVENT_RING_DEQUEUE_POINTER_OFFSET,
        plan.ring_plan.event_ring_address,
    );

    if ((mmio.readReg64(dcbaap_offset) & ~ADDRESS_64_BYTE_ALIGNMENT_MASK) !=
        plan.arena.dcbaa_address or
        (mmio.readReg32(iman_offset) & INTERRUPTER_ENABLE) != 0 or
        (mmio.readReg32(primary_interrupter + INTERRUPTER_MODERATION_OFFSET) & 0xFFFF) !=
            INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS or
        (mmio.readReg32(primary_interrupter + EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET) & 0xFFFF) !=
            plan.event_ring_segment_table_entries or
        (mmio.readReg64(primary_interrupter + EVENT_RING_SEGMENT_TABLE_BASE_OFFSET) &
            ~ADDRESS_64_BYTE_ALIGNMENT_MASK) != plan.event_ring_segment_table_address or
        (mmio.readReg64(primary_interrupter + EVENT_RING_DEQUEUE_POINTER_OFFSET) &
            EVENT_RING_DEQUEUE_POINTER_MASK) != plan.ring_plan.event_ring_address)
    {
        return error.DmaRegisterRejected;
    }
}

pub fn rejectKernelInputReport(_: InputRequest) Error!void {
    return error.KernelUsbInputDataPlaneDisabled;
}

pub fn withHardwareInputEvidence(proof: InputProof, evidence: HardwareInputEvidence) InputProof {
    var upgraded = proof;
    upgraded.mmio.hardware_input = evidence;
    return upgraded;
}

fn initializeLinkTrb(
    plan: ControllerDmaPlan,
    memory: []u8,
    ring_address: u64,
    ring_trbs: u32,
) Error!void {
    if (ring_trbs < 2) return error.RingTooSmall;
    const ring_bytes = std.math.mul(u64, ring_trbs, TRB_BYTES) catch
        return error.DmaLayoutOverflow;
    const link_address = checkedAdd(ring_address, ring_bytes - TRB_BYTES) catch
        return error.DmaLayoutOverflow;
    const link = try dmaBytes(plan, memory, link_address, TRB_BYTES);
    writeU64Le(link[0..8], ring_address);
    writeU32Le(
        link[12..16],
        (@as(u32, LINK_TRB_TYPE) << TRB_TYPE_SHIFT) |
            LINK_TRB_TOGGLE_CYCLE |
            @as(u32, COMMAND_RING_INITIAL_CYCLE_STATE),
    );
}

fn dmaBytes(
    plan: ControllerDmaPlan,
    memory: []u8,
    address: u64,
    byte_count: u64,
) Error![]u8 {
    if (address < plan.base_address) return error.DmaAddressOutsidePlan;
    const offset = address - plan.base_address;
    const end = checkedAdd(offset, byte_count) catch return error.DmaLayoutOverflow;
    if (end > plan.total_bytes or end > memory.len) return error.DmaAddressOutsidePlan;
    const start_index = std.math.cast(usize, offset) orelse return error.DmaAddressOutsidePlan;
    const end_index = std.math.cast(usize, end) orelse return error.DmaAddressOutsidePlan;
    return memory[start_index..end_index];
}

fn validateRing(trbs: u32, address: u64) Error!void {
    if (trbs < 16) return error.RingTooSmall;
    if (address == 0) return error.RingAddressInvalid;
    if (!aligned(address, RING_ALIGNMENT_BYTES)) return error.RingAddressUnaligned;
}

fn ringEndAddress(address: u64, trbs: u32) Error!u64 {
    return std.math.add(u64, address, ringByteLength(trbs)) catch error.RingAddressOverflow;
}

fn ringByteLength(trbs: u32) u64 {
    return @as(u64, trbs) * TRB_BYTES;
}

fn checkedAdd(left: u64, right: u64) error{Overflow}!u64 {
    return std.math.add(u64, left, right) catch error.Overflow;
}

fn alignForwardChecked(address: u64, alignment: u64) error{Overflow}!u64 {
    if (alignment == 0) return address;
    const remainder = address % alignment;
    return if (remainder == 0)
        address
    else
        checkedAdd(address, alignment - remainder);
}

fn advancePageRounded(address: u64, bytes: u64) Error!u64 {
    const end = checkedAdd(address, bytes) catch return error.DmaLayoutOverflow;
    return alignForwardChecked(end, XHCI_PAGE_BYTES) catch error.DmaLayoutOverflow;
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
    writeU32Le(
        mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES],
        (@as(u32, TEST_MAX_SCRATCHPAD_BUFFERS >> 5) << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT) |
            ((@as(u32, TEST_MAX_SCRATCHPAD_BUFFERS) & HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK) << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT) |
            HCSPARAMS2_SCRATCHPAD_RESTORE,
    );
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_64_BIT_ADDRESSING | HCCPARAMS1_CONTEXT_SIZE,
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
    try std.testing.expect(caps.supports_64_bit_addressing);
    try std.testing.expectEqual(TEST_CONTEXT_SIZE, caps.context_size);
    try std.testing.expectEqual(TEST_MAX_SCRATCHPAD_BUFFERS, caps.max_scratchpad_buffers);
    try std.testing.expect(caps.scratchpad_restore);
    try std.testing.expectEqual(@as(u32, 0), caps.extended_capability_offset);
    try std.testing.expectEqual(TEST_DOORBELL_OFFSET, caps.doorbell_offset);
    try std.testing.expectEqual(TEST_RUNTIME_REGISTER_OFFSET, caps.runtime_register_offset);
}

test "xHCI capability parser isolates context scratchpad and interrupter fields" {
    var mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, TEST_MAX_DEVICE_SLOTS) |
            (@as(u32, TEST_MAX_INTERRUPTERS) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) |
            (@as(u32, 0x1F) << 19) |
            (@as(u32, TEST_MAX_PORTS) << HCSPARAMS1_MAX_PORTS_SHIFT),
    );
    writeU32Le(
        mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES],
        (HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT) |
            (HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT),
    );
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_64_BIT_ADDRESSING,
    );

    const caps = try parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(TEST_MAX_INTERRUPTERS, caps.max_interrupters);
    try std.testing.expectEqual(ContextSize.bytes_32, caps.context_size);
    try std.testing.expectEqual(@as(u16, 1023), caps.max_scratchpad_buffers);
    try std.testing.expect(!caps.scratchpad_restore);
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
        HCCPARAMS1_64_BIT_ADDRESSING |
            HCCPARAMS1_CONTEXT_SIZE |
            (@as(u32, 0x2000) << HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT),
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

test "xHCI supported protocols accept sparse nonoverlapping USB port ranges" {
    var registers = [_]u8{0} ** 0x100;
    writeU32Le(
        registers[0x40..0x44],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 4) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) |
            (@as(u32, 2) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    writeU32Le(registers[0x44..0x48], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(registers[0x48..0x4C], 1 | (@as(u32, 6) << 8));
    writeU32Le(registers[0x4C..0x50], 0);
    writeU32Le(
        registers[0x50..0x54],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 3) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    writeU32Le(registers[0x54..0x58], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(registers[0x58..0x5C], 7 | (@as(u32, 6) << 8));
    writeU32Le(registers[0x5C..0x60], 1);

    var capabilities = defaultCapabilityRegisters();
    capabilities.max_ports = 12;
    const reader = TestExtendedCapabilityReader{ .bytes = &registers };
    const protocols = try parseSupportedProtocols(capabilities, 0x40, reader);
    try std.testing.expectEqual(ProtocolKind.usb2, protocols.forPort(1).?.kind);
    try std.testing.expectEqual(@as(u5, 0), protocols.forPort(6).?.slot_type);
    try std.testing.expectEqual(@as(u16, 64), try endpointZeroMaxPacketSize(protocols.forPort(1).?, 3));
    try std.testing.expectEqual(@as(u16, 8), try endpointZeroMaxPacketSize(protocols.forPort(1).?, 1));
    try std.testing.expectEqual(@as(u16, 1) << 1, protocols.forPort(1).?.full_speed_ids);
    try std.testing.expectEqual(@as(u16, 1) << 2, protocols.forPort(1).?.low_speed_ids);
    try std.testing.expectEqual(ProtocolKind.usb3, protocols.forPort(7).?.kind);
    try std.testing.expectEqual(@as(u5, 1), protocols.forPort(12).?.slot_type);
    try std.testing.expectEqual(@as(u16, 512), try endpointZeroMaxPacketSize(protocols.forPort(7).?, 4));
    try std.testing.expectError(
        error.InvalidProtocolSpeed,
        endpointZeroMaxPacketSize(protocols.forPort(7).?, 3),
    );
    try std.testing.expect(protocols.forPort(0) == null);

    writeU32Le(registers[0x58..0x5C], 6 | (@as(u32, 6) << 8));
    try std.testing.expectError(
        error.OverlappingSupportedProtocolPorts,
        parseSupportedProtocols(capabilities, 0x40, reader),
    );
    writeU32Le(registers[0x58..0x5C], 8 | (@as(u32, 5) << 8));
    const sparse = try parseSupportedProtocols(capabilities, 0x40, reader);
    try std.testing.expect(sparse.forPort(7) == null);
    try std.testing.expectEqual(ProtocolKind.usb3, sparse.forPort(8).?.kind);

    writeU32Le(registers[0x44..0x48], 0);
    try std.testing.expectError(
        error.InvalidSupportedProtocol,
        parseSupportedProtocols(capabilities, 0x40, reader),
    );
    writeU32Le(registers[0x44..0x48], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(
        registers[0x40..0x44],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 4) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) |
            (@as(u32, 1) << SUPPORTED_PROTOCOL_MINOR_REVISION_SHIFT) |
            (@as(u32, 2) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    try std.testing.expectError(
        error.InvalidSupportedProtocol,
        parseSupportedProtocols(capabilities, 0x40, reader),
    );
}

test "xHCI supported protocol PSI definitions validate custom USB2 speed ids" {
    var registers = [_]u8{0} ** 0x80;
    writeU32Le(
        registers[0x40..0x44],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 2) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    writeU32Le(registers[0x44..0x48], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(
        registers[0x48..0x4C],
        1 | (@as(u32, 1) << 8) | (@as(u32, 2) << 28),
    );
    writeU32Le(registers[0x4C..0x50], 5);
    writeU32Le(
        registers[0x50..0x54],
        9 | (@as(u32, 2) << 4) | (@as(u32, 12) << 16),
    );
    writeU32Le(
        registers[0x54..0x58],
        10 | (@as(u32, 2) << 4) | (@as(u32, 480) << 16),
    );
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_ports = 1;
    const reader = TestExtendedCapabilityReader{ .bytes = &registers };
    const protocols = try parseSupportedProtocols(capabilities, 0x40, reader);
    const protocol = protocols.forPort(1).?;
    try std.testing.expectEqual(@as(u5, 5), protocol.slot_type);
    try std.testing.expectEqual(@as(u16, 8), try endpointZeroMaxPacketSize(protocol, 9));
    try std.testing.expectEqual(@as(u16, 64), try endpointZeroMaxPacketSize(protocol, 10));
    try std.testing.expectEqual(@as(u16, 1) << 9, protocol.full_speed_ids);
    try std.testing.expectEqual(@as(u16, 1) << 10, protocol.high_speed_ids);

    writeU32Le(
        registers[0x54..0x58],
        9 | (@as(u32, 2) << 4) | (@as(u32, 480) << 16),
    );
    try std.testing.expectError(
        error.InvalidSupportedProtocol,
        parseSupportedProtocols(capabilities, 0x40, reader),
    );
}

test "xHCI device descriptor prefix validates endpoint-zero packet size by speed" {
    const usb2 = PortProtocol{
        .kind = .usb2,
        .slot_type = 0,
        .speed_ids = (@as(u16, 1) << 1) | (@as(u16, 1) << 2) | (@as(u16, 1) << 3),
        .full_speed_ids = @as(u16, 1) << 1,
        .low_speed_ids = @as(u16, 1) << 2,
        .high_speed_ids = @as(u16, 1) << 3,
    };
    var prefix = [_]u8{ 18, USB_DESCRIPTOR_DEVICE, 0, 2, 0, 0, 0, 32 };
    try std.testing.expectEqual(
        @as(u16, 32),
        try deviceDescriptorEndpointZeroMaxPacketSize(usb2, 1, &prefix),
    );
    prefix[7] = 8;
    try std.testing.expectEqual(
        @as(u16, 8),
        try deviceDescriptorEndpointZeroMaxPacketSize(usb2, 2, &prefix),
    );
    prefix[7] = 64;
    try std.testing.expectEqual(
        @as(u16, 64),
        try deviceDescriptorEndpointZeroMaxPacketSize(usb2, 3, &prefix),
    );
    prefix[7] = 16;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        deviceDescriptorEndpointZeroMaxPacketSize(usb2, 3, &prefix),
    );

    const usb3 = PortProtocol{
        .kind = .usb3,
        .slot_type = 1,
        .speed_ids = @as(u16, 1) << 4,
    };
    prefix[7] = 9;
    try std.testing.expectEqual(
        @as(u16, 512),
        try deviceDescriptorEndpointZeroMaxPacketSize(usb3, 4, &prefix),
    );
    prefix[0] = 0;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        deviceDescriptorEndpointZeroMaxPacketSize(usb3, 4, &prefix),
    );
}

test "xHCI full device descriptor parser validates identity and USB generation" {
    const usb2 = PortProtocol{
        .kind = .usb2,
        .slot_type = 0,
        .speed_ids = @as(u16, 1) << 3,
        .high_speed_ids = @as(u16, 1) << 3,
    };
    var bytes = [_]u8{
        18, USB_DESCRIPTOR_DEVICE,
        0x10, 0x02,
        0,  0, 0, 64,
        0x6B, 0x04,
        0x01, 0xC3,
        0x23, 0x01,
        1, 2, 3, 2,
    };
    const descriptor = try parseUsbDeviceDescriptor(usb2, 3, &bytes);
    try std.testing.expectEqual(@as(u16, 0x0210), descriptor.usb_version_bcd);
    try std.testing.expectEqual(@as(u16, 64), descriptor.endpoint_zero_max_packet_size);
    try std.testing.expectEqual(@as(u16, 0x046B), descriptor.vendor_id);
    try std.testing.expectEqual(@as(u16, 0xC301), descriptor.product_id);
    try std.testing.expectEqual(@as(u16, 0x0123), descriptor.device_version_bcd);
    try std.testing.expectEqual(@as(u8, 3), descriptor.serial_number_string_index);
    try std.testing.expectEqual(@as(u8, 2), descriptor.configuration_count);

    bytes[5] = 1;
    try std.testing.expectError(error.InvalidUsbDescriptor, parseUsbDeviceDescriptor(usb2, 3, &bytes));
    bytes[5] = 0;
    bytes[17] = 0;
    try std.testing.expectError(error.InvalidUsbDescriptor, parseUsbDeviceDescriptor(usb2, 3, &bytes));
    bytes[17] = 1;
    bytes[2] = 0x1A;
    try std.testing.expectError(error.InvalidUsbDescriptor, parseUsbDeviceDescriptor(usb2, 3, &bytes));
    bytes[2] = 0x10;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbDeviceDescriptor(usb2, 3, bytes[0 .. bytes.len - 1]),
    );

    const usb3 = PortProtocol{
        .kind = .usb3,
        .slot_type = 1,
        .speed_ids = @as(u16, 1) << 4,
    };
    bytes[2] = 0x10;
    bytes[3] = 0x03;
    bytes[7] = 9;
    const superspeed = try parseUsbDeviceDescriptor(usb3, 4, &bytes);
    try std.testing.expectEqual(@as(u16, 0x0310), superspeed.usb_version_bcd);
    try std.testing.expectEqual(@as(u16, 512), superspeed.endpoint_zero_max_packet_size);
    bytes[3] = 0x02;
    try std.testing.expectError(error.InvalidUsbDescriptor, parseUsbDeviceDescriptor(usb3, 4, &bytes));
}

test "xHCI configuration parser validates complete USB2 and USB3 descriptor trees" {
    const usb2 = PortProtocol{
        .kind = .usb2,
        .slot_type = 0,
        .speed_ids = @as(u16, 1) << 3,
        .high_speed_ids = @as(u16, 1) << 3,
    };
    var usb2_bytes = bootKeyboardConfigurationDescriptor(DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const usb2_header = try parseUsbConfigurationDescriptorHeader(
        usb2,
        usb2_bytes[0..USB_CONFIGURATION_DESCRIPTOR_BYTES],
    );
    try std.testing.expectEqual(@as(u16, usb2_bytes.len), usb2_header.total_length);
    try std.testing.expectEqual(@as(u8, 1), usb2_header.interface_count);
    try std.testing.expectEqual(@as(u8, 1), usb2_header.configuration_value);
    try std.testing.expect(!usb2_header.self_powered);
    try std.testing.expect(!usb2_header.remote_wakeup);
    try std.testing.expectEqual(@as(u16, 100), usb2_header.max_power_milliamps);
    try std.testing.expectEqualDeep(
        usb2_header,
        try parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    const usb2_selection = try parseUsbBootKeyboardConfiguration(usb2, 3, &usb2_bytes);
    try std.testing.expectEqualDeep(usb2_header, usb2_selection.configuration);
    try std.testing.expectEqual(@as(u8, 0), usb2_selection.keyboard.interface_number);
    try std.testing.expectEqual(@as(u8, 1), usb2_selection.keyboard.endpoint_id);
    try std.testing.expectEqual(@as(u5, 3), usb2_selection.keyboard.device_context_index);
    try std.testing.expectEqual(@as(u16, 8), usb2_selection.keyboard.max_packet_size);
    try std.testing.expectEqual(@as(u8, 0), usb2_selection.keyboard.max_burst_size);
    try std.testing.expectEqual(@as(u8, 9), usb2_selection.keyboard.interval);
    try std.testing.expectEqual(@as(u16, 8), usb2_selection.keyboard.max_esit_payload);

    const full_speed = PortProtocol{
        .kind = .usb2,
        .slot_type = 0,
        .speed_ids = @as(u16, 1) << 2,
        .full_speed_ids = @as(u16, 1) << 2,
    };
    const full_speed_selection = try parseUsbBootKeyboardConfiguration(
        full_speed,
        2,
        &usb2_bytes,
    );
    try std.testing.expectEqual(@as(u8, 6), full_speed_selection.keyboard.interval);
    usb2_bytes[12] = 1;
    try std.testing.expectError(
        error.MissingBootKeyboardInterface,
        parseUsbBootKeyboardConfiguration(usb2, 3, &usb2_bytes),
    );
    usb2_bytes[12] = 0;

    usb2_bytes[7] = 0;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[7] = 0x80;
    usb2_bytes[0] = USB_CONFIGURATION_DESCRIPTOR_BYTES + 1;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptorHeader(
            usb2,
            usb2_bytes[0..USB_CONFIGURATION_DESCRIPTOR_BYTES],
        ),
    );
    usb2_bytes[0] = USB_CONFIGURATION_DESCRIPTOR_BYTES;
    usb2_bytes[4] = 2;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[4] = 1;
    usb2_bytes[13] = 2;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[13] = 1;
    usb2_bytes[29] = 0;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[29] = USB_ENDPOINT_DIRECTION_IN | DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptor(
            usb2,
            usb2_bytes[0 .. usb2_bytes.len - 1],
        ),
    );

    const usb3 = PortProtocol{
        .kind = .usb3,
        .slot_type = 1,
        .speed_ids = @as(u16, 1) << 4,
    };
    var usb3_bytes = [_]u8{
        9, USB_DESCRIPTOR_CONFIGURATION, 31, 0, 1, 1, 0, 0xA0, 50,
        9, USB_DESCRIPTOR_INTERFACE, 0, 0, 1, USB_CLASS_HID, USB_HID_SUBCLASS_BOOT, USB_HID_PROTOCOL_KEYBOARD, 0,
        7, USB_DESCRIPTOR_ENDPOINT, USB_ENDPOINT_DIRECTION_IN | 1, USB_ENDPOINT_TRANSFER_INTERRUPT, 8, 0, 10,
        6, USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION, 0, 0, 0, 0,
    };
    const usb3_descriptor = try parseUsbConfigurationDescriptor(usb3, &usb3_bytes);
    try std.testing.expectEqual(@as(u16, 31), usb3_descriptor.total_length);
    try std.testing.expect(usb3_descriptor.remote_wakeup);
    try std.testing.expectEqual(@as(u16, 400), usb3_descriptor.max_power_milliamps);
    usb3_bytes[29] = HID_BOOT_KEYBOARD_REPORT_BYTES;
    const usb3_selection = try parseUsbBootKeyboardConfiguration(usb3, 4, &usb3_bytes);
    try std.testing.expectEqual(@as(u8, 9), usb3_selection.keyboard.interval);
    try std.testing.expectEqual(@as(u16, 8), usb3_selection.keyboard.max_esit_payload);
    usb3_bytes[28] = 1;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbBootKeyboardConfiguration(usb3, 4, &usb3_bytes),
    );
    usb3_bytes[28] = 0;
    usb3_bytes[26] = USB_DESCRIPTOR_HID;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        parseUsbConfigurationDescriptor(usb3, &usb3_bytes),
    );
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

const ScriptedOperationalMmio = struct {
    command_offset: u32,
    status_offset: u32,
    command_reads: []const u32,
    status_reads: []const u32,
    command_read_index: usize = 0,
    status_read_index: usize = 0,
    writes: [4]u32 = [_]u32{0} ** 4,
    write_count: usize = 0,

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        if (offset == self.command_offset) {
            const index = @min(self.command_read_index, self.command_reads.len - 1);
            self.command_read_index += 1;
            return self.command_reads[index];
        }
        if (offset == self.status_offset) {
            const index = @min(self.status_read_index, self.status_reads.len - 1);
            self.status_read_index += 1;
            return self.status_reads[index];
        }
        unreachable;
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        if (offset != self.command_offset or self.write_count == self.writes.len) unreachable;
        self.writes[self.write_count] = value;
        self.write_count += 1;
    }
};

fn scriptedOperationalMmio(command_reads: []const u32, status_reads: []const u32) ScriptedOperationalMmio {
    return .{
        .command_offset = @as(u32, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_COMMAND_OFFSET,
        .status_offset = @as(u32, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_STATUS_OFFSET,
        .command_reads = command_reads,
        .status_reads = status_reads,
    };
}

const MockResetClock = struct {
    deadline_checks: usize,
    requested_milliseconds: [4]u64 = [_]u64{0} ** 4,
    request_count: usize = 0,

    pub fn afterMilliseconds(self: *@This(), milliseconds: u64) MockOwnershipDeadline {
        if (self.request_count == self.requested_milliseconds.len) unreachable;
        self.requested_milliseconds[self.request_count] = milliseconds;
        self.request_count += 1;
        return .{ .remaining_checks = self.deadline_checks };
    }
};

test "xHCI reset quiesces a running controller and completes bounded handshakes" {
    const preserved_command_bit: u32 = 1 << 14;
    const command_reads = [_]u32{
        preserved_command_bit | USB_COMMAND_RUN_STOP | USB_COMMAND_INTERRUPTER_ENABLE | USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE,
        preserved_command_bit,
        USB_COMMAND_HOST_CONTROLLER_RESET,
        0,
    };
    const status_reads = [_]u32{
        USB_STATUS_CONTROLLER_NOT_READY,
        0,
        0,
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_CONTROLLER_NOT_READY,
        USB_STATUS_HOST_CONTROLLER_HALTED,
    };
    var mmio = scriptedOperationalMmio(&command_reads, &status_reads);
    var clock = MockResetClock{ .deadline_checks = 2 };
    try resetOwnedController(TEST_CAPABILITY_LENGTH, &mmio, &clock);
    try std.testing.expectEqual(@as(usize, 2), mmio.write_count);
    try std.testing.expectEqual(preserved_command_bit, mmio.writes[0]);
    try std.testing.expectEqual(
        preserved_command_bit | USB_COMMAND_HOST_CONTROLLER_RESET,
        mmio.writes[1],
    );
    try std.testing.expectEqualSlices(u64, &.{
        CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS,
        CONTROLLER_HALT_TIMEOUT_MILLISECONDS,
        CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS,
        CONTROLLER_HANDSHAKE_TIMEOUT_MILLISECONDS,
    }, clock.requested_milliseconds[0..clock.request_count]);
}

test "xHCI reset skips the halt write when the controller is already stopped" {
    const command_reads = [_]u32{
        USB_COMMAND_INTERRUPTER_ENABLE | USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE,
        USB_COMMAND_HOST_CONTROLLER_RESET,
        0,
    };
    const status_reads = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_HOST_CONTROLLER_HALTED,
    };
    var mmio = scriptedOperationalMmio(&command_reads, &status_reads);
    var clock = MockResetClock{ .deadline_checks = 2 };
    try resetOwnedController(TEST_CAPABILITY_LENGTH, &mmio, &clock);
    try std.testing.expectEqual(@as(usize, 1), mmio.write_count);
    try std.testing.expectEqual(USB_COMMAND_HOST_CONTROLLER_RESET, mmio.writes[0]);
}

test "xHCI reset fails closed on ready, halt, reset, and final-state faults" {
    const no_command = [_]u32{0};
    const never_ready = [_]u32{USB_STATUS_CONTROLLER_NOT_READY};
    var mmio = scriptedOperationalMmio(&no_command, &never_ready);
    var expired = MockResetClock{ .deadline_checks = 0 };
    try std.testing.expectError(error.ControllerNotReadyTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const running = [_]u32{0};
    mmio = scriptedOperationalMmio(&no_command, &running);
    expired = .{ .deadline_checks = 0 };
    try std.testing.expectError(error.ControllerHaltTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const reset_stuck = [_]u32{ 0, USB_COMMAND_HOST_CONTROLLER_RESET };
    const halted = [_]u32{USB_STATUS_HOST_CONTROLLER_HALTED};
    mmio = scriptedOperationalMmio(&reset_stuck, &halted);
    expired = .{ .deadline_checks = 0 };
    try std.testing.expectError(error.ControllerResetTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const reset_completes = [_]u32{ 0, USB_COMMAND_HOST_CONTROLLER_RESET, 0 };
    const ready_then_stuck = [_]u32{ USB_STATUS_HOST_CONTROLLER_HALTED, USB_STATUS_CONTROLLER_NOT_READY };
    mmio = scriptedOperationalMmio(&reset_completes, &ready_then_stuck);
    expired = .{ .deadline_checks = 1 };
    try std.testing.expectError(error.ControllerNotReadyTimeout, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));

    const failed_state = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_HOST_CONTROLLER_HALTED | USB_STATUS_HOST_CONTROLLER_ERROR,
    };
    mmio = scriptedOperationalMmio(&reset_completes, &failed_state);
    expired = .{ .deadline_checks = 1 };
    try std.testing.expectError(error.ControllerResetFailed, resetOwnedController(
        TEST_CAPABILITY_LENGTH,
        &mmio,
        &expired,
    ));
}

const MockStartMmio = struct {
    capabilities: CapabilityRegisters = defaultCapabilityRegisters(),
    command: u32 = 1 << 14,
    iman: u32 = 0,
    erdp: u64 = 0,
    last_erdp_write: u64 = 0,
    status_reads: []const u32,
    status_read_index: usize = 0,

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        const operational_base: u32 = self.capabilities.capability_length;
        if (offset == operational_base + OPERATIONAL_USB_COMMAND_OFFSET) return self.command;
        if (offset == operational_base + OPERATIONAL_USB_STATUS_OFFSET) {
            const index = @min(self.status_read_index, self.status_reads.len - 1);
            self.status_read_index += 1;
            return self.status_reads[index];
        }
        const iman_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + INTERRUPTER_MANAGEMENT_OFFSET;
        if (offset == iman_offset) return self.iman;
        unreachable;
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        const operational_base: u32 = self.capabilities.capability_length;
        if (offset == operational_base + OPERATIONAL_USB_COMMAND_OFFSET) {
            self.command = value;
            return;
        }
        const iman_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + INTERRUPTER_MANAGEMENT_OFFSET;
        if (offset == iman_offset) {
            self.iman = value;
            return;
        }
        unreachable;
    }

    pub fn readReg64(self: *@This(), offset: u32) u64 {
        const erdp_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + EVENT_RING_DEQUEUE_POINTER_OFFSET;
        if (offset != erdp_offset) unreachable;
        return self.erdp;
    }

    pub fn writeReg64(self: *@This(), offset: u32, value: u64) void {
        const erdp_offset = self.capabilities.runtime_register_offset +
            PRIMARY_INTERRUPTER_OFFSET + EVENT_RING_DEQUEUE_POINTER_OFFSET;
        if (offset != erdp_offset) unreachable;
        self.last_erdp_write = value;
        self.erdp = value & EVENT_RING_DEQUEUE_POINTER_MASK;
    }
};

test "xHCI start enables the primary interrupter before the schedule" {
    const halted_then_running = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED,
        USB_STATUS_HOST_CONTROLLER_HALTED,
        0,
    };
    var mmio = MockStartMmio{ .status_reads = &halted_then_running };
    var clock = MockResetClock{ .deadline_checks = 2 };
    try startOwnedController(mmio.capabilities, &mmio, &clock);

    const expected_enable_mask = USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE |
        USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE;
    try std.testing.expectEqual(expected_enable_mask, mmio.command & expected_enable_mask);
    try std.testing.expectEqual(INTERRUPTER_ENABLE, mmio.iman & INTERRUPTER_ENABLE);
    try std.testing.expectEqual(@as(usize, 1), clock.request_count);
    try std.testing.expect(controllerRunningHealthy(mmio.capabilities, &mmio));
}

test "xHCI start failure restores a quiescent controller" {
    const halted = [_]u32{USB_STATUS_HOST_CONTROLLER_HALTED};
    var mmio = MockStartMmio{ .status_reads = &halted };
    var expired = MockResetClock{ .deadline_checks = 0 };
    try std.testing.expectError(
        error.ControllerStartTimeout,
        startOwnedController(mmio.capabilities, &mmio, &expired),
    );
    try std.testing.expectEqual(@as(u32, 0), mmio.command & (USB_COMMAND_RUN_STOP |
        USB_COMMAND_INTERRUPTER_ENABLE | USB_COMMAND_HOST_SYSTEM_ERROR_ENABLE));
    try std.testing.expectEqual(@as(u32, 0), mmio.iman & INTERRUPTER_ENABLE);

    const host_error = [_]u32{
        USB_STATUS_HOST_CONTROLLER_HALTED | USB_STATUS_HOST_SYSTEM_ERROR,
    };
    mmio = .{ .status_reads = &host_error };
    expired = .{ .deadline_checks = 1 };
    try std.testing.expectError(
        error.ControllerStartUnavailable,
        startOwnedController(mmio.capabilities, &mmio, &expired),
    );
}

test "xHCI event consumer follows cycle ownership and wrap" {
    var consumer = EventRingConsumer{};
    const port_event = [4]u32{
        @as(u32, 7) << 24,
        0,
        @as(u32, COMPLETION_CODE_SUCCESS) << 24,
        (@as(u32, EVENT_TRB_PORT_STATUS_CHANGE) << TRB_TYPE_SHIFT) | 1,
    };
    const first = (try consumer.consume(port_event, 2)).?;
    try std.testing.expectEqual(EventType.port_status_change, first.kind);
    try std.testing.expect(first.succeeded());
    try std.testing.expectEqual(@as(u8, 7), first.port_id);
    try std.testing.expectEqual(@as(u24, 0), first.transfer_length);
    try std.testing.expect(!first.event_data);
    try std.testing.expectEqual(@as(u32, 1), consumer.dequeue_index);

    var command_event = port_event;
    command_event[3] = (@as(u32, EVENT_TRB_COMMAND_COMPLETION) << TRB_TYPE_SHIFT) |
        (@as(u32, 3) << 24) | 1;
    const second = (try consumer.consume(command_event, 2)).?;
    try std.testing.expectEqual(EventType.command_completion, second.kind);
    try std.testing.expectEqual(@as(u8, 3), second.slot_id);
    try std.testing.expectEqual(@as(u64, 7) << 24, second.parameter);
    try std.testing.expectEqual(@as(u32, 0), consumer.dequeue_index);
    try std.testing.expectEqual(@as(u1, 0), consumer.cycle_state);

    const transfer = decodeEvent(.{
        0x1234_5000,
        0,
        (@as(u32, COMPLETION_CODE_SUCCESS) << 24) | 5,
        (@as(u32, 4) << 24) | (@as(u32, ENDPOINT_ZERO_DCI) << 16) |
            (@as(u32, EVENT_TRB_TRANSFER) << TRB_TYPE_SHIFT) | (1 << 2),
    });
    try std.testing.expectEqual(EventType.transfer, transfer.kind);
    try std.testing.expectEqual(@as(u24, 5), transfer.transfer_length);
    try std.testing.expectEqual(@as(u5, ENDPOINT_ZERO_DCI), transfer.endpoint_id);
    try std.testing.expect(transfer.event_data);

    try std.testing.expect((try consumer.consume(port_event, 2)) == null);
    var wrapped = port_event;
    wrapped[3] &= ~@as(u32, 1);
    try std.testing.expect((try consumer.consume(wrapped, 2)) != null);
    try std.testing.expectEqual(@as(u64, 0x2010), try consumer.dequeueAddress(0x2000, 2));
}

test "xHCI PORTSC writes preserve sticky controls and acknowledge only changes" {
    const status_value = PORT_CURRENT_CONNECT_STATUS |
        PORT_ENABLED_DISABLED |
        PORT_OVER_CURRENT_ACTIVE |
        PORT_RESET |
        (@as(u32, 5) << PORT_LINK_STATE_SHIFT) |
        PORT_POWER |
        (@as(u32, 3) << PORT_SPEED_SHIFT) |
        (@as(u32, 2) << 14) |
        (@as(u32, 0b1010101) << 17) |
        PORT_COLD_ATTACH_STATUS |
        (@as(u32, 0b101) << 25) |
        (@as(u32, 1) << 31);
    const status = decodePortStatus(status_value);
    try std.testing.expect(status.connected);
    try std.testing.expect(status.enabled);
    try std.testing.expect(status.over_current);
    try std.testing.expect(status.reset_active);
    try std.testing.expectEqual(@as(u4, 5), status.link_state);
    try std.testing.expectEqual(@as(u4, 3), status.speed);
    try std.testing.expect(status.cold_attach);
    try std.testing.expectEqual(@as(u7, 0b1010101), status.change_bits);

    const acknowledge = portStatusAcknowledge(status_value);
    try std.testing.expectEqual(status_value & (PORT_READ_WRITE_STICKY_MASK | PORT_CHANGE_MASK), acknowledge);
    try std.testing.expectEqual(
        @as(u32, 0),
        acknowledge & (PORT_ENABLED_DISABLED | PORT_RESET |
            (@as(u32, 1) << 16) | (@as(u32, 1) << 31)),
    );
    try std.testing.expect((portResetWrite(status_value, .{ .kind = .usb2, .slot_type = 0 }) & PORT_RESET) != 0);
    try std.testing.expect((portResetWrite(status_value, .{ .kind = .usb3, .slot_type = 1 }) & (@as(u32, 1) << 31)) != 0);
}

test "xHCI TRB producer encodes slot commands and toggles on the link TRB" {
    const plan = RingPlan{
        .command_ring_trbs = 4,
        .event_ring_trbs = 4,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    };
    var producer = TrbRingProducer{};
    try std.testing.expectEqual(
        @as(u64, 0x1000),
        try producer.trbAddress(plan.command_ring_address, plan.command_ring_trbs),
    );
    try std.testing.expectEqual(
        @as(u64, 0x1030),
        try producer.linkAddress(plan.command_ring_address, plan.command_ring_trbs),
    );
    const enable = enableSlotCommand(7, producer.cycle_state);
    try std.testing.expectEqual(
        (@as(u32, 7) << 16) | (ENABLE_SLOT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) | 1,
        enable[3],
    );
    try std.testing.expect(!(try producer.advance(plan.command_ring_trbs)));
    try std.testing.expect(!(try producer.advance(plan.command_ring_trbs)));
    try std.testing.expect(try producer.advance(plan.command_ring_trbs));
    try std.testing.expectEqual(@as(u32, 0), producer.enqueue_index);
    try std.testing.expectEqual(@as(u1, 0), producer.cycle_state);
    const disable = try disableSlotCommand(4, producer.cycle_state);
    try std.testing.expectEqual(
        (@as(u32, 4) << 24) | (DISABLE_SLOT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT),
        disable[3],
    );
    try std.testing.expectEqual(
        (LINK_TRB_TYPE << TRB_TYPE_SHIFT) | LINK_TRB_TOGGLE_CYCLE | 1,
        ringLinkControl(1),
    );
}

const MockDoorbellMmio = struct {
    offset: u32 = 0,
    value: u32 = 0,

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        self.offset = offset;
        self.value = value;
    }
};

test "xHCI descriptor control stages and slot doorbell are exact" {
    const setup = try getDescriptorSetupStage(
        USB_DESCRIPTOR_DEVICE,
        0,
        USB_DEVICE_DESCRIPTOR_PREFIX_BYTES,
        1,
    );
    try std.testing.expectEqual(@as(u32, 0x0100_0680), setup[0]);
    try std.testing.expectEqual(@as(u32, 0x0008_0000), setup[1]);
    try std.testing.expectEqual(@as(u32, USB_DEVICE_DESCRIPTOR_PREFIX_BYTES), setup[2]);
    try std.testing.expectEqual(
        SETUP_TRANSFER_TYPE_IN | (SETUP_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_IMMEDIATE_DATA | 1,
        setup[3],
    );
    const data = try controlInDataStage(0x9000, USB_DEVICE_DESCRIPTOR_PREFIX_BYTES, 0);
    try std.testing.expectEqual(@as(u32, 0x9000), data[0]);
    try std.testing.expectEqual(@as(u32, USB_DEVICE_DESCRIPTOR_PREFIX_BYTES), data[2]);
    try std.testing.expectEqual(
        CONTROL_TRANSFER_DIRECTION_IN |
            (DATA_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_SHORT_PACKET,
        data[3],
    );
    const status = controlOutStatusStage(1);
    try std.testing.expectEqual(@as(u32, 0), status[0]);
    try std.testing.expectEqual(
        (STATUS_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) | TRB_INTERRUPT_ON_COMPLETION | 1,
        status[3],
    );
    var wrapping_producer = TrbRingProducer{ .enqueue_index = TRANSFER_RING_TRBS - 2 };
    try std.testing.expectEqual(
        @as(u64, 0x80E0),
        try wrapping_producer.trbAddress(0x8000, TRANSFER_RING_TRBS),
    );
    try std.testing.expect(try wrapping_producer.advance(TRANSFER_RING_TRBS));
    try std.testing.expectEqual(@as(u1, 0), wrapping_producer.cycle_state);
    try std.testing.expectEqual(
        @as(u32, 0),
        (try controlInDataStage(
            0x9000,
            USB_DEVICE_DESCRIPTOR_PREFIX_BYTES,
            wrapping_producer.cycle_state,
        ))[3] & 1,
    );
    const configuration_setup = try getDescriptorSetupStage(
        USB_DESCRIPTOR_CONFIGURATION,
        3,
        0x1234,
        0,
    );
    try std.testing.expectEqual(@as(u32, 0x0203_0680), configuration_setup[0]);
    try std.testing.expectEqual(@as(u32, 0x1234_0000), configuration_setup[1]);
    const set_configuration = try setConfigurationSetupStage(5, 1);
    try std.testing.expectEqual(@as(u32, 0x0005_0900), set_configuration[0]);
    try std.testing.expectEqual(@as(u32, 0), set_configuration[1]);
    try std.testing.expectEqual(USB_SETUP_PACKET_BYTES, set_configuration[2]);
    try std.testing.expectEqual(
        (SETUP_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) | TRB_IMMEDIATE_DATA | 1,
        set_configuration[3],
    );
    const set_configuration_status = controlInStatusStage(1);
    try std.testing.expectEqual(
        STATUS_STAGE_DIRECTION_IN |
            (STATUS_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_COMPLETION | 1,
        set_configuration_status[3],
    );
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        setConfigurationSetupStage(0, 1),
    );
    try std.testing.expectError(error.InvalidUsbDescriptor, getDescriptorSetupStage(0, 0, 8, 1));
    try std.testing.expectError(
        error.DmaAddressOutsidePlan,
        controlInDataStage(0x9000, 0, 1),
    );
    try std.testing.expectError(
        error.DmaAddressOutsidePlan,
        controlInDataStage(0xF000, 0x2000, 1),
    );
    const maximum_data = try controlInDataStage(
        XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES,
        @intCast(USB_ENUMERATION_BUFFER_BYTES),
        1,
    );
    try std.testing.expectEqual(USB_ENUMERATION_BUFFER_BYTES, maximum_data[2]);

    var mmio = MockDoorbellMmio{};
    const capabilities = defaultCapabilityRegisters();
    try ringCommandDoorbell(capabilities, &mmio);
    try std.testing.expectEqual(TEST_DOORBELL_OFFSET, mmio.offset);
    try std.testing.expectEqual(@as(u32, 0), mmio.value);
    try ringDeviceDoorbell(capabilities, 4, ENDPOINT_ZERO_DCI, &mmio);
    try std.testing.expectEqual(TEST_DOORBELL_OFFSET + 4 * @sizeOf(u32), mmio.offset);
    try std.testing.expectEqual(@as(u32, ENDPOINT_ZERO_DCI), mmio.value);
    try std.testing.expectError(
        error.InvalidDeviceSlot,
        ringDeviceDoorbell(capabilities, 0, ENDPOINT_ZERO_DCI, &mmio),
    );
    try std.testing.expectError(error.EndpointMismatch, ringDeviceDoorbell(capabilities, 1, 0, &mmio));
}

test "xHCI Address Device context encodes only slot and endpoint zero authority" {
    var input_context = [_]u8{0xA5} ** (INPUT_CONTEXT_ENTRIES * 64);
    try initializeAddressDeviceInputContext(
        .bytes_64,
        7,
        4,
        512,
        0x8000,
        &input_context,
    );
    try std.testing.expectEqual(ADDRESS_DEVICE_ADD_CONTEXT_FLAGS, readU32Le(input_context[4..8]));
    const slot_offset: usize = 64;
    try std.testing.expectEqual(
        (@as(u32, 4) << 20) | (ADDRESS_DEVICE_CONTEXT_ENTRIES << 27),
        readU32Le(input_context[slot_offset..][0..4]),
    );
    try std.testing.expectEqual(@as(u32, 7) << 16, readU32Le(input_context[slot_offset + 4 ..][0..4]));
    const endpoint_offset: usize = 128;
    try std.testing.expectEqual(
        (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
            (ENDPOINT_TYPE_CONTROL << 3) |
            (@as(u32, 512) << 16),
        readU32Le(input_context[endpoint_offset + 4 ..][0..4]),
    );
    try std.testing.expectEqual(@as(u64, 0x8001), readU64Le(input_context[endpoint_offset + 8 ..][0..8]));
    try std.testing.expectEqual(
        CONTROL_ENDPOINT_AVERAGE_TRB_LENGTH,
        readU32Le(input_context[endpoint_offset + 16 ..][0..4]),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** 64),
        input_context[3 * 64 .. 4 * 64],
    );

    const command = try addressDeviceCommand(0x9000, 5, 1);
    try std.testing.expectEqual(@as(u32, 0x9000), command[0]);
    try std.testing.expectEqual(@as(u32, 0), command[1]);
    try std.testing.expectEqual(
        (@as(u32, 5) << 24) | (ADDRESS_DEVICE_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) | 1,
        command[3],
    );
    try std.testing.expectError(error.InvalidInputContext, addressDeviceCommand(0x9001, 5, 1));
    try std.testing.expectError(error.InvalidDeviceSlot, addressDeviceCommand(0x9000, 0, 1));

    var compact_context = [_]u8{0xA5} ** (INPUT_CONTEXT_ENTRIES * 32);
    try initializeAddressDeviceInputContext(
        .bytes_32,
        2,
        3,
        64,
        0xA000,
        &compact_context,
    );
    try std.testing.expectEqual(ADDRESS_DEVICE_ADD_CONTEXT_FLAGS, readU32Le(compact_context[4..8]));
    try std.testing.expectEqual(
        (@as(u32, 3) << 20) | (ADDRESS_DEVICE_CONTEXT_ENTRIES << 27),
        readU32Le(compact_context[32..36]),
    );
    try std.testing.expectEqual(@as(u64, 0xA001), readU64Le(compact_context[72..80]));
    try std.testing.expectError(
        error.InvalidInputContext,
        initializeAddressDeviceInputContext(.bytes_32, 2, 3, 64, 0xA000, compact_context[0 .. compact_context.len - 1]),
    );
    try std.testing.expectError(
        error.InvalidInputContext,
        initializeAddressDeviceInputContext(.bytes_32, 2, 3, 64, 0xA001, &compact_context),
    );
}

test "xHCI Evaluate Context updates only endpoint-zero max packet size" {
    var input_context = [_]u8{0xA5} ** (INPUT_CONTEXT_ENTRIES * 64);
    try initializeEvaluateEndpointZeroInputContext(.bytes_64, 32, &input_context);
    try std.testing.expectEqual(
        EVALUATE_ENDPOINT_ZERO_ADD_CONTEXT_FLAGS,
        readU32Le(input_context[4..8]),
    );
    try std.testing.expectEqual(@as(u32, 32) << 16, readU32Le(input_context[132..136]));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), input_context[64..128]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 48), input_context[144..192]);

    const command = try evaluateContextCommand(0x9000, 5, 1);
    try std.testing.expectEqual(@as(u32, 0x9000), command[0]);
    try std.testing.expectEqual(
        (@as(u32, 5) << 24) | (EVALUATE_CONTEXT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) | 1,
        command[3],
    );
    try std.testing.expectError(error.InvalidInputContext, evaluateContextCommand(0x9001, 5, 1));
    try std.testing.expectError(error.InvalidDeviceSlot, evaluateContextCommand(0x9000, 0, 1));
    try std.testing.expectError(
        error.InvalidInputContext,
        initializeEvaluateEndpointZeroInputContext(.bytes_64, 12, &input_context),
    );
}

test "xHCI Configure Endpoint context grants one interrupt-IN endpoint" {
    const keyboard = UsbBootKeyboardConfiguration{
        .configuration_value = 1,
        .interface_number = 0,
        .endpoint_id = 1,
        .device_context_index = 3,
        .max_packet_size = HID_BOOT_KEYBOARD_REPORT_BYTES,
        .max_burst_size = 0,
        .interval = 9,
        .max_esit_payload = HID_BOOT_KEYBOARD_REPORT_BYTES,
    };
    var input_context = [_]u8{0xA5} ** (INPUT_CONTEXT_ENTRIES * 64);
    try initializeConfigureInterruptInEndpointInputContext(
        .bytes_64,
        keyboard,
        0xA000,
        &input_context,
    );
    try std.testing.expectEqual(@as(u32, 0), readU32Le(input_context[0..4]));
    try std.testing.expectEqual(@as(u32, 0b1001), readU32Le(input_context[4..8]));
    try std.testing.expectEqual(
        @as(u32, keyboard.device_context_index) << 27,
        readU32Le(input_context[64..68]),
    );
    const endpoint_offset: usize = 4 * 64;
    try std.testing.expectEqual(
        @as(u32, keyboard.interval) << 16,
        readU32Le(input_context[endpoint_offset..][0..4]),
    );
    try std.testing.expectEqual(
        (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
            (ENDPOINT_TYPE_INTERRUPT_IN << 3) |
            (@as(u32, keyboard.max_packet_size) << 16),
        readU32Le(input_context[endpoint_offset + 4 ..][0..4]),
    );
    try std.testing.expectEqual(
        @as(u64, 0xA001),
        readU64Le(input_context[endpoint_offset + 8 ..][0..8]),
    );
    try std.testing.expectEqual(
        INTERRUPT_ENDPOINT_AVERAGE_TRB_LENGTH |
            (@as(u32, keyboard.max_esit_payload) << 16),
        readU32Le(input_context[endpoint_offset + 16 ..][0..4]),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), input_context[128..192]);

    const command = try configureEndpointCommand(0x9000, 5, 1);
    try std.testing.expectEqual(@as(u32, 0x9000), command[0]);
    try std.testing.expectEqual(
        (@as(u32, 5) << 24) |
            (CONFIGURE_ENDPOINT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) | 1,
        command[3],
    );
    try std.testing.expectError(
        error.InvalidInputContext,
        configureEndpointCommand(0x9001, 5, 1),
    );
    try std.testing.expectError(
        error.InvalidDeviceSlot,
        configureEndpointCommand(0x9000, 0, 1),
    );
    var invalid_keyboard = keyboard;
    invalid_keyboard.device_context_index = 5;
    try std.testing.expectError(
        error.InvalidInputContext,
        initializeConfigureInterruptInEndpointInputContext(
            .bytes_64,
            invalid_keyboard,
            0xA000,
            &input_context,
        ),
    );
}

test "xHCI event acknowledgement clears EHB at the next dequeue address" {
    const running = [_]u32{0};
    var mmio = MockStartMmio{ .status_reads = &running };
    try acknowledgePrimaryEventRing(mmio.capabilities, 0x2040, &mmio);
    try std.testing.expectEqual(@as(u64, 0x2040) | EVENT_HANDLER_BUSY, mmio.last_erdp_write);
    try std.testing.expectError(
        error.EventRingStateInvalid,
        acknowledgePrimaryEventRing(mmio.capabilities, 0x2041, &mmio),
    );
}

const MockConfigurationMmio = struct {
    status: u32 = USB_STATUS_HOST_CONTROLLER_HALTED,
    configuration: u32 = 0,
    accept_write: bool = true,
    write_count: usize = 0,

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        const operational_base: u32 = TEST_CAPABILITY_LENGTH;
        if (offset == operational_base + OPERATIONAL_USB_STATUS_OFFSET) return self.status;
        if (offset == operational_base + OPERATIONAL_CONFIGURE_OFFSET) return self.configuration;
        unreachable;
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        if (offset != @as(u32, TEST_CAPABILITY_LENGTH) + OPERATIONAL_CONFIGURE_OFFSET) unreachable;
        self.write_count += 1;
        if (self.accept_write) self.configuration = value;
    }
};

test "xHCI post-reset configuration caps enabled slots to kernel capacity" {
    const preserved_configuration: u32 = (1 << 8) | (1 << 10) | (1 << 20);
    var mmio = MockConfigurationMmio{ .configuration = preserved_configuration };
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 64;

    try std.testing.expectEqual(maxDeviceSlotsU8(), try configureDeviceSlots(capabilities, &mmio));
    try std.testing.expectEqual(@as(usize, 1), mmio.write_count);
    try std.testing.expectEqual(
        preserved_configuration | @as(u32, maxDeviceSlotsU8()),
        mmio.configuration,
    );

    capabilities.max_device_slots = 16;
    mmio = .{};
    try std.testing.expectEqual(@as(u8, 16), try configureDeviceSlots(capabilities, &mmio));
    try std.testing.expectEqual(@as(u32, 16), mmio.configuration);
}

test "xHCI post-reset configuration requires a ready halted controller and accepted readback" {
    const capabilities = defaultCapabilityRegisters();
    var mmio = MockConfigurationMmio{ .status = 0 };
    try std.testing.expectError(
        error.ControllerConfigurationUnavailable,
        configureDeviceSlots(capabilities, &mmio),
    );
    try std.testing.expectEqual(@as(usize, 0), mmio.write_count);

    mmio = .{ .status = USB_STATUS_HOST_CONTROLLER_HALTED | USB_STATUS_CONTROLLER_NOT_READY };
    try std.testing.expectError(
        error.ControllerConfigurationUnavailable,
        configureDeviceSlots(capabilities, &mmio),
    );

    mmio = .{ .accept_write = false };
    try std.testing.expectError(
        error.DeviceSlotConfigurationRejected,
        configureDeviceSlots(capabilities, &mmio),
    );
    try std.testing.expectEqual(@as(usize, 1), mmio.write_count);
}

test "xHCI capability parser rejects unsupported controllers" {
    var mmio = validCapabilityRegisters();
    mmio[CAPABILITY_LENGTH_OFFSET] = TEST_CAPABILITY_LENGTH + 1;
    try std.testing.expectError(error.InvalidCapabilityLength, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], TEST_UNSUPPORTED_INTERFACE_VERSION);
    try std.testing.expectError(error.UnsupportedVersion, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], 0x0100);
    try std.testing.expectError(error.UnsupportedVersion, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_CONTEXT_SIZE,
    );
    try std.testing.expectError(error.Unsupported32BitAddressing, parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES],
        HCSPARAMS2_SCRATCHPAD_RESTORE,
    );
    try std.testing.expectError(error.InvalidScratchpadRestore, parseCapabilityRegisters(mmio[0..]));

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

test "xHCI DMA arena packs complete contexts and scratchpads without overlap" {
    const capabilities = defaultCapabilityRegisters();
    const plan = try planDmaArena(capabilities, TEST_MAX_DEVICE_SLOTS, 0x4000);
    try std.testing.expectEqual(@as(u64, 0x4000), plan.dcbaa_address);
    try std.testing.expectEqual(@as(u32, 33 * DCBAA_ENTRY_BYTES), plan.dcbaa_bytes);
    try std.testing.expectEqual(@as(u64, 0x5000), plan.scratchpad_array_address);
    try std.testing.expectEqual(@as(u64, 33 * SCRATCHPAD_ARRAY_ENTRY_BYTES), plan.scratchpad_array_bytes);
    try std.testing.expectEqual(@as(u64, 0x6000), plan.scratchpad_buffers_address);
    try std.testing.expectEqual(@as(u64, 33) * XHCI_PAGE_BYTES, plan.scratchpad_buffers_bytes);
    try std.testing.expectEqual(@as(u32, 2048), plan.device_context_stride);
    try std.testing.expectEqual(@as(u64, 0x27000), plan.device_contexts_address);
    try std.testing.expectEqual(@as(u64, 0x10000), plan.device_contexts_bytes);
    try std.testing.expectEqual(@as(u64, 0x27000), try plan.deviceContextAddress(1));
    try std.testing.expectEqual(@as(u64, 0x36800), try plan.deviceContextAddress(32));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.deviceContextAddress(0));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.deviceContextAddress(33));
    try std.testing.expectEqual(@as(u64, 0x40000), plan.enumeration_buffer_address);
    try std.testing.expectEqual(USB_ENUMERATION_BUFFER_BYTES, plan.enumeration_buffer_bytes);
    try std.testing.expectEqual(@as(u64, 0x50000), plan.input_context_address);
    try std.testing.expectEqual(@as(u32, 2112), plan.input_context_bytes);
    try std.testing.expectEqual(@as(u64, 0x51000), plan.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u32, 256), plan.control_transfer_ring_stride);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.control_transfer_rings_bytes);
    try std.testing.expectEqual(@as(u64, 0x51000), try plan.controlTransferRingAddress(1));
    try std.testing.expectEqual(@as(u64, 0x52F00), try plan.controlTransferRingAddress(32));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.controlTransferRingAddress(33));
    try std.testing.expectEqual(@as(u64, 0x53000), plan.interrupt_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.interrupt_transfer_rings_bytes);
    try std.testing.expectEqual(@as(u64, 0x53000), try plan.interruptTransferRingAddress(1));
    try std.testing.expectEqual(@as(u64, 0x54F00), try plan.interruptTransferRingAddress(32));
    try std.testing.expectEqual(@as(u64, 0x55000), plan.interrupt_report_buffers_address);
    try std.testing.expectEqual(@as(u64, 0x55000), try plan.interruptReportBufferAddress(1));
    try std.testing.expectEqual(@as(u64, 0x557C0), try plan.interruptReportBufferAddress(32));
    try std.testing.expectError(error.InvalidDeviceSlot, plan.interruptReportBufferAddress(33));
    try std.testing.expectEqual(@as(u64, 0x52000), plan.total_bytes);
}

test "xHCI DMA arena handles compact contexts and rejects invalid ranges" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.context_size = .bytes_32;
    capabilities.max_device_slots = 3;
    capabilities.max_scratchpad_buffers = 0;
    capabilities.scratchpad_restore = false;
    const plan = try planDmaArena(capabilities, 3, 0x1000);
    try std.testing.expectEqual(@as(u64, 0), plan.scratchpad_array_address);
    try std.testing.expectEqual(@as(u64, 0), plan.scratchpad_buffers_address);
    try std.testing.expectEqual(@as(u32, 1024), plan.device_context_stride);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.device_contexts_address);
    try std.testing.expectEqual(@as(u64, 3072), plan.device_contexts_bytes);
    try std.testing.expectEqual(@as(u64, 0x10000), plan.enumeration_buffer_address);
    try std.testing.expectEqual(@as(u64, 0x20000), plan.input_context_address);
    try std.testing.expectEqual(@as(u32, 1056), plan.input_context_bytes);
    try std.testing.expectEqual(@as(u64, 0x21000), plan.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, XHCI_PAGE_BYTES), plan.control_transfer_rings_bytes);
    try std.testing.expectEqual(@as(u64, 0x22000), plan.interrupt_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x23000), plan.interrupt_report_buffers_address);
    try std.testing.expectEqual(@as(u64, 0x23000), plan.total_bytes);

    try std.testing.expectError(error.DmaArenaBaseInvalid, planDmaArena(capabilities, 3, 0));
    try std.testing.expectError(error.DmaArenaBaseInvalid, planDmaArena(capabilities, 3, 0x1800));
    try std.testing.expectError(error.DmaSlotCountInvalid, planDmaArena(capabilities, 0, 0x1000));
    try std.testing.expectError(error.DmaSlotCountInvalid, planDmaArena(capabilities, 4, 0x1000));
    const final_page = std.math.maxInt(u64) & ~(XHCI_PAGE_BYTES - 1);
    try std.testing.expectError(error.DmaLayoutOverflow, planDmaArena(capabilities, 1, final_page));
}

test "xHCI DMA arena page-rounds the maximum scratchpad pointer array" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 1023;
    const plan = try planDmaArena(capabilities, 1, 0x1000);
    try std.testing.expectEqual(@as(u64, 0x2000), plan.scratchpad_array_address);
    try std.testing.expectEqual(@as(u64, 8184), plan.scratchpad_array_bytes);
    try std.testing.expectEqual(@as(u64, 0x4000), plan.scratchpad_buffers_address);
    try std.testing.expectEqual(@as(u64, 1023) * XHCI_PAGE_BYTES, plan.scratchpad_buffers_bytes);
    try std.testing.expectEqual(@as(u64, 0x403000), plan.device_contexts_address);
    try std.testing.expectEqual(@as(u64, 0x410000), plan.enumeration_buffer_address);
    try std.testing.expectEqual(@as(u64, 0x420000), plan.input_context_address);
    try std.testing.expectEqual(@as(u64, 0x421000), plan.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x422000), plan.interrupt_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x423000), plan.interrupt_report_buffers_address);
    try std.testing.expectEqual(@as(u64, 0x423000), plan.total_bytes);

    capabilities.max_device_slots = TEST_MAX_DEVICE_SLOTS;
    const full_plan = try planControllerDma(capabilities, TEST_MAX_DEVICE_SLOTS, 0x1000);
    try std.testing.expectEqual(@as(u32, 1077), try full_plan.frameCount());
}

test "xHCI controller DMA plan initializes rings tables and scratchpad pointers" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 2;
    const plan = try planControllerDma(capabilities, 1, 0x1000);
    try std.testing.expectEqual(@as(u32, 35), try plan.frameCount());
    const reserved_frames = try controllerDmaFrameCount(capabilities, 1);
    var saw_worst_case = false;
    var candidate_base = XHCI_PAGE_BYTES;
    while (candidate_base <= XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) : (candidate_base += XHCI_PAGE_BYTES) {
        const candidate_frames = try (try planControllerDma(
            capabilities,
            1,
            candidate_base,
        )).frameCount();
        try std.testing.expect(candidate_frames <= reserved_frames);
        saw_worst_case = saw_worst_case or candidate_frames == reserved_frames;
    }
    try std.testing.expect(saw_worst_case);
    try std.testing.expectEqual(@as(u64, 0x21000), plan.arena.control_transfer_rings_address);
    try std.testing.expectEqual(@as(u64, 0x2400), plan.event_ring_segment_table_address);
    try std.testing.expectEqual(@as(u32, 64), plan.event_ring_segment_table_bytes);
    try std.testing.expectEqual(@as(u64, 0x3000), plan.arena.base_address);

    var memory = [_]u8{0xA5} ** (35 * @as(usize, XHCI_PAGE_BYTES));
    try std.testing.expectError(
        error.DmaBufferTooSmall,
        initializeControllerDma(plan, memory[0 .. memory.len - 1]),
    );
    try initializeControllerDma(plan, &memory);

    const command_link = memory[(COMMAND_RING_TRBS - 1) * TRB_BYTES ..][0..TRB_BYTES];
    try std.testing.expectEqual(@as(u64, 0x1000), readU64Le(command_link[0..8]));
    try std.testing.expectEqual(
        (@as(u32, LINK_TRB_TYPE) << TRB_TYPE_SHIFT) | LINK_TRB_TOGGLE_CYCLE | 1,
        readU32Le(command_link[12..16]),
    );
    const transfer_link_offset: usize = @intCast(
        plan.arena.control_transfer_rings_address - plan.base_address +
            (@as(u64, plan.arena.control_transfer_ring_trbs) - 1) * TRB_BYTES,
    );
    try std.testing.expectEqual(
        plan.arena.control_transfer_rings_address,
        readU64Le(memory[transfer_link_offset..][0..8]),
    );
    const interrupt_link_offset: usize = @intCast(
        plan.arena.interrupt_transfer_rings_address - plan.base_address +
            (@as(u64, plan.arena.interrupt_transfer_ring_trbs) - 1) * TRB_BYTES,
    );
    try std.testing.expectEqual(
        plan.arena.interrupt_transfer_rings_address,
        readU64Le(memory[interrupt_link_offset..][0..8]),
    );
    const erst_offset: usize = @intCast(plan.event_ring_segment_table_address - plan.base_address);
    try std.testing.expectEqual(
        plan.ring_plan.event_ring_address,
        readU64Le(memory[erst_offset..][0..8]),
    );
    try std.testing.expectEqual(
        plan.ring_plan.event_ring_trbs,
        readU32Le(memory[erst_offset + 8 ..][0..4]),
    );
    const dcbaa_offset: usize = @intCast(plan.arena.dcbaa_address - plan.base_address);
    try std.testing.expectEqual(
        plan.arena.scratchpad_array_address,
        readU64Le(memory[dcbaa_offset..][0..8]),
    );
    try std.testing.expectEqual(@as(u64, 0), readU64Le(memory[dcbaa_offset + 8 ..][0..8]));
    const scratchpad_offset: usize = @intCast(
        plan.arena.scratchpad_array_address - plan.base_address,
    );
    try std.testing.expectEqual(
        plan.arena.scratchpad_buffers_address,
        readU64Le(memory[scratchpad_offset..][0..8]),
    );
    try std.testing.expectEqual(
        plan.arena.scratchpad_buffers_address + XHCI_PAGE_BYTES,
        readU64Le(memory[scratchpad_offset + 8 ..][0..8]),
    );
}

test "xHCI controller DMA regions preserve page-granular direction isolation" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_device_slots = 1;
    capabilities.max_scratchpad_buffers = 2;
    const plan = try planControllerDma(capabilities, 1, 0x1000);
    var region_storage: [MAX_CONTROLLER_DMA_REGIONS]DmaAccessRegion = undefined;
    const regions = try controllerDmaAccessRegions(plan, &region_storage);
    try std.testing.expectEqual(@as(usize, 8), regions.len);
    try std.testing.expectEqualDeep(DmaAccessRegion{
        .address = 0x1000,
        .bytes = XHCI_PAGE_BYTES,
        .device_readable = true,
        .device_writable = false,
    }, regions[0]);
    try std.testing.expect(regions[1].device_readable and regions[1].device_writable);
    try std.testing.expectEqual(plan.arena.dcbaa_address, regions[2].address);
    try std.testing.expect(regions[3].device_readable and !regions[3].device_writable);
    try std.testing.expectEqual(plan.arena.scratchpad_buffers_bytes, regions[4].bytes);
    try std.testing.expect(regions[4].device_readable and regions[4].device_writable);
    try std.testing.expect(regions[5].device_readable and regions[5].device_writable);
    try std.testing.expect(regions[6].device_readable and !regions[6].device_writable);
    try std.testing.expect(!regions[7].device_readable and regions[7].device_writable);
    try std.testing.expectEqual(
        plan.arena.interrupt_report_buffers_address,
        regions[7].address,
    );

    capabilities.context_size = .bytes_32;
    capabilities.max_device_slots = 3;
    capabilities.max_scratchpad_buffers = 0;
    capabilities.scratchpad_restore = false;
    const compact = try planControllerDma(capabilities, 3, 0x1000);
    try std.testing.expectEqual(@as(u32, 35), try compact.frameCount());
    const compact_regions = try controllerDmaAccessRegions(compact, &region_storage);
    try std.testing.expectEqual(@as(usize, 6), compact_regions.len);
    try std.testing.expectEqual(@as(u64, 0x1C000), compact_regions[3].bytes);
    try std.testing.expectEqual(@as(u64, 0x3000), compact_regions[4].bytes);
    try std.testing.expectEqual(@as(u64, XHCI_PAGE_BYTES), compact_regions[5].bytes);
}

const MockDmaRegisterMmio = struct {
    registers: [0x1100]u8 = [_]u8{0} ** 0x1100,
    accept_writes: bool = true,

    fn ready() @This() {
        var mmio = @This(){};
        writeU32Le(
            mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_STATUS_OFFSET ..][0..4],
            USB_STATUS_HOST_CONTROLLER_HALTED,
        );
        writeU32Le(
            mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_PAGE_SIZE_OFFSET ..][0..4],
            PAGE_SIZE_4K_SUPPORTED,
        );
        return mmio;
    }

    pub fn readReg32(self: *@This(), offset: u32) u32 {
        return readU32Le(self.registers[@as(usize, offset)..][0..4]);
    }

    pub fn readReg64(self: *@This(), offset: u32) u64 {
        return readU64Le(self.registers[@as(usize, offset)..][0..8]);
    }

    pub fn writeReg32(self: *@This(), offset: u32, value: u32) void {
        if (self.accept_writes) writeU32Le(self.registers[@as(usize, offset)..][0..4], value);
    }

    pub fn writeReg64(self: *@This(), offset: u32, value: u64) void {
        if (self.accept_writes) writeU64Le(self.registers[@as(usize, offset)..][0..8], value);
    }
};

test "xHCI halted DMA register programming initializes the primary event ring" {
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_scratchpad_buffers = 0;
    capabilities.scratchpad_restore = false;
    const plan = try planControllerDma(capabilities, TEST_MAX_DEVICE_SLOTS, 0x4000);
    var mmio = MockDmaRegisterMmio.ready();
    try programControllerDmaRegisters(capabilities, plan, &mmio);

    const operational_base: u32 = capabilities.capability_length;
    try std.testing.expectEqual(
        plan.arena.dcbaa_address,
        mmio.readReg64(operational_base + OPERATIONAL_DEVICE_CONTEXT_BASE_ARRAY_POINTER_OFFSET),
    );
    try std.testing.expectEqual(
        plan.ring_plan.command_ring_address | COMMAND_RING_INITIAL_CYCLE_STATE,
        mmio.readReg64(operational_base + OPERATIONAL_COMMAND_RING_CONTROL_OFFSET),
    );
    const primary = capabilities.runtime_register_offset + PRIMARY_INTERRUPTER_OFFSET;
    try std.testing.expectEqual(
        INTERRUPTER_MODERATION_INTERVAL_125_MICROSECONDS,
        mmio.readReg32(primary + INTERRUPTER_MODERATION_OFFSET),
    );
    try std.testing.expectEqual(
        EVENT_RING_SEGMENT_TABLE_ENTRIES,
        mmio.readReg32(primary + EVENT_RING_SEGMENT_TABLE_SIZE_OFFSET),
    );
    try std.testing.expectEqual(
        plan.event_ring_segment_table_address,
        mmio.readReg64(primary + EVENT_RING_SEGMENT_TABLE_BASE_OFFSET),
    );
    try std.testing.expectEqual(
        plan.ring_plan.event_ring_address,
        mmio.readReg64(primary + EVENT_RING_DEQUEUE_POINTER_OFFSET),
    );
}

test "xHCI DMA register programming rejects unsafe controller states" {
    const capabilities = defaultCapabilityRegisters();
    const plan = try planControllerDma(capabilities, TEST_MAX_DEVICE_SLOTS, 0x4000);
    var mmio = MockDmaRegisterMmio.ready();
    writeU32Le(
        mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_USB_STATUS_OFFSET ..][0..4],
        0,
    );
    try std.testing.expectError(
        error.DmaProgrammingUnavailable,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );

    mmio = MockDmaRegisterMmio.ready();
    writeU32Le(
        mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_PAGE_SIZE_OFFSET ..][0..4],
        0,
    );
    try std.testing.expectError(
        error.UnsupportedPageSize,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );

    mmio = MockDmaRegisterMmio.ready();
    writeU64Le(
        mmio.registers[@as(usize, TEST_CAPABILITY_LENGTH) + OPERATIONAL_COMMAND_RING_CONTROL_OFFSET ..][0..8],
        COMMAND_RING_RUNNING,
    );
    try std.testing.expectError(
        error.DmaProgrammingUnavailable,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );

    mmio = MockDmaRegisterMmio.ready();
    mmio.accept_writes = false;
    try std.testing.expectError(
        error.DmaRegisterRejected,
        programControllerDmaRegisters(capabilities, plan, &mmio),
    );
}

test "xHCI controller binds MMIO command doorbells and event ring input proof" {
    try std.testing.expectError(error.MissingDoorbellRegisters, HidController.initWithMmio(.{
        .capability_length = TEST_CAPABILITY_LENGTH,
        .interface_version = TEST_INTERFACE_VERSION,
        .max_device_slots = TEST_MAX_DEVICE_SLOTS,
        .max_interrupters = TEST_MAX_INTERRUPTERS,
        .max_ports = TEST_MAX_PORTS,
        .supports_64_bit_addressing = true,
        .context_size = TEST_CONTEXT_SIZE,
        .max_scratchpad_buffers = 0,
        .scratchpad_restore = false,
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
    try std.testing.expectEqual(TEST_CONTEXT_SIZE, proof.mmio.context_size);
    try std.testing.expectEqual(
        @as(u32, TEST_MAX_DEVICE_SLOTS) * DEVICE_CONTEXT_ENTRIES * TEST_CONTEXT_SIZE.byteCount(),
        proof.mmio.device_context_bytes,
    );
    try std.testing.expectEqual(
        INPUT_CONTEXT_ENTRIES * TEST_CONTEXT_SIZE.byteCount(),
        proof.mmio.input_context_bytes,
    );
    const dma_arena = controller.dmaArenaPlan().?;
    try std.testing.expectEqual(@as(u64, 0x3000), dma_arena.base_address);
    try std.testing.expectEqual(TEST_MAX_DEVICE_SLOTS, dma_arena.enabled_device_slots);
    try std.testing.expectEqual(TRANSFER_RING_TRBS, proof.mmio.transfer_ring_trbs);
    try std.testing.expectEqual(EVENT_RING_SEGMENT_TABLE_ENTRIES, proof.mmio.event_ring_segment_table_entries);
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
