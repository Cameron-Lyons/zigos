//! xHCI TRB encoding: event decoding, the command ring producer, command
//! and control-transfer TRBs and transfer-event validation.

const std = @import("std");
const xhci = @import("../xhci.zig");

const ENDPOINT_ZERO_DCI = xhci.ENDPOINT_ZERO_DCI;
const Error = xhci.Error;
const HID_BOOT_KEYBOARD_REPORT_BYTES = xhci.HID_BOOT_KEYBOARD_REPORT_BYTES;
const RING_ALIGNMENT_BYTES = xhci.RING_ALIGNMENT_BYTES;
const RingPlan = xhci.RingPlan;
const TEST_DOORBELL_OFFSET = xhci.TEST_DOORBELL_OFFSET;
const TRANSFER_RING_TRBS = xhci.TRANSFER_RING_TRBS;
const TRB_BYTES = xhci.TRB_BYTES;
const USB_DESCRIPTOR_CONFIGURATION = xhci.USB_DESCRIPTOR_CONFIGURATION;
const USB_DESCRIPTOR_DEVICE = xhci.USB_DESCRIPTOR_DEVICE;
const USB_DEVICE_DESCRIPTOR_PREFIX_BYTES = xhci.USB_DEVICE_DESCRIPTOR_PREFIX_BYTES;
const USB_ENUMERATION_BUFFER_BYTES = xhci.USB_ENUMERATION_BUFFER_BYTES;
const USB_REQUEST_SET_CONFIGURATION = xhci.USB_REQUEST_SET_CONFIGURATION;
const USB_REQUEST_SET_PROTOCOL = xhci.USB_REQUEST_SET_PROTOCOL;
const XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES = xhci.XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES;
const aligned = xhci.aligned;
const defaultCapabilityRegisters = xhci.defaultCapabilityRegisters;
const ringCommandDoorbell = xhci.controller.ringCommandDoorbell;
const ringDeviceDoorbell = xhci.controller.ringDeviceDoorbell;

pub const COMMAND_RING_INITIAL_CYCLE_STATE: u64 = 1;
const NORMAL_TRB_TYPE: u32 = 1;
pub const LINK_TRB_TYPE: u32 = 6;
pub const LINK_TRB_TOGGLE_CYCLE: u32 = 1 << 1;
const SETUP_STAGE_TRB_TYPE: u32 = 2;
const DATA_STAGE_TRB_TYPE: u32 = 3;
const STATUS_STAGE_TRB_TYPE: u32 = 4;
const ENABLE_SLOT_COMMAND_TRB_TYPE: u32 = 9;
const DISABLE_SLOT_COMMAND_TRB_TYPE: u32 = 10;
pub const ADDRESS_DEVICE_COMMAND_TRB_TYPE: u32 = 11;
pub const CONFIGURE_ENDPOINT_COMMAND_TRB_TYPE: u32 = 12;
pub const EVALUATE_CONTEXT_COMMAND_TRB_TYPE: u32 = 13;
const RESET_ENDPOINT_COMMAND_TRB_TYPE: u32 = 14;
const STOP_ENDPOINT_COMMAND_TRB_TYPE: u32 = 15;
pub const TRB_TYPE_SHIFT: u5 = 10;
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
const USB_SETUP_PACKET_BYTES: u32 = 8;
const USB_REQUEST_TYPE_CLASS_INTERFACE_OUT: u8 = 0x21;
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

pub const EndpointState = enum(u3) {
    disabled = 0,
    running = 1,
    halted = 2,
    stopped = 3,
    error_state = 4,
};

pub fn decodeEndpointState(dword0: u32) Error!EndpointState {
    return switch (@as(u3, @truncate(dword0))) {
        0 => .disabled,
        1 => .running,
        2 => .halted,
        3 => .stopped,
        4 => .error_state,
        else => error.EndpointContextStateInvalid,
    };
}

pub const StoppedTransferCompletion = enum {
    stopped,
    stopped_length_invalid,
    stopped_short_packet,
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

    pub fn stoppedCompletion(self: Event) ?StoppedTransferCompletion {
        if (self.kind != .transfer) return null;
        return switch (self.completion_code) {
            26 => .stopped,
            27 => .stopped_length_invalid,
            28 => .stopped_short_packet,
            else => null,
        };
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

pub const CommandKind = enum(u8) {
    enable_slot,
    disable_slot,
    address_device,
    configure_endpoint,
    evaluate_context,
    reset_endpoint,
    stop_endpoint,
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

pub fn stopEndpointCommand(
    slot_id: u8,
    endpoint_dci: u5,
    suspend_endpoint: bool,
    cycle_state: u1,
) Error![4]u32 {
    if (slot_id == 0) return error.InvalidDeviceSlot;
    if (endpoint_dci == 0) return error.EndpointMismatch;
    // xHCI 1.2c section 6.4.3.8: SP denotes an impending >= 10 ms suspend.
    return .{
        0,
        0,
        0,
        (@as(u32, slot_id) << 24) |
            (@as(u32, @intFromBool(suspend_endpoint)) << 23) |
            (@as(u32, endpoint_dci) << 16) |
            (STOP_ENDPOINT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            cycle_state,
    };
}

pub fn resetEndpointCommand(
    slot_id: u8,
    endpoint_dci: u5,
    preserve_transfer_state: bool,
    cycle_state: u1,
) Error![4]u32 {
    if (slot_id == 0) return error.InvalidDeviceSlot;
    if (endpoint_dci == 0) return error.EndpointMismatch;
    return .{
        0,
        0,
        0,
        (@as(u32, slot_id) << 24) |
            (@as(u32, endpoint_dci) << 16) |
            (RESET_ENDPOINT_COMMAND_TRB_TYPE << TRB_TYPE_SHIFT) |
            (@as(u32, @intFromBool(preserve_transfer_state)) << 9) |
            cycle_state,
    };
}

pub fn ringLinkControl(cycle_state: u1) u32 {
    return (LINK_TRB_TYPE << TRB_TYPE_SHIFT) | LINK_TRB_TOGGLE_CYCLE | cycle_state;
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

pub fn setBootProtocolSetupStage(interface_number: u8, cycle_state: u1) [4]u32 {
    return .{
        @as(u32, USB_REQUEST_TYPE_CLASS_INTERFACE_OUT) |
            (@as(u32, USB_REQUEST_SET_PROTOCOL) << 8),
        interface_number,
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

pub fn interruptInTransfer(
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
        (NORMAL_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_SHORT_PACKET |
            TRB_INTERRUPT_ON_COMPLETION |
            cycle_state,
    };
}

pub fn validateInterruptTransferEvent(
    event: Event,
    trb_address: u64,
    slot_id: u8,
    endpoint_dci: u5,
) Error!void {
    if (event.kind != .transfer or !event.succeeded() or trb_address == 0 or
        event.parameter != trb_address or slot_id == 0 or event.slot_id != slot_id or
        endpoint_dci == 0 or endpoint_dci == ENDPOINT_ZERO_DCI or
        event.endpoint_id != endpoint_dci or
        event.event_data or event.transfer_length != 0)
    {
        return error.TrbRingStateInvalid;
    }
}

pub fn validateFailedTransferEvent(
    event: Event,
    owned_trb_addresses: []const u64,
    slot_id: u8,
    endpoint_dci: u5,
) Error!void {
    if (event.kind != .transfer or event.completion_code != 4 or event.event_data or
        slot_id == 0 or event.slot_id != slot_id or endpoint_dci == 0 or
        event.endpoint_id != endpoint_dci or owned_trb_addresses.len == 0 or
        owned_trb_addresses.len > 3 or event.transfer_length > XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES)
    {
        return error.TrbRingStateInvalid;
    }
    // Current control requests own separate Setup/[Data]/Status TDs; interrupt
    // requests own one Normal TRB. A failure must name the active request, unlike
    // a forced stopped event which can name the empty ring's Link TRB.
    var matched = false;
    for (owned_trb_addresses, 0..) |address, index| {
        if (address == 0 or !aligned(address, TRB_BYTES)) return error.TrbRingStateInvalid;
        _ = std.math.add(u64, address, TRB_BYTES) catch return error.TrbRingStateInvalid;
        for (owned_trb_addresses[0..index]) |previous| {
            if (address == previous) return error.TrbRingStateInvalid;
        }
        matched = matched or event.parameter == address;
    }
    if (!matched) return error.TrbRingStateInvalid;
}

pub fn validateStoppedTransferEvent(
    event: Event,
    ring_address: u64,
    ring_trbs: u32,
    slot_id: u8,
    endpoint_dci: u5,
) Error!StoppedTransferCompletion {
    const completion = event.stoppedCompletion() orelse return error.TrbRingStateInvalid;
    if (ring_address == 0 or !aligned(ring_address, RING_ALIGNMENT_BYTES) or
        ring_trbs < 2 or slot_id == 0 or event.slot_id != slot_id or
        endpoint_dci == 0 or event.endpoint_id != endpoint_dci or event.event_data or
        !aligned(event.parameter, TRB_BYTES))
    {
        return error.TrbRingStateInvalid;
    }
    const ring_bytes = std.math.mul(u64, ring_trbs, TRB_BYTES) catch
        return error.TrbRingStateInvalid;
    const ring_end = std.math.add(u64, ring_address, ring_bytes) catch
        return error.TrbRingStateInvalid;
    if (event.parameter < ring_address or event.parameter >= ring_end) {
        return error.TrbRingStateInvalid;
    }
    // Stops may identify any interrupted TRB, including the Link TRB on an empty
    // ring. Code 26 carries a residual; code 27's length is invalid and code 28
    // reports EDTLA bytes transferred rather than that residual (tables 6-38/90).
    if (completion == .stopped and event.transfer_length > XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES) {
        return error.TrbRingStateInvalid;
    }
    return completion;
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

test "xHCI Stop Endpoint command uses protocol fields and validates identifiers" {
    const stopped = try stopEndpointCommand(1, ENDPOINT_ZERO_DCI, false, 1);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0x0101_3C01 }, stopped);
    const suspended = try stopEndpointCommand(255, 31, true, 0);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0xFF9F_3C00 }, suspended);
    try std.testing.expectEqual(
        @as(u32, 1) << 23,
        (try stopEndpointCommand(7, 5, true, 1))[3] ^
            (try stopEndpointCommand(7, 5, false, 1))[3],
    );
    try std.testing.expectError(error.InvalidDeviceSlot, stopEndpointCommand(0, 1, false, 1));
    try std.testing.expectError(error.EndpointMismatch, stopEndpointCommand(1, 0, false, 1));
}

test "xHCI Reset Endpoint command preserves transfer state with protocol bit 9" {
    const reset = try resetEndpointCommand(1, ENDPOINT_ZERO_DCI, true, 1);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0x0101_3A01 }, reset);
    const maximum = try resetEndpointCommand(255, 31, false, 0);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0xFF1F_3800 }, maximum);
    try std.testing.expectEqual(
        @as(u32, 1) << 9,
        (try resetEndpointCommand(7, 5, true, 1))[3] ^
            (try resetEndpointCommand(7, 5, false, 1))[3],
    );
    try std.testing.expectError(error.InvalidDeviceSlot, resetEndpointCommand(0, 1, true, 1));
    try std.testing.expectError(error.EndpointMismatch, resetEndpointCommand(1, 0, true, 1));
}

test "xHCI failed transaction belongs to the exact active control or interrupt request" {
    const control_td = [_]u64{ 0x530E0, 0x53000, 0x53010 };
    var event = decodeEvent(.{ 0x530E0, 0, 4 << 24, (3 << 24) | (1 << 16) | (32 << 10) });
    for (control_td) |address| {
        event.parameter = address;
        try validateFailedTransferEvent(event, &control_td, 3, 1);
    }
    // A two-stage no-data control request excludes a neighboring Data TRB.
    try validateFailedTransferEvent(event, &.{ 0x530E0, 0x53010 }, 3, 1);
    event.parameter = 0x53000;
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{ 0x530E0, 0x53010 }, 3, 1));
    event.endpoint_id = 3;
    event.transfer_length = 8;
    try validateFailedTransferEvent(event, &.{0x53000}, 3, 3);
    event.transfer_length = 65536;
    try validateFailedTransferEvent(event, &.{0x53000}, 3, 3);
    event.transfer_length = 65537;
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{0x53000}, 3, 3));
    event.transfer_length = 0;
    try std.testing.expectError(error.TrbRingStateInvalid, validateInterruptTransferEvent(event, 0x53000, 3, 3));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, 16, 3, 3));
}

test "xHCI failed transaction rejects foreign malformed and inactive TRBs" {
    const event = decodeEvent(.{ 0x53000, 0, 4 << 24, (3 << 24) | (1 << 16) | (32 << 10) });
    var mismatch = event;
    mismatch.kind = .command_completion;
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(mismatch, &.{0x53000}, 3, 1));
    for ([_]u8{ 0, 1, 5, 6, 26, 27, 28 }) |code| {
        mismatch = event;
        mismatch.completion_code = code;
        try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(mismatch, &.{0x53000}, 3, 1));
    }
    mismatch = event;
    mismatch.event_data = true;
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(mismatch, &.{0x53000}, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{0x53000}, 0, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{0x53000}, 4, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{0x53000}, 3, 0));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{0x53000}, 3, 2));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{}, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{ 0x53000, 0x53010, 0x53020, 0x53030 }, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{ 0x53000, 0 }, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{ 0x53000, 0x53001 }, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{ 0x53000, 0x53000 }, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(event, &.{ 0x53000, std.math.maxInt(u64) - 15 }, 3, 1));
    // Both an older TD in the same ring and the terminal Link are unowned.
    for ([_]u64{ 0, 0x53001, 0x52FF0, 0x53020, 0x530F0 }) |pointer| {
        mismatch = event;
        mismatch.parameter = pointer;
        try std.testing.expectError(error.TrbRingStateInvalid, validateFailedTransferEvent(mismatch, &.{0x53000}, 3, 1));
    }
}

test "xHCI output endpoint state rejects reserved protocol values" {
    const states = [_]EndpointState{ .disabled, .running, .halted, .stopped, .error_state };
    for (states, 0..) |state, value| {
        try std.testing.expectEqual(state, try decodeEndpointState(@intCast(value)));
        try std.testing.expectEqual(state, try decodeEndpointState(0xFFFF_FFF8 | @as(u32, @intCast(value))));
    }
    for (5..8) |reserved| {
        try std.testing.expectError(error.EndpointContextStateInvalid, decodeEndpointState(@intCast(reserved)));
    }
}

test "xHCI stopped transfer completion validates every owned TRB and length semantics" {
    var event = decodeEvent(.{ 0x53000, 0, 26 << 24, (3 << 24) | (1 << 16) | (32 << 10) });
    const completions = [_]StoppedTransferCompletion{ .stopped, .stopped_length_invalid, .stopped_short_packet };
    for (completions, 26..) |completion, code| {
        event.completion_code = @intCast(code);
        try std.testing.expectEqual(completion, event.stoppedCompletion().?);
        // Includes Setup/Data/Status/Normal positions and the terminal Link TRB.
        for (0..TRANSFER_RING_TRBS) |index| {
            event.parameter = 0x53000 + index * TRB_BYTES;
            try std.testing.expectEqual(
                completion,
                try validateStoppedTransferEvent(event, 0x53000, TRANSFER_RING_TRBS, 3, 1),
            );
        }
    }
    event.parameter = 0x53000;
    event.completion_code = 26;
    event.transfer_length = 65536;
    try std.testing.expectEqual(.stopped, try validateStoppedTransferEvent(event, 0x53000, TRANSFER_RING_TRBS, 3, 1));
    event.transfer_length = 65537;
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, TRANSFER_RING_TRBS, 3, 1));
    event.transfer_length = std.math.maxInt(u24);
    event.completion_code = 27;
    try std.testing.expectEqual(.stopped_length_invalid, try validateStoppedTransferEvent(event, 0x53000, TRANSFER_RING_TRBS, 3, 1));
    event.completion_code = 28;
    try std.testing.expectEqual(.stopped_short_packet, try validateStoppedTransferEvent(event, 0x53000, TRANSFER_RING_TRBS, 3, 1));
    // Stopped completion never satisfies an ordinary successful report TD.
    event.endpoint_id = 3;
    event.transfer_length = 0;
    try std.testing.expectError(error.TrbRingStateInvalid, validateInterruptTransferEvent(event, 0x53000, 3, 3));
}

test "xHCI stopped transfer completion rejects foreign events and invalid ring geometry" {
    const event = decodeEvent(.{ 0x53000, 0, 27 << 24, (3 << 24) | (1 << 16) | (32 << 10) });
    var mismatch = event;
    mismatch.kind = .command_completion;
    try std.testing.expectEqual(@as(?StoppedTransferCompletion, null), mismatch.stoppedCompletion());
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(mismatch, 0x53000, 16, 3, 1));
    mismatch = event;
    mismatch.completion_code = 1;
    try std.testing.expectEqual(@as(?StoppedTransferCompletion, null), mismatch.stoppedCompletion());
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(mismatch, 0x53000, 16, 3, 1));
    mismatch = event;
    mismatch.event_data = true;
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(mismatch, 0x53000, 16, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, 16, 0, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, 16, 4, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, 16, 3, 0));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, 16, 3, 2));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0, 16, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53001, 16, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, 0x53000, 1, 3, 1));
    try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(event, std.math.maxInt(u64) - 63, 16, 3, 1));
    for ([_]u64{ 0x52FF0, 0x53001, 0x53100 }) |pointer| {
        mismatch = event;
        mismatch.parameter = pointer;
        try std.testing.expectError(error.TrbRingStateInvalid, validateStoppedTransferEvent(mismatch, 0x53000, 16, 3, 1));
    }
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

test "xHCI HID boot protocol request is interface scoped and has no data stage" {
    const setup = setBootProtocolSetupStage(7, 1);
    try std.testing.expectEqual(@as(u32, 0x0000_0B21), setup[0]);
    try std.testing.expectEqual(@as(u32, 7), setup[1]);
    try std.testing.expectEqual(USB_SETUP_PACKET_BYTES, setup[2]);
    try std.testing.expectEqual(
        (SETUP_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_IMMEDIATE_DATA |
            1,
        setup[3],
    );

    const maximum_interface = setBootProtocolSetupStage(std.math.maxInt(u8), 0);
    try std.testing.expectEqual(@as(u32, std.math.maxInt(u8)), maximum_interface[1]);
    try std.testing.expectEqual(
        (SETUP_STAGE_TRB_TYPE << TRB_TYPE_SHIFT) | TRB_IMMEDIATE_DATA,
        maximum_interface[3],
    );
}

test "xHCI interrupt-IN transfer and completion are bound to one report TD" {
    const transfer = try interruptInTransfer(0x12_3456_7800, HID_BOOT_KEYBOARD_REPORT_BYTES, 1);
    try std.testing.expectEqual(@as(u32, 0x3456_7800), transfer[0]);
    try std.testing.expectEqual(@as(u32, 0x12), transfer[1]);
    try std.testing.expectEqual(@as(u32, HID_BOOT_KEYBOARD_REPORT_BYTES), transfer[2]);
    try std.testing.expectEqual(
        (NORMAL_TRB_TYPE << TRB_TYPE_SHIFT) |
            TRB_INTERRUPT_ON_SHORT_PACKET |
            TRB_INTERRUPT_ON_COMPLETION |
            1,
        transfer[3],
    );
    try std.testing.expectError(error.DmaAddressOutsidePlan, interruptInTransfer(0, 8, 1));
    try std.testing.expectError(
        error.DmaAddressOutsidePlan,
        interruptInTransfer(XHCI_TRANSFER_BUFFER_BOUNDARY_BYTES - 1, 2, 1),
    );

    const event = Event{
        .parameter = 0x53000,
        .kind = .transfer,
        .type_id = EVENT_TRB_TRANSFER,
        .transfer_length = 0,
        .completion_code = COMPLETION_CODE_SUCCESS,
        .port_id = 0,
        .slot_id = 3,
        .endpoint_id = 3,
        .event_data = false,
    };
    try validateInterruptTransferEvent(event, 0x53000, 3, 3);
    var mismatch = event;
    mismatch.endpoint_id = ENDPOINT_ZERO_DCI;
    try std.testing.expectError(
        error.TrbRingStateInvalid,
        validateInterruptTransferEvent(mismatch, 0x53000, 3, 3),
    );
    mismatch = event;
    mismatch.transfer_length = 1;
    try std.testing.expectError(
        error.TrbRingStateInvalid,
        validateInterruptTransferEvent(mismatch, 0x53000, 3, 3),
    );
    mismatch = event;
    mismatch.parameter += TRB_BYTES;
    try std.testing.expectError(
        error.TrbRingStateInvalid,
        validateInterruptTransferEvent(mismatch, 0x53000, 3, 3),
    );
}
