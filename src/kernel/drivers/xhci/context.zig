//! xHCI input contexts for Address Device, Evaluate Context and Configure
//! Endpoint commands.

const std = @import("std");
const xhci = @import("../xhci.zig");

const ADDRESS_DEVICE_COMMAND_TRB_TYPE = xhci.trb.ADDRESS_DEVICE_COMMAND_TRB_TYPE;
const CONFIGURE_ENDPOINT_COMMAND_TRB_TYPE = xhci.trb.CONFIGURE_ENDPOINT_COMMAND_TRB_TYPE;
const ContextSize = xhci.ContextSize;
const EVALUATE_CONTEXT_COMMAND_TRB_TYPE = xhci.trb.EVALUATE_CONTEXT_COMMAND_TRB_TYPE;
const Error = xhci.Error;
const HID_BOOT_KEYBOARD_REPORT_BYTES = xhci.HID_BOOT_KEYBOARD_REPORT_BYTES;
const INPUT_CONTEXT_ENTRIES = xhci.INPUT_CONTEXT_ENTRIES;
const RING_ALIGNMENT_BYTES = xhci.RING_ALIGNMENT_BYTES;
const TRB_TYPE_SHIFT = xhci.trb.TRB_TYPE_SHIFT;
const UsbBootKeyboardConfiguration = xhci.descriptors.UsbBootKeyboardConfiguration;
const addressDeviceCommand = xhci.trb.addressDeviceCommand;
const aligned = xhci.aligned;
const configureEndpointCommand = xhci.trb.configureEndpointCommand;
const evaluateContextCommand = xhci.trb.evaluateContextCommand;
const interruptInDeviceContextIndex = xhci.descriptors.interruptInDeviceContextIndex;

const ENDPOINT_TYPE_CONTROL: u32 = 4;
const ENDPOINT_TYPE_INTERRUPT_IN: u32 = 7;
const DEFAULT_ENDPOINT_ERROR_COUNT: u32 = 3;
const CONTROL_ENDPOINT_AVERAGE_TRB_LENGTH: u32 = 8;
const INTERRUPT_ENDPOINT_AVERAGE_TRB_LENGTH: u32 = 1024;
const ADDRESS_DEVICE_ADD_CONTEXT_FLAGS: u32 = 0b11;
const EVALUATE_ENDPOINT_ZERO_ADD_CONTEXT_FLAGS: u32 = 0b10;
const ADDRESS_DEVICE_CONTEXT_ENTRIES: u32 = 1;
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

    std.mem.writeInt(u32, input_context[4..8], ADDRESS_DEVICE_ADD_CONTEXT_FLAGS, .little);
    const slot_context = input_context[entry_bytes..][0..entry_bytes];
    std.mem.writeInt(u32, slot_context[0..4], (@as(u32, speed_id) << 20) | (ADDRESS_DEVICE_CONTEXT_ENTRIES << 27), .little);
    std.mem.writeInt(u32, slot_context[4..8], @as(u32, port_id) << 16, .little);

    const endpoint_context = input_context[2 * entry_bytes ..][0..entry_bytes];
    std.mem.writeInt(u32, endpoint_context[4..8], (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
        (ENDPOINT_TYPE_CONTROL << 3) |
        (@as(u32, max_packet_size) << 16), .little);
    std.mem.writeInt(u64, endpoint_context[8..16], control_transfer_ring_address | 1, .little);
    std.mem.writeInt(u32, endpoint_context[16..20], CONTROL_ENDPOINT_AVERAGE_TRB_LENGTH, .little);
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
    std.mem.writeInt(u32, input_context[4..8], EVALUATE_ENDPOINT_ZERO_ADD_CONTEXT_FLAGS, .little);
    const endpoint_context = input_context[2 * entry_bytes ..][0..entry_bytes];
    std.mem.writeInt(u32, endpoint_context[4..8], @as(u32, max_packet_size) << 16, .little);
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

    std.mem.writeInt(u32, input_context[4..8], (@as(u32, 1) << 0) | (@as(u32, 1) << keyboard.device_context_index), .little);
    const slot_context = input_context[entry_bytes..][0..entry_bytes];
    std.mem.writeInt(u32, slot_context[0..4], @as(u32, keyboard.device_context_index) << 27, .little);

    const endpoint_offset = (@as(usize, keyboard.device_context_index) + 1) * entry_bytes;
    const endpoint_context = input_context[endpoint_offset..][0..entry_bytes];
    std.mem.writeInt(u32, endpoint_context[0..4], @as(u32, keyboard.interval) << 16, .little);
    std.mem.writeInt(u32, endpoint_context[4..8], (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
        (ENDPOINT_TYPE_INTERRUPT_IN << 3) |
        (@as(u32, keyboard.max_burst_size) << 8) |
        (@as(u32, keyboard.max_packet_size) << 16), .little);
    std.mem.writeInt(u64, endpoint_context[8..16], interrupt_transfer_ring_address | 1, .little);
    std.mem.writeInt(u32, endpoint_context[16..20], INTERRUPT_ENDPOINT_AVERAGE_TRB_LENGTH |
        (@as(u32, keyboard.max_esit_payload) << 16), .little);
}

test "xHCI Address Device context encodes only slot and endpoint zero authority" {
    var input_context = @as([INPUT_CONTEXT_ENTRIES * 64]u8, @splat(0xA5));
    try initializeAddressDeviceInputContext(
        .bytes_64,
        7,
        4,
        512,
        0x8000,
        &input_context,
    );
    try std.testing.expectEqual(ADDRESS_DEVICE_ADD_CONTEXT_FLAGS, std.mem.readInt(u32, input_context[4..8], .little));
    const slot_offset: usize = 64;
    try std.testing.expectEqual(
        (@as(u32, 4) << 20) | (ADDRESS_DEVICE_CONTEXT_ENTRIES << 27),
        std.mem.readInt(u32, input_context[slot_offset..][0..4], .little),
    );
    try std.testing.expectEqual(@as(u32, 7) << 16, std.mem.readInt(u32, input_context[slot_offset + 4 ..][0..4], .little));
    const endpoint_offset: usize = 128;
    try std.testing.expectEqual(
        (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
            (ENDPOINT_TYPE_CONTROL << 3) |
            (@as(u32, 512) << 16),
        std.mem.readInt(u32, input_context[endpoint_offset + 4 ..][0..4], .little),
    );
    try std.testing.expectEqual(@as(u64, 0x8001), std.mem.readInt(u64, input_context[endpoint_offset + 8 ..][0..8], .little));
    try std.testing.expectEqual(
        CONTROL_ENDPOINT_AVERAGE_TRB_LENGTH,
        std.mem.readInt(u32, input_context[endpoint_offset + 16 ..][0..4], .little),
    );
    try std.testing.expectEqualSlices(
        u8,
        &(@as([64]u8, @splat(0))),
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

    var compact_context = @as([INPUT_CONTEXT_ENTRIES * 32]u8, @splat(0xA5));
    try initializeAddressDeviceInputContext(
        .bytes_32,
        2,
        3,
        64,
        0xA000,
        &compact_context,
    );
    try std.testing.expectEqual(ADDRESS_DEVICE_ADD_CONTEXT_FLAGS, std.mem.readInt(u32, compact_context[4..8], .little));
    try std.testing.expectEqual(
        (@as(u32, 3) << 20) | (ADDRESS_DEVICE_CONTEXT_ENTRIES << 27),
        std.mem.readInt(u32, compact_context[32..36], .little),
    );
    try std.testing.expectEqual(@as(u64, 0xA001), std.mem.readInt(u64, compact_context[72..80], .little));
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
    var input_context = @as([INPUT_CONTEXT_ENTRIES * 64]u8, @splat(0xA5));
    try initializeEvaluateEndpointZeroInputContext(.bytes_64, 32, &input_context);
    try std.testing.expectEqual(
        EVALUATE_ENDPOINT_ZERO_ADD_CONTEXT_FLAGS,
        std.mem.readInt(u32, input_context[4..8], .little),
    );
    try std.testing.expectEqual(@as(u32, 32) << 16, std.mem.readInt(u32, input_context[132..136], .little));
    try std.testing.expectEqualSlices(u8, &(@as([64]u8, @splat(0))), input_context[64..128]);
    try std.testing.expectEqualSlices(u8, &(@as([48]u8, @splat(0))), input_context[144..192]);

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
    var input_context = @as([INPUT_CONTEXT_ENTRIES * 64]u8, @splat(0xA5));
    try initializeConfigureInterruptInEndpointInputContext(
        .bytes_64,
        keyboard,
        0xA000,
        &input_context,
    );
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, input_context[0..4], .little));
    try std.testing.expectEqual(@as(u32, 0b1001), std.mem.readInt(u32, input_context[4..8], .little));
    try std.testing.expectEqual(
        @as(u32, keyboard.device_context_index) << 27,
        std.mem.readInt(u32, input_context[64..68], .little),
    );
    const endpoint_offset: usize = 4 * 64;
    try std.testing.expectEqual(
        @as(u32, keyboard.interval) << 16,
        std.mem.readInt(u32, input_context[endpoint_offset..][0..4], .little),
    );
    try std.testing.expectEqual(
        (DEFAULT_ENDPOINT_ERROR_COUNT << 1) |
            (ENDPOINT_TYPE_INTERRUPT_IN << 3) |
            (@as(u32, keyboard.max_packet_size) << 16),
        std.mem.readInt(u32, input_context[endpoint_offset + 4 ..][0..4], .little),
    );
    try std.testing.expectEqual(
        @as(u64, 0xA001),
        std.mem.readInt(u64, input_context[endpoint_offset + 8 ..][0..8], .little),
    );
    try std.testing.expectEqual(
        INTERRUPT_ENDPOINT_AVERAGE_TRB_LENGTH |
            (@as(u32, keyboard.max_esit_payload) << 16),
        std.mem.readInt(u32, input_context[endpoint_offset + 16 ..][0..4], .little),
    );
    try std.testing.expectEqualSlices(u8, &(@as([64]u8, @splat(0))), input_context[128..192]);

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
