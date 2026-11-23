//! USB device and configuration descriptor parsing and boot-keyboard
//! interface selection for xHCI enumeration.

const std = @import("std");
const xhci = @import("../xhci.zig");

const Error = xhci.Error;
const HID_BOOT_KEYBOARD_REPORT_BYTES = xhci.HID_BOOT_KEYBOARD_REPORT_BYTES;
const PortProtocol = xhci.PortProtocol;
const USB_CLASS_HID = xhci.USB_CLASS_HID;
const USB_CONFIGURATION_DESCRIPTOR_BYTES = xhci.USB_CONFIGURATION_DESCRIPTOR_BYTES;
const USB_DESCRIPTOR_CONFIGURATION = xhci.USB_DESCRIPTOR_CONFIGURATION;
const USB_DESCRIPTOR_DEVICE = xhci.USB_DESCRIPTOR_DEVICE;
const USB_DESCRIPTOR_ENDPOINT = xhci.USB_DESCRIPTOR_ENDPOINT;
const USB_DESCRIPTOR_HID = xhci.USB_DESCRIPTOR_HID;
const USB_DESCRIPTOR_INTERFACE = xhci.USB_DESCRIPTOR_INTERFACE;
const USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION = xhci.USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION;
const USB_DEVICE_DESCRIPTOR_BYTES = xhci.USB_DEVICE_DESCRIPTOR_BYTES;
const USB_DEVICE_DESCRIPTOR_PREFIX_BYTES = xhci.USB_DEVICE_DESCRIPTOR_PREFIX_BYTES;
const USB_ENDPOINT_DIRECTION_IN = xhci.USB_ENDPOINT_DIRECTION_IN;
const USB_ENDPOINT_TRANSFER_INTERRUPT = xhci.USB_ENDPOINT_TRANSFER_INTERRUPT;
const USB_HID_PROTOCOL_KEYBOARD = xhci.USB_HID_PROTOCOL_KEYBOARD;
const USB_HID_SUBCLASS_BOOT = xhci.USB_HID_SUBCLASS_BOOT;
const bootKeyboardConfigurationDescriptor = xhci.bootKeyboardConfigurationDescriptor;

const USB_DEVICE_DESCRIPTOR_MAX_PACKET_SIZE_OFFSET: usize = 7;
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
    interface_numbers: [4]u64 = @as([4]u64, @splat(0)),
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
                const packet_payload_bytes = std.mem.readInt(u16, descriptor[4..6], .little) & 0x07FF;
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
                        .raw_max_packet_size = std.mem.readInt(u16, descriptor[4..6], .little),
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
    const max_esit_payload = std.mem.readInt(u16, companion[4..6], .little);
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
    const usb_version_bcd = std.mem.readInt(u16, descriptor[2..4], .little);
    const device_class = descriptor[4];
    const device_subclass = descriptor[5];
    const device_version_bcd = std.mem.readInt(u16, descriptor[12..14], .little);
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
        .vendor_id = std.mem.readInt(u16, descriptor[8..10], .little),
        .product_id = std.mem.readInt(u16, descriptor[10..12], .little),
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
    const total_length = std.mem.readInt(u16, descriptor[2..4], .little);
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

/// Walk a configuration descriptor tree of `total_length` bytes. Each
/// descriptor is copied out of `source` before the parser sees it, so DMA
/// memory the device can still write is read once per byte.
pub fn walkConfigurationDescriptors(
    parser: *ConfigurationDescriptorParser,
    source: anytype,
    total_length: usize,
) Error!void {
    var storage: [std.math.maxInt(u8)]u8 = undefined;
    var offset: usize = 0;
    while (offset < total_length) {
        if (total_length - offset < 2) return error.InvalidUsbDescriptor;
        const descriptor_length: usize = source[offset];
        if (descriptor_length < 2 or descriptor_length > total_length - offset) {
            return error.InvalidUsbDescriptor;
        }
        for (storage[0..descriptor_length], 0..) |*byte, index| byte.* = source[offset + index];
        try parser.consume(storage[0..descriptor_length]);
        offset += descriptor_length;
    }
}

fn validBcd(value: u16) bool {
    return (value & 0x000F) <= 9 and
        ((value >> 4) & 0x000F) <= 9 and
        ((value >> 8) & 0x000F) <= 9 and
        ((value >> 12) & 0x000F) <= 9;
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
        18,   USB_DESCRIPTOR_DEVICE,
        0x10, 0x02,
        0,    0,
        0,    64,
        0x6B, 0x04,
        0x01, 0xC3,
        0x23, 0x01,
        1,    2,
        3,    2,
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
    var usb2_bytes = bootKeyboardConfigurationDescriptor(1);
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
        try testing.parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    const usb2_selection = try testing.parseUsbBootKeyboardConfiguration(usb2, 3, &usb2_bytes);
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
    const full_speed_selection = try testing.parseUsbBootKeyboardConfiguration(
        full_speed,
        2,
        &usb2_bytes,
    );
    try std.testing.expectEqual(@as(u8, 6), full_speed_selection.keyboard.interval);
    usb2_bytes[12] = 1;
    try std.testing.expectError(
        error.MissingBootKeyboardInterface,
        testing.parseUsbBootKeyboardConfiguration(usb2, 3, &usb2_bytes),
    );
    usb2_bytes[12] = 0;

    usb2_bytes[7] = 0;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        testing.parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
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
        testing.parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[4] = 1;
    usb2_bytes[13] = 2;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        testing.parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[13] = 1;
    usb2_bytes[29] = 0;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        testing.parseUsbConfigurationDescriptor(usb2, &usb2_bytes),
    );
    usb2_bytes[29] = USB_ENDPOINT_DIRECTION_IN | 1;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        testing.parseUsbConfigurationDescriptor(
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
        9, USB_DESCRIPTOR_CONFIGURATION, 31,                            0,                               1, 1,             0,                     0xA0,                      50,
        9, USB_DESCRIPTOR_INTERFACE,     0,                             0,                               1, USB_CLASS_HID, USB_HID_SUBCLASS_BOOT, USB_HID_PROTOCOL_KEYBOARD, 0,
        7, USB_DESCRIPTOR_ENDPOINT,      USB_ENDPOINT_DIRECTION_IN | 1, USB_ENDPOINT_TRANSFER_INTERRUPT, 8, 0,             10,                    6,                         USB_DESCRIPTOR_SUPERSPEED_ENDPOINT_COMPANION,
        0, 0,                            0,                             0,
    };
    const usb3_descriptor = try testing.parseUsbConfigurationDescriptor(usb3, &usb3_bytes);
    try std.testing.expectEqual(@as(u16, 31), usb3_descriptor.total_length);
    try std.testing.expect(usb3_descriptor.remote_wakeup);
    try std.testing.expectEqual(@as(u16, 400), usb3_descriptor.max_power_milliamps);
    usb3_bytes[29] = HID_BOOT_KEYBOARD_REPORT_BYTES;
    const usb3_selection = try testing.parseUsbBootKeyboardConfiguration(usb3, 4, &usb3_bytes);
    try std.testing.expectEqual(@as(u8, 9), usb3_selection.keyboard.interval);
    try std.testing.expectEqual(@as(u16, 8), usb3_selection.keyboard.max_esit_payload);
    usb3_bytes[28] = 1;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        testing.parseUsbBootKeyboardConfiguration(usb3, 4, &usb3_bytes),
    );
    usb3_bytes[28] = 0;
    usb3_bytes[26] = USB_DESCRIPTOR_HID;
    try std.testing.expectError(
        error.InvalidUsbDescriptor,
        testing.parseUsbConfigurationDescriptor(usb3, &usb3_bytes),
    );
}

pub const testing = struct {
    pub fn parseUsbConfigurationDescriptor(protocol: PortProtocol, descriptors: []const u8) Error!UsbConfigurationDescriptor {
        var parser = ConfigurationDescriptorParser.init(protocol);
        try walkConfigurationDescriptors(&parser, descriptors, descriptors.len);
        return parser.finish(descriptors.len);
    }

    pub fn parseUsbBootKeyboardConfiguration(
        protocol: PortProtocol,
        speed_id: u4,
        descriptors: []const u8,
    ) Error!UsbBootKeyboardSelection {
        var parser = ConfigurationDescriptorParser.initForPort(protocol, speed_id);
        try walkConfigurationDescriptors(&parser, descriptors, descriptors.len);
        return parser.finishBootKeyboard(descriptors.len);
    }
};
