const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const storage_driver_protocol = @import("../drivers/storage_driver_protocol.zig");

const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn inb(_: u16) u8 {
            unreachable;
        }

        pub fn inw(_: u16) u16 {
            unreachable;
        }

        pub fn inl(_: u16) u32 {
            unreachable;
        }

        pub fn outb(_: u16, _: u8) void {}

        pub fn outw(_: u16, _: u16) void {}

        pub fn outl(_: u16, _: u32) void {}
    };

pub const MAX_DEVICES: usize = 4;

pub const PortWidth = abi.DevicePortWidth;

pub const MmioWindow = struct {
    base: u64,
    length: u64,
    writable: bool = false,
    executable: bool = false,
};

pub const ControllerDescriptor = struct {
    device_id: u64,
    base_port: u16,
    io_port_count: u16,
    ctrl_port: u16,
    is_master: bool,
    irq_line: u8,
    mmio_window_count: u8,
    sector_count: u64,
};

pub const Error = error{
    DeviceNotFound,
    InvalidPort,
    UnsupportedMmioWindow,
    UnsupportedWidth,
};

const ControllerSlot = struct {
    in_use: bool = false,
    device_id: u64 = 0,
    grant: storage_driver_protocol.AtaBrokerGrant = .{
        .base_port = 0,
        .ctrl_port = 0,
        .is_master = false,
        .irq_line = 0,
        .sector_count = 0,
    },
    host_registers: [9]u32 = [_]u32{0} ** 9,
};

var controllers: [MAX_DEVICES]ControllerSlot = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES;

pub fn reset() void {
    controllers = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES;
}

pub fn publishAtaController(device_id: u64, grant: storage_driver_protocol.AtaBrokerGrant) bool {
    if (device_id == 0) return false;
    if (findController(device_id)) |slot| {
        slot.grant = grant;
        return true;
    }
    for (&controllers) |*slot| {
        if (slot.in_use) continue;
        slot.in_use = true;
        slot.device_id = device_id;
        slot.grant = grant;
        slot.host_registers = [_]u32{0} ** slot.host_registers.len;
        return true;
    }
    return false;
}

pub fn describe(device_id: u64) Error!ControllerDescriptor {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    return .{
        .device_id = device_id,
        .base_port = slot.grant.base_port,
        .io_port_count = 8,
        .ctrl_port = slot.grant.ctrl_port,
        .is_master = slot.grant.is_master,
        .irq_line = slot.grant.irq_line,
        .mmio_window_count = 0,
        .sector_count = slot.grant.sector_count,
    };
}

pub fn irqLine(device_id: u64) Error!u8 {
    return (try describe(device_id)).irq_line;
}

pub fn mmioWindow(device_id: u64, window_index: u8) Error!MmioWindow {
    _ = device_id;
    _ = window_index;
    return error.UnsupportedMmioWindow;
}

pub fn readPort(device_id: u64, port: u16, width: PortWidth) Error!u32 {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    const register_index = try registerIndex(slot, port);
    if (builtin.target.os.tag == .freestanding) {
        return switch (width) {
            .u8 => x86.inb(port),
            .u16 => x86.inw(port),
            .u32 => x86.inl(port),
        };
    }
    return switch (width) {
        .u8 => @truncate(slot.host_registers[register_index]),
        .u16 => @truncate(slot.host_registers[register_index]),
        .u32 => slot.host_registers[register_index],
    };
}

pub fn writePort(device_id: u64, port: u16, width: PortWidth, value: u32) Error!void {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    const register_index = try registerIndex(slot, port);
    if (builtin.target.os.tag == .freestanding) {
        switch (width) {
            .u8 => x86.outb(port, @truncate(value)),
            .u16 => x86.outw(port, @truncate(value)),
            .u32 => x86.outl(port, value),
        }
        return;
    }

    slot.host_registers[register_index] = switch (width) {
        .u8 => @truncate(value),
        .u16 => @truncate(value),
        .u32 => value,
    };
}

fn findController(device_id: u64) ?*ControllerSlot {
    for (&controllers) |*slot| {
        if (slot.in_use and slot.device_id == device_id) return slot;
    }
    return null;
}

fn registerIndex(slot: *const ControllerSlot, port: u16) Error!usize {
    if (port >= slot.grant.base_port and port < slot.grant.base_port + 8) {
        return port - slot.grant.base_port;
    }
    if (port == slot.grant.ctrl_port) return 8;
    return error.InvalidPort;
}

test "device broker publishes ATA controllers and exposes typed port and irq metadata" {
    reset();

    try std.testing.expect(publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 4096,
    }));

    const descriptor = try describe(0x1F001);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);
    try std.testing.expectEqual(@as(u16, 8), descriptor.io_port_count);
    try std.testing.expectEqual(@as(u16, 0x3F6), descriptor.ctrl_port);
    try std.testing.expect(descriptor.is_master);
    try std.testing.expectEqual(@as(u8, 14), descriptor.irq_line);
    try std.testing.expectEqual(@as(u64, 4096), descriptor.sector_count);

    try writePort(0x1F001, 0x1F0 + 7, .u8, 0x5A);
    try std.testing.expectEqual(@as(u32, 0x5A), try readPort(0x1F001, 0x1F0 + 7, .u8));
    try std.testing.expectEqual(@as(u8, 14), try irqLine(0x1F001));
    try std.testing.expectError(error.UnsupportedMmioWindow, mmioWindow(0x1F001, 0));
    try std.testing.expectError(error.InvalidPort, readPort(0x1F001, 0x2F8, .u8));
}
