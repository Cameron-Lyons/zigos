const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const native_util = @import("../core/util.zig");
const storage_driver_protocol = @import("../drivers/storage_driver_protocol.zig");

const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn inb(_: u16) u8 {
            native_util.impossibleByInvariant("host device broker cannot perform x86 port input");
        }

        pub fn inw(_: u16) u16 {
            native_util.impossibleByInvariant("host device broker cannot perform x86 port input");
        }

        pub fn inl(_: u16) u32 {
            native_util.impossibleByInvariant("host device broker cannot perform x86 port input");
        }

        pub fn outb(_: u16, _: u8) void {}

        pub fn outw(_: u16, _: u16) void {}

        pub fn outl(_: u16, _: u32) void {}
    };

pub const MAX_DEVICES: usize = 4;
const ata_io_register_count = 8;
const ata_control_register_index = ata_io_register_count;
const ata_host_register_count = ata_io_register_count + 1;
const ata_sector_size = 512;
const ata_reg_data: usize = 0;
const ata_reg_seccount: usize = 2;
const ata_reg_lba0: usize = 3;
const ata_reg_lba1: usize = 4;
const ata_reg_lba2: usize = 5;
const ata_reg_drive: usize = 6;
const ata_reg_status: usize = 7;
const ata_reg_command: usize = 7;
const ata_cmd_read_sectors: u32 = 0x20;
const ata_cmd_write_sectors: u32 = 0x30;
const ata_cmd_cache_flush: u32 = 0xE7;
const ata_sr_drdy: u32 = 0x40;
const ata_sr_drq: u32 = 0x08;
const ata_sr_err: u32 = 0x01;
const ata_lba_byte_mask: u32 = 0xFF;
const ata_lba_drive_head_mask: u32 = 0x0F;
const ata_lba1_shift: u6 = 8;
const ata_lba2_shift: u6 = 16;
const ata_lba3_shift: u6 = 24;
const ata_sector_count_zero_value: u16 = 256;
const host_storage_sectors: usize = if (builtin.target.os.tag == .freestanding) 1 else 8192;
const host_storage_bytes = host_storage_sectors * ata_sector_size;

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
    const TransferKind = enum(u8) {
        none,
        read,
        write,
    };

    in_use: bool = false,
    device_id: u64 = 0,
    grant: storage_driver_protocol.AtaBrokerGrant = .{
        .base_port = 0,
        .ctrl_port = 0,
        .is_master = false,
        .irq_line = 0,
        .sector_count = 0,
    },
    host_registers: [ata_host_register_count]u32 = [_]u32{0} ** ata_host_register_count,
    host_storage: [host_storage_bytes]u8 = [_]u8{0} ** host_storage_bytes,
    transfer_kind: TransferKind = .none,
    transfer_lba: u64 = 0,
    transfer_sector_count: u16 = 0,
    transfer_byte_offset: usize = 0,
};

var controllers: [MAX_DEVICES]ControllerSlot = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES;

pub fn reset() void {
    controllers = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES;
}

pub fn publishAtaController(device_id: u64, grant: storage_driver_protocol.AtaBrokerGrant) bool {
    if (device_id == 0) return false;
    if (findController(device_id)) |slot| {
        slot.grant = grant;
        finishHostTransfer(slot);
        return true;
    }
    for (&controllers) |*slot| {
        if (slot.in_use) continue;
        slot.in_use = true;
        slot.device_id = device_id;
        slot.grant = grant;
        slot.host_registers = [_]u32{0} ** slot.host_registers.len;
        finishHostTransfer(slot);
        return true;
    }
    return false;
}

pub fn describe(device_id: u64) Error!ControllerDescriptor {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    return .{
        .device_id = device_id,
        .base_port = slot.grant.base_port,
        .io_port_count = ata_io_register_count,
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
    return readHostRegister(slot, register_index, width);
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

    writeHostRegister(slot, register_index, width, value);
}

fn findController(device_id: u64) ?*ControllerSlot {
    for (&controllers) |*slot| {
        if (slot.in_use and slot.device_id == device_id) return slot;
    }
    return null;
}

fn registerIndex(slot: *const ControllerSlot, port: u16) Error!usize {
    if (port >= slot.grant.base_port and port < slot.grant.base_port + ata_io_register_count) {
        return port - slot.grant.base_port;
    }
    if (port == slot.grant.ctrl_port) return ata_control_register_index;
    return error.InvalidPort;
}

fn readHostRegister(slot: *ControllerSlot, register_index: usize, width: PortWidth) u32 {
    if (register_index == ata_reg_data and slot.transfer_kind == .read) {
        return readHostTransferData(slot, width);
    }
    if (register_index == ata_control_register_index) {
        return truncateRegisterValue(slot.host_registers[ata_reg_status], width);
    }
    return truncateRegisterValue(slot.host_registers[register_index], width);
}

fn writeHostRegister(slot: *ControllerSlot, register_index: usize, width: PortWidth, value: u32) void {
    if (register_index == ata_reg_data and slot.transfer_kind == .write) {
        writeHostTransferData(slot, width, value);
        return;
    }

    const stored_value = truncateRegisterValue(value, width);
    slot.host_registers[register_index] = stored_value;
    if (register_index != ata_reg_command) return;

    switch (stored_value) {
        ata_cmd_read_sectors => startHostTransfer(slot, .read),
        ata_cmd_write_sectors => startHostTransfer(slot, .write),
        ata_cmd_cache_flush => finishHostTransfer(slot),
        else => {},
    }
}

fn startHostTransfer(slot: *ControllerSlot, transfer_kind: ControllerSlot.TransferKind) void {
    const count_register = @as(u16, @truncate(slot.host_registers[ata_reg_seccount]));
    const sector_count = normalizeAtaSectorCount(count_register);
    const lba = lba28FromRegisters(slot);

    if (!hostTransferInRange(slot, lba, sector_count)) {
        slot.transfer_kind = .none;
        slot.host_registers[ata_reg_status] = ata_sr_drdy | ata_sr_err;
        return;
    }

    slot.transfer_kind = transfer_kind;
    slot.transfer_lba = lba;
    slot.transfer_sector_count = sector_count;
    slot.transfer_byte_offset = 0;
    slot.host_registers[ata_reg_status] = ata_sr_drdy | ata_sr_drq;
}

fn truncateRegisterValue(value: u32, width: PortWidth) u32 {
    return switch (width) {
        .u8 => @as(u8, @truncate(value)),
        .u16 => @as(u16, @truncate(value)),
        .u32 => value,
    };
}

fn normalizeAtaSectorCount(count_register: u16) u16 {
    return if (count_register == 0) ata_sector_count_zero_value else count_register;
}

fn lba28FromRegisters(slot: *const ControllerSlot) u64 {
    return (@as(u64, slot.host_registers[ata_reg_lba0] & ata_lba_byte_mask)) |
        (@as(u64, slot.host_registers[ata_reg_lba1] & ata_lba_byte_mask) << ata_lba1_shift) |
        (@as(u64, slot.host_registers[ata_reg_lba2] & ata_lba_byte_mask) << ata_lba2_shift) |
        (@as(u64, slot.host_registers[ata_reg_drive] & ata_lba_drive_head_mask) << ata_lba3_shift);
}

fn finishHostTransfer(slot: *ControllerSlot) void {
    slot.transfer_kind = .none;
    slot.transfer_lba = 0;
    slot.transfer_sector_count = 0;
    slot.transfer_byte_offset = 0;
    slot.host_registers[ata_reg_status] = ata_sr_drdy;
}

fn readHostTransferData(slot: *ControllerSlot, width: PortWidth) u32 {
    const offset = hostTransferOffset(slot);
    const value = switch (width) {
        .u8 => @as(u32, slot.host_storage[offset]),
        .u16 => @as(u32, std.mem.readInt(u16, slot.host_storage[offset..][0..2], .little)),
        .u32 => std.mem.readInt(u32, slot.host_storage[offset..][0..4], .little),
    };
    advanceHostTransfer(slot, widthByteCount(width));
    return value;
}

fn writeHostTransferData(slot: *ControllerSlot, width: PortWidth, value: u32) void {
    const offset = hostTransferOffset(slot);
    switch (width) {
        .u8 => slot.host_storage[offset] = @truncate(value),
        .u16 => std.mem.writeInt(u16, slot.host_storage[offset..][0..2], @truncate(value), .little),
        .u32 => std.mem.writeInt(u32, slot.host_storage[offset..][0..4], value, .little),
    }
    advanceHostTransfer(slot, widthByteCount(width));
}

fn advanceHostTransfer(slot: *ControllerSlot, byte_count: usize) void {
    slot.transfer_byte_offset += byte_count;
    if (slot.transfer_byte_offset >= @as(usize, slot.transfer_sector_count) * ata_sector_size) {
        finishHostTransfer(slot);
    }
}

fn hostTransferOffset(slot: *const ControllerSlot) usize {
    return @as(usize, @intCast(slot.transfer_lba)) * ata_sector_size + slot.transfer_byte_offset;
}

fn hostTransferInRange(slot: *const ControllerSlot, lba: u64, sector_count: u16) bool {
    if (sector_count == 0) return false;
    const available_sectors = @min(slot.grant.sector_count, host_storage_sectors);
    return lba < available_sectors and @as(u64, sector_count) <= available_sectors - lba;
}

fn widthByteCount(width: PortWidth) usize {
    return switch (width) {
        .u8 => 1,
        .u16 => 2,
        .u32 => 4,
    };
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
    try std.testing.expectEqual(@as(u16, ata_io_register_count), descriptor.io_port_count);
    try std.testing.expectEqual(@as(u16, 0x3F6), descriptor.ctrl_port);
    try std.testing.expect(descriptor.is_master);
    try std.testing.expectEqual(@as(u8, 14), descriptor.irq_line);
    try std.testing.expectEqual(@as(u64, 4096), descriptor.sector_count);

    try writePort(0x1F001, 0x1F0 + ata_io_register_count - 1, .u8, 0x5A);
    try std.testing.expectEqual(@as(u32, 0x5A), try readPort(0x1F001, 0x1F0 + ata_io_register_count - 1, .u8));
    try std.testing.expectEqual(@as(u8, 14), try irqLine(0x1F001));
    try std.testing.expectError(error.UnsupportedMmioWindow, mmioWindow(0x1F001, 0));
    try std.testing.expectError(error.InvalidPort, readPort(0x1F001, 0x2F8, .u8));
}
