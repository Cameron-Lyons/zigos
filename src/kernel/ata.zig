const std = @import("std");
const x86 = @import("../arch/x86.zig");
const vga = @import("vga.zig");
const error_handler = @import("error.zig");

const ATA_PRIMARY_BASE: u16 = 0x1F0;
const ATA_PRIMARY_CTRL: u16 = 0x3F6;
const ATA_SECONDARY_BASE: u16 = 0x170;
const ATA_SECONDARY_CTRL: u16 = 0x376;

const ATA_REG_DATA: u16 = 0;
const ATA_REG_ERROR: u16 = 1;
const ATA_REG_FEATURES: u16 = 1;
const ATA_REG_SECCOUNT: u16 = 2;
const ATA_REG_LBA0: u16 = 3;
const ATA_REG_LBA1: u16 = 4;
const ATA_REG_LBA2: u16 = 5;
const ATA_REG_DRIVE: u16 = 6;
const ATA_REG_STATUS: u16 = 7;
const ATA_REG_COMMAND: u16 = 7;

const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;

const ATA_SR_BSY: u8 = 0x80;
const ATA_SR_DRDY: u8 = 0x40;
const ATA_SR_DF: u8 = 0x20;
const ATA_SR_DSC: u8 = 0x10;
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_CORR: u8 = 0x04;
const ATA_SR_IDX: u8 = 0x02;
const ATA_SR_ERR: u8 = 0x01;

const ATA_ER_BBK: u8 = 0x80;
const ATA_ER_UNC: u8 = 0x40;
const ATA_ER_MC: u8 = 0x20;
const ATA_ER_IDNF: u8 = 0x10;
const ATA_ER_MCR: u8 = 0x08;
const ATA_ER_ABRT: u8 = 0x04;
const ATA_ER_TK0NF: u8 = 0x02;
const ATA_ER_AMNF: u8 = 0x01;

const ATA_MASTER: u8 = 0xA0;
const ATA_SLAVE: u8 = 0xB0;

pub const ATAError = error{
    Timeout,
    DriveError,
    NotFound,
    InvalidParameter,
    ReadError,
    WriteError,
};

pub const ATADevice = struct {
    present: bool,
    base_port: u16,
    ctrl_port: u16,
    is_master: bool,
    sectors: u64,
    model: [41]u8,
    serial: [21]u8,
    supports_lba: bool,
    supports_lba48: bool,
};

var primary_master: ATADevice = undefined;
var primary_slave: ATADevice = undefined;
var secondary_master: ATADevice = undefined;
var secondary_slave: ATADevice = undefined;

pub fn init() void {
    vga.print("  - Detecting ATA drives...\n");

    primary_master = ATADevice{
        .present = false,
        .base_port = ATA_PRIMARY_BASE,
        .ctrl_port = ATA_PRIMARY_CTRL,
        .is_master = true,
        .sectors = 0,
        .model = [_]u8{0} ** 41,
        .serial = [_]u8{0} ** 21,
        .supports_lba = false,
        .supports_lba48 = false,
    };
    detectDrive(&primary_master);

    primary_slave = ATADevice{
        .present = false,
        .base_port = ATA_PRIMARY_BASE,
        .ctrl_port = ATA_PRIMARY_CTRL,
        .is_master = false,
        .sectors = 0,
        .model = [_]u8{0} ** 41,
        .serial = [_]u8{0} ** 21,
        .supports_lba = false,
        .supports_lba48 = false,
    };
    detectDrive(&primary_slave);

    secondary_master = ATADevice{
        .present = false,
        .base_port = ATA_SECONDARY_BASE,
        .ctrl_port = ATA_SECONDARY_CTRL,
        .is_master = true,
        .sectors = 0,
        .model = [_]u8{0} ** 41,
        .serial = [_]u8{0} ** 21,
        .supports_lba = false,
        .supports_lba48 = false,
    };
    detectDrive(&secondary_master);

    secondary_slave = ATADevice{
        .present = false,
        .base_port = ATA_SECONDARY_BASE,
        .ctrl_port = ATA_SECONDARY_CTRL,
        .is_master = false,
        .sectors = 0,
        .model = [_]u8{0} ** 41,
        .serial = [_]u8{0} ** 21,
        .supports_lba = false,
        .supports_lba48 = false,
    };
    detectDrive(&secondary_slave);

    if (primary_master.present) {
        vga.print("    Primary Master: ");
        printDriveInfo(&primary_master);
    }
    if (primary_slave.present) {
        vga.print("    Primary Slave: ");
        printDriveInfo(&primary_slave);
    }
    if (secondary_master.present) {
        vga.print("    Secondary Master: ");
        printDriveInfo(&secondary_master);
    }
    if (secondary_slave.present) {
        vga.print("    Secondary Slave: ");
        printDriveInfo(&secondary_slave);
    }
}

fn detectDrive(device: *ATADevice) void {
    x86.outb(device.base_port + ATA_REG_DRIVE, if (device.is_master) ATA_MASTER else ATA_SLAVE);

    for (0..4) |_| {
        _ = x86.inb(device.ctrl_port);
    }

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

    const status = x86.inb(device.base_port + ATA_REG_STATUS);
    if (status == 0) {
        return;
    }

    while ((x86.inb(device.base_port + ATA_REG_STATUS) & ATA_SR_BSY) != 0) {}

    if (x86.inb(device.base_port + ATA_REG_LBA1) != 0 or
        x86.inb(device.base_port + ATA_REG_LBA2) != 0)
    {
        return;
    }

    while (true) {
        const stat = x86.inb(device.base_port + ATA_REG_STATUS);
        if ((stat & ATA_SR_ERR) != 0) {
            return;
        }
        if ((stat & ATA_SR_DRQ) != 0) {
            break;
        }
    }

    var buffer: [256]u16 = undefined;
    for (&buffer) |*word| {
        word.* = x86.inw(device.base_port + ATA_REG_DATA);
    }

    device.present = true;

    if ((buffer[49] & 0x200) != 0) {
        device.supports_lba = true;
    }

    if ((buffer[83] & 0x400) != 0) {
        device.supports_lba48 = true;
    }

    if (device.supports_lba48) {
        device.sectors = @as(u64, buffer[100]) |
            (@as(u64, buffer[101]) << 16) |
            (@as(u64, buffer[102]) << 32) |
            (@as(u64, buffer[103]) << 48);
    } else if (device.supports_lba) {
        device.sectors = @as(u64, buffer[60]) | (@as(u64, buffer[61]) << 16);
    }

    var model_idx: usize = 0;
    for (27..47) |i| {
        device.model[model_idx] = @as(u8, @intCast((buffer[i] >> 8) & 0xFF));
        model_idx += 1;
        device.model[model_idx] = @as(u8, @intCast(buffer[i] & 0xFF));
        model_idx += 1;
    }
    device.model[40] = 0;

    var serial_idx: usize = 0;
    for (10..20) |i| {
        device.serial[serial_idx] = @as(u8, @intCast((buffer[i] >> 8) & 0xFF));
        serial_idx += 1;
        device.serial[serial_idx] = @as(u8, @intCast(buffer[i] & 0xFF));
        serial_idx += 1;
    }
    device.serial[20] = 0;
}

pub fn readSectors(device: *const ATADevice, lba: u64, count: u8, buffer: []u8) ATAError!void {
    if (!device.present) {
        return ATAError.NotFound;
    }

    if (count == 0 or count > 128) {
        return ATAError.InvalidParameter;
    }

    if (buffer.len < @as(usize, count) * 512) {
        return ATAError.InvalidParameter;
    }

    try waitDriveReady(device);

    const drive_select: u8 = if (device.is_master) 0xE0 else 0xF0;
    x86.outb(device.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & 0x0F)));

    x86.outb(device.base_port + ATA_REG_SECCOUNT, count);

    x86.outb(device.base_port + ATA_REG_LBA0, @as(u8, @intCast(lba & 0xFF)));
    x86.outb(device.base_port + ATA_REG_LBA1, @as(u8, @intCast((lba >> 8) & 0xFF)));
    x86.outb(device.base_port + ATA_REG_LBA2, @as(u8, @intCast((lba >> 16) & 0xFF)));

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_READ_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(device);

        for (0..256) |_| {
            const word = x86.inw(device.base_port + ATA_REG_DATA);
            buffer[buffer_offset] = @as(u8, @intCast(word & 0xFF));
            buffer[buffer_offset + 1] = @as(u8, @intCast((word >> 8) & 0xFF));
            buffer_offset += 2;
        }
    }
}

pub fn writeSectors(device: *const ATADevice, lba: u64, count: u8, buffer: []const u8) ATAError!void {
    if (!device.present) {
        return ATAError.NotFound;
    }

    if (count == 0 or count > 128) {
        return ATAError.InvalidParameter;
    }

    if (buffer.len < @as(usize, count) * 512) {
        return ATAError.InvalidParameter;
    }

    try waitDriveReady(device);

    const drive_select: u8 = if (device.is_master) 0xE0 else 0xF0;
    x86.outb(device.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & 0x0F)));

    x86.outb(device.base_port + ATA_REG_SECCOUNT, count);

    x86.outb(device.base_port + ATA_REG_LBA0, @as(u8, @intCast(lba & 0xFF)));
    x86.outb(device.base_port + ATA_REG_LBA1, @as(u8, @intCast((lba >> 8) & 0xFF)));
    x86.outb(device.base_port + ATA_REG_LBA2, @as(u8, @intCast((lba >> 16) & 0xFF)));

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_WRITE_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(device);

        for (0..256) |_| {
            const word = @as(u16, buffer[buffer_offset]) |
                (@as(u16, buffer[buffer_offset + 1]) << 8);
            x86.outw(device.base_port + ATA_REG_DATA, word);
            buffer_offset += 2;
        }
    }

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    try waitDriveReady(device);
}

pub fn getPrimaryMaster() ?*const ATADevice {
    if (primary_master.present) {
        return &primary_master;
    }
    return null;
}

fn waitDriveReady(device: *const ATADevice) ATAError!void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const status = x86.inb(device.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRDY) != 0) {
            return;
        }
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) {
            return ATAError.DriveError;
        }
    }
    return ATAError.Timeout;
}

fn waitDataReady(device: *const ATADevice) ATAError!void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const status = x86.inb(device.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRQ) != 0) {
            return;
        }
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) {
            return ATAError.DriveError;
        }
    }
    return ATAError.Timeout;
}

fn printDriveInfo(device: *const ATADevice) void {

    var i: usize = 0;
    while (i < 40 and device.model[i] != 0) : (i += 1) {
        vga.put_char(device.model[i]);
    }

    vga.print(" (");
    printSize(device.sectors * 512);
    vga.print(")\n");
}

fn printSize(bytes: u64) void {
    if (bytes >= 1024 * 1024 * 1024) {
        printNumber(bytes / (1024 * 1024 * 1024));
        vga.print(" GB");
    } else if (bytes >= 1024 * 1024) {
        printNumber(bytes / (1024 * 1024));
        vga.print(" MB");
    } else if (bytes >= 1024) {
        printNumber(bytes / 1024);
        vga.print(" KB");
    } else {
        printNumber(bytes);
        vga.print(" B");
    }
}

fn printNumber(num: u64) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    var buffer: [20]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (i += 1) {
        buffer[i] = @as(u8, @intCast((n % 10) + '0'));
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(buffer[i]);
    }
}

