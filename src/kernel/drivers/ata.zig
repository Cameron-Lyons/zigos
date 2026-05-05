const x86 = @import("../../arch/x86.zig");
const common = @import("../boot/common.zig");
const vga = @import("vga.zig");

pub const kernel_boundary_role = "bootstrap_storage_inventory_shim";
pub const publishes_full_storage_service = false;
pub const ata_data_plane_exports_fail_closed = true;

const ATA_PRIMARY_BASE: u16 = 0x1F0;
const ATA_PRIMARY_CTRL: u16 = 0x3F6;
const ATA_SECONDARY_BASE: u16 = 0x170;
const ATA_SECONDARY_CTRL: u16 = 0x376;

const ATA_REG_DATA: u16 = 0;
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
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_ERR: u8 = 0x01;

const ATA_MASTER: u8 = 0xA0;
const ATA_SLAVE: u8 = 0xB0;
const ATA_LBA28_MASTER: u8 = 0xE0;
const ATA_LBA28_SLAVE: u8 = 0xF0;
const ATA_IDENTIFY_WORDS: usize = 256;
const ATA_WORD_BYTES: usize = 2;
const ATA_SECTOR_SIZE: usize = 512;
const ATA_SECTOR_WORDS: usize = ATA_SECTOR_SIZE / ATA_WORD_BYTES;
const ATA_MAX_SECTORS_PER_PIO: u8 = 128;
const ATA_POLL_DELAY_READS: usize = 4;
const ATA_WAIT_LIMIT: u32 = 100000;
const ATA_MODEL_BYTES: usize = 40;
const ATA_SERIAL_BYTES: usize = 20;
const ATA_MODEL_BUFFER_BYTES: usize = ATA_MODEL_BYTES + 1;
const ATA_SERIAL_BUFFER_BYTES: usize = ATA_SERIAL_BYTES + 1;
const ATA_IDENTIFY_LBA_WORD: usize = 49;
const ATA_IDENTIFY_LBA48_WORD: usize = 83;
const ATA_IDENTIFY_LBA28_SECTORS_WORD: usize = 60;
const ATA_IDENTIFY_LBA48_SECTORS_WORD: usize = 100;
const ATA_IDENTIFY_MODEL_WORD_START: usize = 27;
const ATA_IDENTIFY_MODEL_WORD_END: usize = 47;
const ATA_IDENTIFY_SERIAL_WORD_START: usize = 10;
const ATA_IDENTIFY_SERIAL_WORD_END: usize = 20;
const ATA_IDENTIFY_LBA_SUPPORTED: u16 = 0x200;
const ATA_IDENTIFY_LBA48_SUPPORTED: u16 = 0x400;
const LOW_BYTE_MASK: u16 = 0xFF;
const LOW_BYTE_MASK_U64: u64 = 0xFF;
const LBA28_DRIVE_HEAD_MASK: u8 = 0x0F;
const BYTE_BITS: u6 = 8;

pub const ATAError = error{
    Timeout,
    DriveError,
    NotFound,
    InvalidParameter,
    ReadError,
    WriteError,
    KernelDataPlaneDisabled,
};

pub const ATADevice = struct {
    present: bool,
    base_port: u16,
    ctrl_port: u16,
    is_master: bool,
    sectors: u64,
    model: [ATA_MODEL_BUFFER_BYTES]u8,
    serial: [ATA_SERIAL_BUFFER_BYTES]u8,
    supports_lba: bool,
    supports_lba48: bool,
};

// SAFETY: fully initialized in init() before use
var primary_master: ATADevice = undefined;
// SAFETY: fully initialized in init() before use
var primary_slave: ATADevice = undefined;
// SAFETY: fully initialized in init() before use
var secondary_master: ATADevice = undefined;
// SAFETY: fully initialized in init() before use
var secondary_slave: ATADevice = undefined;

pub fn init() void {
    vga.print("  - Detecting ATA drives...\n");

    primary_master = ATADevice{
        .present = false,
        .base_port = ATA_PRIMARY_BASE,
        .ctrl_port = ATA_PRIMARY_CTRL,
        .is_master = true,
        .sectors = 0,
        .model = [_]u8{0} ** ATA_MODEL_BUFFER_BYTES,
        .serial = [_]u8{0} ** ATA_SERIAL_BUFFER_BYTES,
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
        .model = [_]u8{0} ** ATA_MODEL_BUFFER_BYTES,
        .serial = [_]u8{0} ** ATA_SERIAL_BUFFER_BYTES,
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
        .model = [_]u8{0} ** ATA_MODEL_BUFFER_BYTES,
        .serial = [_]u8{0} ** ATA_SERIAL_BUFFER_BYTES,
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
        .model = [_]u8{0} ** ATA_MODEL_BUFFER_BYTES,
        .serial = [_]u8{0} ** ATA_SERIAL_BUFFER_BYTES,
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

    for (0..ATA_POLL_DELAY_READS) |_| {
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

    // SAFETY: filled by the subsequent port I/O reads in the loop
    var buffer: [ATA_IDENTIFY_WORDS]u16 = undefined;
    for (&buffer) |*word| {
        word.* = x86.inw(device.base_port + ATA_REG_DATA);
    }

    device.present = true;

    if ((buffer[ATA_IDENTIFY_LBA_WORD] & ATA_IDENTIFY_LBA_SUPPORTED) != 0) {
        device.supports_lba = true;
    }

    if ((buffer[ATA_IDENTIFY_LBA48_WORD] & ATA_IDENTIFY_LBA48_SUPPORTED) != 0) {
        device.supports_lba48 = true;
    }

    if (device.supports_lba48) {
        device.sectors = @as(u64, buffer[ATA_IDENTIFY_LBA48_SECTORS_WORD]) |
            (@as(u64, buffer[ATA_IDENTIFY_LBA48_SECTORS_WORD + 1]) << 16) |
            (@as(u64, buffer[ATA_IDENTIFY_LBA48_SECTORS_WORD + 2]) << 32) |
            (@as(u64, buffer[ATA_IDENTIFY_LBA48_SECTORS_WORD + 3]) << 48);
    } else if (device.supports_lba) {
        device.sectors = @as(u64, buffer[ATA_IDENTIFY_LBA28_SECTORS_WORD]) | (@as(u64, buffer[ATA_IDENTIFY_LBA28_SECTORS_WORD + 1]) << 16);
    }

    var model_idx: usize = 0;
    for (ATA_IDENTIFY_MODEL_WORD_START..ATA_IDENTIFY_MODEL_WORD_END) |i| {
        device.model[model_idx] = @as(u8, @intCast((buffer[i] >> BYTE_BITS) & LOW_BYTE_MASK));
        model_idx += 1;
        device.model[model_idx] = @as(u8, @intCast(buffer[i] & LOW_BYTE_MASK));
        model_idx += 1;
    }
    device.model[ATA_MODEL_BYTES] = 0;

    var serial_idx: usize = 0;
    for (ATA_IDENTIFY_SERIAL_WORD_START..ATA_IDENTIFY_SERIAL_WORD_END) |i| {
        device.serial[serial_idx] = @as(u8, @intCast((buffer[i] >> BYTE_BITS) & LOW_BYTE_MASK));
        serial_idx += 1;
        device.serial[serial_idx] = @as(u8, @intCast(buffer[i] & LOW_BYTE_MASK));
        serial_idx += 1;
    }
    device.serial[ATA_SERIAL_BYTES] = 0;
}

fn readSectorsSync(device: *const ATADevice, lba: u64, count: u8, buffer: []u8) ATAError!void {
    if (!device.present) {
        return ATAError.NotFound;
    }

    if (count == 0 or count > ATA_MAX_SECTORS_PER_PIO) {
        return ATAError.InvalidParameter;
    }

    if (buffer.len < @as(usize, count) * ATA_SECTOR_SIZE) {
        return ATAError.InvalidParameter;
    }

    try waitDriveReady(device);

    const drive_select: u8 = if (device.is_master) ATA_LBA28_MASTER else ATA_LBA28_SLAVE;
    x86.outb(device.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & LBA28_DRIVE_HEAD_MASK)));
    for (0..ATA_POLL_DELAY_READS) |_| {
        _ = x86.inb(device.ctrl_port);
    }

    x86.outb(device.base_port + ATA_REG_SECCOUNT, count);

    x86.outb(device.base_port + ATA_REG_LBA0, @as(u8, @intCast(lba & LOW_BYTE_MASK_U64)));
    x86.outb(device.base_port + ATA_REG_LBA1, @as(u8, @intCast((lba >> 8) & LOW_BYTE_MASK_U64)));
    x86.outb(device.base_port + ATA_REG_LBA2, @as(u8, @intCast((lba >> 16) & LOW_BYTE_MASK_U64)));

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_READ_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(device);

        for (0..ATA_SECTOR_WORDS) |_| {
            const word = x86.inw(device.base_port + ATA_REG_DATA);
            buffer[buffer_offset] = @as(u8, @intCast(word & LOW_BYTE_MASK));
            buffer[buffer_offset + 1] = @as(u8, @intCast((word >> BYTE_BITS) & LOW_BYTE_MASK));
            buffer_offset += ATA_WORD_BYTES;
        }
    }
}

fn writeSectorsSync(device: *const ATADevice, lba: u64, count: u8, buffer: []const u8) ATAError!void {
    if (!device.present) {
        return ATAError.NotFound;
    }

    if (count == 0 or count > ATA_MAX_SECTORS_PER_PIO) {
        return ATAError.InvalidParameter;
    }

    if (buffer.len < @as(usize, count) * ATA_SECTOR_SIZE) {
        return ATAError.InvalidParameter;
    }

    common.printBootMarker("ZIGOS:STORAGE:CHECKPOINT:ATA_WRITE_READY_WAIT");
    try waitDriveReady(device);

    const drive_select: u8 = if (device.is_master) ATA_LBA28_MASTER else ATA_LBA28_SLAVE;
    x86.outb(device.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & LBA28_DRIVE_HEAD_MASK)));
    for (0..ATA_POLL_DELAY_READS) |_| {
        _ = x86.inb(device.ctrl_port);
    }

    x86.outb(device.base_port + ATA_REG_SECCOUNT, count);

    x86.outb(device.base_port + ATA_REG_LBA0, @as(u8, @intCast(lba & LOW_BYTE_MASK_U64)));
    x86.outb(device.base_port + ATA_REG_LBA1, @as(u8, @intCast((lba >> 8) & LOW_BYTE_MASK_U64)));
    x86.outb(device.base_port + ATA_REG_LBA2, @as(u8, @intCast((lba >> 16) & LOW_BYTE_MASK_U64)));

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_WRITE_SECTORS);
    common.printBootMarker("ZIGOS:STORAGE:CHECKPOINT:ATA_WRITE_COMMAND");

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(device);
        common.printBootMarker("ZIGOS:STORAGE:CHECKPOINT:ATA_WRITE_SECTOR");

        for (0..ATA_SECTOR_WORDS) |_| {
            const word = @as(u16, buffer[buffer_offset]) |
                (@as(u16, buffer[buffer_offset + 1]) << BYTE_BITS);
            x86.outw(device.base_port + ATA_REG_DATA, word);
            buffer_offset += ATA_WORD_BYTES;
        }
    }

    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    common.printBootMarker("ZIGOS:STORAGE:CHECKPOINT:ATA_WRITE_FLUSH");
    try waitDriveReady(device);
    common.printBootMarker("ZIGOS:STORAGE:CHECKPOINT:ATA_WRITE_DONE");
}

pub fn readSectors(device: *const ATADevice, lba: u64, count: u8, buffer: []u8) ATAError!void {
    _ = device;
    _ = lba;
    _ = count;
    _ = buffer;
    return error.KernelDataPlaneDisabled;
}

pub fn writeSectors(device: *const ATADevice, lba: u64, count: u8, buffer: []const u8) ATAError!void {
    _ = device;
    _ = lba;
    _ = count;
    _ = buffer;
    return error.KernelDataPlaneDisabled;
}

pub fn getPrimaryMaster() ?*const ATADevice {
    if (primary_master.present) {
        return &primary_master;
    }
    return null;
}

pub fn getPrimarySlave() ?*const ATADevice {
    if (primary_slave.present) {
        return &primary_slave;
    }
    return null;
}

pub fn getSecondaryMaster() ?*const ATADevice {
    if (secondary_master.present) {
        return &secondary_master;
    }
    return null;
}

pub fn getSecondarySlave() ?*const ATADevice {
    if (secondary_slave.present) {
        return &secondary_slave;
    }
    return null;
}

pub fn firstDetectedDevice() ?*const ATADevice {
    return getPrimaryMaster() orelse getPrimarySlave() orelse getSecondaryMaster() orelse getSecondarySlave();
}

pub fn findDetectedDeviceByStableId(device_id: u64) ?*const ATADevice {
    const devices = [_]?*const ATADevice{
        getPrimaryMaster(),
        getPrimarySlave(),
        getSecondaryMaster(),
        getSecondarySlave(),
    };
    for (devices) |maybe_device| {
        const device = maybe_device orelse continue;
        if (stableDeviceId(device) == device_id) return device;
    }
    return null;
}

pub fn stableDeviceId(device: *const ATADevice) u64 {
    return (@as(u64, device.base_port) << 8) | @as(u64, @intFromBool(device.is_master));
}

fn waitDriveReady(device: *const ATADevice) ATAError!void {
    var timeout: u32 = ATA_WAIT_LIMIT;
    while (timeout > 0) : (timeout -= 1) {
        const status = x86.inb(device.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0) {
            return;
        }
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) {
            return ATAError.DriveError;
        }
    }
    return ATAError.Timeout;
}

fn waitDataReady(device: *const ATADevice) ATAError!void {
    var timeout: u32 = ATA_WAIT_LIMIT;
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
    while (i < ATA_MODEL_BYTES and device.model[i] != 0) : (i += 1) {
        vga.put_char(device.model[i]);
    }

    vga.print(" (");
    printSize(device.sectors * @as(u64, ATA_SECTOR_SIZE));
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

    // SAFETY: filled by the following digit extraction loop
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
