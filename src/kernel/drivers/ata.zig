const builtin = @import("builtin");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn outb(_: u16, _: u8) void {}

        pub fn inb(_: u16) u8 {
            return 0;
        }

        pub fn inw(_: u16) u16 {
            return 0;
        }
    };
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

const ATA_CMD_IDENTIFY: u8 = 0xEC;

const ATA_SR_BSY: u8 = 0x80;
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_ERR: u8 = 0x01;

const ATA_MASTER: u8 = 0xA0;
const ATA_SLAVE: u8 = 0xB0;
const ATA_IDENTIFY_WORDS: usize = 256;
const ATA_SECTOR_SIZE: usize = 512;
const ATA_POLL_DELAY_READS: usize = 4;
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
const BYTE_BITS: u6 = 8;
const WORD_BITS: u6 = 16;
const DWORD_BITS: u6 = 32;
const QWORD_HIGH_BITS: u6 = 48;
const DRIVE_SELECT_SHIFT = 8;
const WAIT_NOT_BUSY_POLLS: u32 = 100_000;
const BYTES_PER_KIB: u64 = 1024;
const BYTES_PER_MIB: u64 = BYTES_PER_KIB * 1024;
const BYTES_PER_GIB: u64 = BYTES_PER_MIB * 1024;

pub const ATAError = error{
    Timeout,
    DriveError,
    NotFound,
    InvalidParameter,
    KernelStorageDataPlaneDisabled,
};

pub const DataPlaneTransferRequest = struct {
    device_id: u64,
    lba: u64,
    sector_count: u8,
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

    primary_master = emptyDevice(ATA_PRIMARY_BASE, ATA_PRIMARY_CTRL, true);
    detectDrive(&primary_master);

    primary_slave = emptyDevice(ATA_PRIMARY_BASE, ATA_PRIMARY_CTRL, false);
    detectDrive(&primary_slave);

    secondary_master = emptyDevice(ATA_SECONDARY_BASE, ATA_SECONDARY_CTRL, true);
    detectDrive(&secondary_master);

    secondary_slave = emptyDevice(ATA_SECONDARY_BASE, ATA_SECONDARY_CTRL, false);
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

fn emptyDevice(base_port: u16, ctrl_port: u16, is_master: bool) ATADevice {
    return .{
        .present = false,
        .base_port = base_port,
        .ctrl_port = ctrl_port,
        .is_master = is_master,
        .sectors = 0,
        .model = [_]u8{0} ** ATA_MODEL_BUFFER_BYTES,
        .serial = [_]u8{0} ** ATA_SERIAL_BUFFER_BYTES,
        .supports_lba = false,
        .supports_lba48 = false,
    };
}

fn detectDrive(device: *ATADevice) void {
    x86.outb(device.base_port + ATA_REG_DRIVE, if (device.is_master) ATA_MASTER else ATA_SLAVE);

    for (0..ATA_POLL_DELAY_READS) |_| {
        _ = x86.inb(device.ctrl_port);
    }

    if (!waitNotBusy(device)) return;
    x86.outb(device.base_port + ATA_REG_SECCOUNT, 0);
    x86.outb(device.base_port + ATA_REG_LBA0, 0);
    x86.outb(device.base_port + ATA_REG_LBA1, 0);
    x86.outb(device.base_port + ATA_REG_LBA2, 0);
    x86.outb(device.base_port + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

    const status = x86.inb(device.base_port + ATA_REG_STATUS);
    if (status == 0) {
        return;
    }

    if (!waitNotBusy(device)) return;

    if (x86.inb(device.base_port + ATA_REG_LBA1) != 0 or
        x86.inb(device.base_port + ATA_REG_LBA2) != 0)
    {
        return;
    }

    var drq_polls: u32 = WAIT_NOT_BUSY_POLLS;
    while (true) {
        if (drq_polls == 0) return;
        drq_polls -= 1;
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

    if ((buffer[ATA_IDENTIFY_LBA_WORD] & ATA_IDENTIFY_LBA_SUPPORTED) != 0) {
        device.supports_lba = true;
    }

    if ((buffer[ATA_IDENTIFY_LBA48_WORD] & ATA_IDENTIFY_LBA48_SUPPORTED) != 0) {
        device.supports_lba48 = true;
    }

    const lba28_sectors = if (device.supports_lba) identifyU32(&buffer, ATA_IDENTIFY_LBA28_SECTORS_WORD) else 0;
    const lba48_sectors = if (device.supports_lba48) identifyU64(&buffer, ATA_IDENTIFY_LBA48_SECTORS_WORD) else 0;
    device.sectors = if (lba48_sectors != 0) lba48_sectors else lba28_sectors;
    if (device.sectors == 0) return;

    device.present = true;

    copyIdentifyText(device.model[0..ATA_MODEL_BYTES], &buffer, ATA_IDENTIFY_MODEL_WORD_START, ATA_IDENTIFY_MODEL_WORD_END);
    device.model[ATA_MODEL_BYTES] = 0;

    copyIdentifyText(device.serial[0..ATA_SERIAL_BYTES], &buffer, ATA_IDENTIFY_SERIAL_WORD_START, ATA_IDENTIFY_SERIAL_WORD_END);
    device.serial[ATA_SERIAL_BYTES] = 0;
}

fn identifyU32(buffer: *const [ATA_IDENTIFY_WORDS]u16, start_word: usize) u64 {
    return @as(u64, buffer[start_word]) |
        (@as(u64, buffer[start_word + 1]) << WORD_BITS);
}

fn identifyU64(buffer: *const [ATA_IDENTIFY_WORDS]u16, start_word: usize) u64 {
    return @as(u64, buffer[start_word]) |
        (@as(u64, buffer[start_word + 1]) << WORD_BITS) |
        (@as(u64, buffer[start_word + 2]) << DWORD_BITS) |
        (@as(u64, buffer[start_word + 3]) << QWORD_HIGH_BITS);
}

fn copyIdentifyText(dest: []u8, buffer: *const [ATA_IDENTIFY_WORDS]u16, start_word: usize, end_word: usize) void {
    var dest_index: usize = 0;
    for (start_word..end_word) |word_index| {
        dest[dest_index] = @as(u8, @intCast((buffer[word_index] >> BYTE_BITS) & LOW_BYTE_MASK));
        dest_index += 1;
        dest[dest_index] = @as(u8, @intCast(buffer[word_index] & LOW_BYTE_MASK));
        dest_index += 1;
    }
}

fn waitNotBusy(device: *const ATADevice) bool {
    var remaining: u32 = WAIT_NOT_BUSY_POLLS;
    while (remaining > 0) : (remaining -= 1) {
        const status = x86.inb(device.base_port + ATA_REG_STATUS);
        if (status == 0) return true;
        if ((status & ATA_SR_BSY) == 0) return true;
    }
    return false;
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
    return (@as(u64, device.base_port) << DRIVE_SELECT_SHIFT) | @as(u64, @intFromBool(device.is_master));
}

pub fn rejectKernelDataPlaneTransfer(_: DataPlaneTransferRequest) ATAError!void {
    return error.KernelStorageDataPlaneDisabled;
}

test "kernel ATA shim rejects direct data-plane transfer attempts" {
    try @import("std").testing.expectError(error.KernelStorageDataPlaneDisabled, rejectKernelDataPlaneTransfer(.{
        .device_id = 0x1F001,
        .lba = 7,
        .sector_count = 1,
    }));
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
    if (bytes >= BYTES_PER_GIB) {
        printNumber(bytes / BYTES_PER_GIB);
        vga.print(" GB");
    } else if (bytes >= BYTES_PER_MIB) {
        printNumber(bytes / BYTES_PER_MIB);
        vga.print(" MB");
    } else if (bytes >= BYTES_PER_KIB) {
        printNumber(bytes / BYTES_PER_KIB);
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
    const DECIMAL_U64_BUFFER_BYTES: usize = 20;
    var buffer: [DECIMAL_U64_BUFFER_BYTES]u8 = undefined;
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
