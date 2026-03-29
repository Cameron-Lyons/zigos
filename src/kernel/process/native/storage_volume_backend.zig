const builtin = @import("builtin");
const std = @import("std");
const storage_volume = @import("storage_volume.zig");

const ata = if (builtin.target.os.tag == .freestanding)
    @import("../../drivers/ata.zig")
else
    struct {
        pub const ATADevice = struct {
            sectors: u64 = 0,
            base_port: u16 = 0,
            is_master: bool = false,
        };

        pub fn getPrimaryMaster() ?*const ATADevice {
            return null;
        }

        pub fn getPrimarySlave() ?*const ATADevice {
            return null;
        }

        pub fn getSecondaryMaster() ?*const ATADevice {
            return null;
        }

        pub fn getSecondarySlave() ?*const ATADevice {
            return null;
        }

        pub fn firstDetectedDevice() ?*const ATADevice {
            return null;
        }

        pub fn stableDeviceId(_: *const ATADevice) u64 {
            return 0;
        }

        pub fn readSectors(_: *const ATADevice, _: u64, _: u8, _: []u8) error{}!void {}

        pub fn writeSectors(_: *const ATADevice, _: u64, _: u8, _: []const u8) error{}!void {}
    };

var attached_device: ?*const ata.ATADevice = null;

pub fn defaultAtaBackend() ?storage_volume.Backend {
    const device = ensureAttachedDevice() orelse return null;
    return .{
        .sector_count = device.sectors,
        .read = readRange,
        .write = writeRange,
    };
}

pub fn defaultAtaBackendForDevice(device_id: u64) ?storage_volume.Backend {
    const device = ensureAttachedDevice() orelse return null;
    if (ata.stableDeviceId(device) != device_id) return null;
    return .{
        .sector_count = device.sectors,
        .read = readRange,
        .write = writeRange,
    };
}

pub fn attachDefaultAtaBackend() bool {
    const device = ensureAttachedDevice() orelse return false;
    storage_volume.attachAtaBootstrapDevice(@ptrCast(device), device.sectors);
    return true;
}

pub fn attachDefaultAtaBackendForDevice(device_id: u64) bool {
    const device = ensureAttachedDevice() orelse return false;
    if (ata.stableDeviceId(device) != device_id) return false;
    storage_volume.attachAtaBootstrapDevice(@ptrCast(device), device.sectors);
    return true;
}

fn readRange(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
    const device = attached_device orelse return false;
    const context = ReadContext{ .device = device };
    return transferReadRange(start_lba, buffer_ptr[0..buffer_len], &context);
}

fn writeRange(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
    const device = attached_device orelse return false;
    const context = WriteContext{ .device = device };
    return transferWriteRange(start_lba, buffer_ptr[0..buffer_len], &context);
}

fn ensureAttachedDevice() ?*const ata.ATADevice {
    if (attached_device == null) {
        attached_device = ata.firstDetectedDevice();
    }
    return attached_device;
}

const ReadContext = struct {
    device: *const ata.ATADevice,

    fn read(self: *const @This(), lba: u64, sector_count: u8, buffer: []u8) bool {
        ata.readSectors(self.device, lba, sector_count, buffer) catch return false;
        return true;
    }
};

const WriteContext = struct {
    device: *const ata.ATADevice,

    fn write(self: *const @This(), lba: u64, sector_count: u8, buffer: []const u8) bool {
        ata.writeSectors(self.device, lba, sector_count, buffer) catch return false;
        return true;
    }
};

fn transferReadRange(start_lba: u64, buffer: []u8, context: anytype) bool {
    var offset: usize = 0;
    var lba = start_lba;
    while (offset < buffer.len) {
        const remaining_sectors = (buffer.len - offset) / storage_volume.sector_size;
        const chunk_sectors: u8 = @intCast(@min(remaining_sectors, 128));
        const chunk = buffer[offset .. offset + (@as(usize, chunk_sectors) * storage_volume.sector_size)];
        if (!context.read(lba, chunk_sectors, chunk)) return false;
        lba += chunk_sectors;
        offset += @as(usize, chunk_sectors) * storage_volume.sector_size;
    }
    return true;
}

fn transferWriteRange(start_lba: u64, buffer: []const u8, context: anytype) bool {
    var offset: usize = 0;
    var lba = start_lba;
    while (offset < buffer.len) {
        const remaining_sectors = (buffer.len - offset) / storage_volume.sector_size;
        const chunk_sectors: u8 = @intCast(@min(remaining_sectors, 128));
        const chunk = buffer[offset .. offset + (@as(usize, chunk_sectors) * storage_volume.sector_size)];
        if (!context.write(lba, chunk_sectors, chunk)) return false;
        lba += chunk_sectors;
        offset += @as(usize, chunk_sectors) * storage_volume.sector_size;
    }
    return true;
}

export fn zigosStorageBootstrapAtaRead(
    device_ptr: *const anyopaque,
    start_lba: u64,
    buffer_ptr: [*]u8,
    buffer_len: usize,
) callconv(.c) bool {
    const device: *const ata.ATADevice = @ptrCast(@alignCast(device_ptr));
    const context = ReadContext{ .device = device };
    return transferReadRange(start_lba, buffer_ptr[0..buffer_len], &context);
}

export fn zigosStorageBootstrapAtaWrite(
    device_ptr: *const anyopaque,
    start_lba: u64,
    buffer_ptr: [*]const u8,
    buffer_len: usize,
) callconv(.c) bool {
    const device: *const ata.ATADevice = @ptrCast(@alignCast(device_ptr));
    const context = WriteContext{ .device = device };
    return transferWriteRange(start_lba, buffer_ptr[0..buffer_len], &context);
}

test "storage volume backend splits large reads into ATA-sized chunks" {
    const Recorder = struct {
        const Call = struct {
            lba: u64,
            sector_count: u8,
            first_byte: u8,
        };

        calls: [4]Call = undefined,
        count: usize = 0,

        fn read(self: *@This(), lba: u64, sector_count: u8, buffer: []u8) bool {
            self.calls[self.count] = .{
                .lba = lba,
                .sector_count = sector_count,
                .first_byte = @intCast(self.count + 1),
            };
            @memset(buffer, self.calls[self.count].first_byte);
            self.count += 1;
            return true;
        }
    };

    var recorder = Recorder{};
    var buffer: [130 * storage_volume.sector_size]u8 = undefined;

    try std.testing.expect(transferReadRange(40, &buffer, &recorder));
    try std.testing.expectEqual(@as(usize, 2), recorder.count);
    try std.testing.expectEqual(@as(u64, 40), recorder.calls[0].lba);
    try std.testing.expectEqual(@as(u8, 128), recorder.calls[0].sector_count);
    try std.testing.expectEqual(@as(u64, 168), recorder.calls[1].lba);
    try std.testing.expectEqual(@as(u8, 2), recorder.calls[1].sector_count);
    try std.testing.expectEqual(@as(u8, 1), buffer[0]);
    try std.testing.expectEqual(@as(u8, 2), buffer[128 * storage_volume.sector_size]);
}

test "storage volume backend splits large writes into ATA-sized chunks" {
    const Recorder = struct {
        const Call = struct {
            lba: u64,
            sector_count: u8,
            first_byte: u8,
        };

        calls: [4]Call = undefined,
        count: usize = 0,

        fn write(self: *@This(), lba: u64, sector_count: u8, buffer: []const u8) bool {
            self.calls[self.count] = .{
                .lba = lba,
                .sector_count = sector_count,
                .first_byte = buffer[0],
            };
            self.count += 1;
            return true;
        }
    };

    var recorder = Recorder{};
    var buffer: [129 * storage_volume.sector_size]u8 = [_]u8{0xAB} ** (129 * storage_volume.sector_size);
    buffer[128 * storage_volume.sector_size] = 0xCD;

    try std.testing.expect(transferWriteRange(90, &buffer, &recorder));
    try std.testing.expectEqual(@as(usize, 2), recorder.count);
    try std.testing.expectEqual(@as(u64, 90), recorder.calls[0].lba);
    try std.testing.expectEqual(@as(u8, 128), recorder.calls[0].sector_count);
    try std.testing.expectEqual(@as(u8, 0xAB), recorder.calls[0].first_byte);
    try std.testing.expectEqual(@as(u64, 218), recorder.calls[1].lba);
    try std.testing.expectEqual(@as(u8, 1), recorder.calls[1].sector_count);
    try std.testing.expectEqual(@as(u8, 0xCD), recorder.calls[1].first_byte);
}
