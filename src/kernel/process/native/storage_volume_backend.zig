const ata = @import("../../drivers/ata.zig");
const storage_volume = @import("storage_volume.zig");

var attached_device: ?*const ata.ATADevice = null;

pub fn attachDefaultAtaBackend() bool {
    if (attached_device == null) {
        attached_device = ata.getPrimarySlave() orelse ata.getSecondaryMaster() orelse ata.getSecondarySlave();
    }
    if (attached_device == null) return false;

    storage_volume.attachBackend(.{
        .sector_count = attached_device.?.sectors,
        .read = readRange,
        .write = writeRange,
    });
    return true;
}

fn readRange(start_lba: u64, buffer: []u8) bool {
    const device = attached_device orelse return false;
    var offset: usize = 0;
    var lba = start_lba;
    while (offset < buffer.len) {
        const remaining_sectors = (buffer.len - offset) / storage_volume.sector_size;
        const chunk_sectors: u8 = @intCast(@min(remaining_sectors, 128));
        ata.readSectors(device, lba, chunk_sectors, buffer[offset .. offset + (@as(usize, chunk_sectors) * storage_volume.sector_size)]) catch return false;
        lba += chunk_sectors;
        offset += @as(usize, chunk_sectors) * storage_volume.sector_size;
    }
    return true;
}

fn writeRange(start_lba: u64, buffer: []const u8) bool {
    const device = attached_device orelse return false;
    var offset: usize = 0;
    var lba = start_lba;
    while (offset < buffer.len) {
        const remaining_sectors = (buffer.len - offset) / storage_volume.sector_size;
        const chunk_sectors: u8 = @intCast(@min(remaining_sectors, 128));
        ata.writeSectors(device, lba, chunk_sectors, buffer[offset .. offset + (@as(usize, chunk_sectors) * storage_volume.sector_size)]) catch return false;
        lba += chunk_sectors;
        offset += @as(usize, chunk_sectors) * storage_volume.sector_size;
    }
    return true;
}
