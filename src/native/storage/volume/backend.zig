const builtin = @import("builtin");
const volume_layout = @import("layout.zig");

const ata_bridge = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn zigosStorageBootstrapAtaRead(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]u8,
            buffer_len: usize,
        ) callconv(.c) bool;

        extern fn zigosStorageBootstrapAtaWrite(
            device: *const anyopaque,
            start_lba: u64,
            buffer_ptr: [*]const u8,
            buffer_len: usize,
        ) callconv(.c) bool;

        extern fn zigosStorageBootstrapAtaFlush(device: *const anyopaque) callconv(.c) bool;

        pub fn read(device: *const anyopaque, start_lba: u64, buffer: []u8) bool {
            return zigosStorageBootstrapAtaRead(device, start_lba, buffer.ptr, buffer.len);
        }

        pub fn write(device: *const anyopaque, start_lba: u64, buffer: []const u8) bool {
            return zigosStorageBootstrapAtaWrite(device, start_lba, buffer.ptr, buffer.len);
        }

        pub fn flush(device: *const anyopaque) bool {
            return zigosStorageBootstrapAtaFlush(device);
        }
    }
else
    struct {
        pub fn read(_: *const anyopaque, _: u64, _: []u8) bool {
            return false;
        }

        pub fn write(_: *const anyopaque, _: u64, _: []const u8) bool {
            return false;
        }

        pub fn flush(_: *const anyopaque) bool {
            return false;
        }
    };

pub const Backend = struct {
    sector_count: u64,
    read: *const fn (start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool,
    write: *const fn (start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool,
    flush: *const fn () callconv(.c) bool,
};

pub const AttachedBackendKind = enum(u8) {
    none,
    generic,
    nvme_pci,
    ata_bootstrap,
    ata_bootstrap_broker,
};

pub fn unattachedRead(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
    return false;
}

pub fn unattachedWrite(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
    return false;
}

pub fn unattachedFlush() callconv(.c) bool {
    return false;
}

pub fn readAtaBootstrap(device: *const anyopaque, start_lba: u64, buffer: []u8) bool {
    return ata_bridge.read(device, start_lba, buffer);
}

pub fn writeAtaBootstrap(device: *const anyopaque, start_lba: u64, buffer: []const u8) bool {
    return ata_bridge.write(device, start_lba, buffer);
}

pub fn flushAtaBootstrap(device: *const anyopaque) bool {
    return ata_bridge.flush(device);
}

pub fn clearAttachedVolume(volume: anytype) void {
    if (!volume.hasAttachedDevice()) return;
    if (volume.attached_backend_sector_count < volume_layout.required_device_sectors) return;
    @memset(volume.sector_buffer[0..], 0);
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        if (!writeAttachedRange(volume, sector_index, volume.sector_buffer[0..])) return;
    }
    _ = flushAttached(volume);
}

pub fn writeAttachedBytes(volume: anytype, offset: usize, bytes: []const u8) bool {
    if (offset + bytes.len > volume_layout.image_bytes) return false;
    var remaining = bytes.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / volume_layout.sector_size;
        const sector_offset = absolute_offset % volume_layout.sector_size;

        if (sector_offset == 0 and remaining >= volume_layout.sector_size) {
            // Sector-aligned full-sector run: issue ONE multi-sector backend write
            // instead of decomposing into a backend call per 512B sector.
            const run_sectors = remaining / volume_layout.sector_size;
            const run_len = run_sectors * volume_layout.sector_size;
            if (!writeAttachedRange(volume, @intCast(sector_index), bytes[cursor .. cursor + run_len])) return false;
            cursor += run_len;
            remaining -= run_len;
        } else {
            // Unaligned head or sub-sector tail: read-modify-write one sector.
            const chunk_len = @min(remaining, volume_layout.sector_size - sector_offset);
            if (!readAttachedRange(volume, @intCast(sector_index), volume.sector_buffer[0..])) return false;
            @memcpy(volume.sector_buffer[sector_offset .. sector_offset + chunk_len], bytes[cursor .. cursor + chunk_len]);
            if (!writeAttachedRange(volume, @intCast(sector_index), volume.sector_buffer[0..])) return false;
            cursor += chunk_len;
            remaining -= chunk_len;
        }
    }
    return true;
}

pub fn readAttachedBytes(volume: anytype, offset: usize, buffer: []u8) bool {
    if (offset + buffer.len > volume_layout.image_bytes) return false;
    var remaining = buffer.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / volume_layout.sector_size;
        const sector_offset = absolute_offset % volume_layout.sector_size;

        if (sector_offset == 0 and remaining >= volume_layout.sector_size) {
            // Sector-aligned full-sector run: read directly into the caller buffer in
            // ONE multi-sector backend read, avoiding both the per-sector backend call
            // and the per-sector staging memcpy.
            const run_sectors = remaining / volume_layout.sector_size;
            const run_len = run_sectors * volume_layout.sector_size;
            if (!readAttachedRange(volume, @intCast(sector_index), buffer[cursor .. cursor + run_len])) return false;
            cursor += run_len;
            remaining -= run_len;
        } else {
            const chunk_len = @min(remaining, volume_layout.sector_size - sector_offset);
            if (!readAttachedRange(volume, @intCast(sector_index), volume.sector_buffer[0..])) return false;
            @memcpy(buffer[cursor .. cursor + chunk_len], volume.sector_buffer[sector_offset .. sector_offset + chunk_len]);
            cursor += chunk_len;
            remaining -= chunk_len;
        }
    }
    return true;
}

pub fn readAttachedRange(volume: anytype, start_lba: u64, buffer: []u8) bool {
    return switch (volume.attached_backend_kind) {
        .none => false,
        .generic, .nvme_pci, .ata_bootstrap_broker => volume.attached_backend_read(start_lba, buffer.ptr, buffer.len),
        .ata_bootstrap => ataReadRange(volume, start_lba, buffer),
    };
}

pub fn writeAttachedRange(volume: anytype, start_lba: u64, buffer: []const u8) bool {
    return switch (volume.attached_backend_kind) {
        .none => false,
        .generic, .nvme_pci, .ata_bootstrap_broker => volume.attached_backend_write(start_lba, buffer.ptr, buffer.len),
        .ata_bootstrap => ataWriteRange(volume, start_lba, buffer),
    };
}

pub fn writeAttachedDurableRange(volume: anytype, start_lba: u64, buffer: []const u8) bool {
    if (!writeAttachedRange(volume, start_lba, buffer)) return false;
    return flushAttached(volume);
}

pub fn flushAttached(volume: anytype) bool {
    return switch (volume.attached_backend_kind) {
        .none => false,
        .generic, .nvme_pci, .ata_bootstrap_broker => volume.attached_backend_flush(),
        .ata_bootstrap => ataFlush(volume),
    };
}

fn ataReadRange(volume: anytype, start_lba: u64, buffer: []u8) bool {
    const device = volume.attached_ata_device orelse return false;
    return readAtaBootstrap(device, start_lba, buffer);
}

fn ataWriteRange(volume: anytype, start_lba: u64, buffer: []const u8) bool {
    const device = volume.attached_ata_device orelse return false;
    return writeAtaBootstrap(device, start_lba, buffer);
}

fn ataFlush(volume: anytype) bool {
    const device = volume.attached_ata_device orelse return false;
    return flushAtaBootstrap(device);
}
