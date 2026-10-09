const volume_layout = @import("layout.zig");

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

pub fn clearAttachedVolume(volume: anytype) bool {
    if (!volume.hasAttachedDevice()) return true;
    if (volume.attached_backend_sector_count < volume_layout.required_device_sectors) return false;
    @memset(volume.sector_buffer[0..], 0);
    var sector_index: u32 = 0;
    while (sector_index < volume_layout.root_sector_count) : (sector_index += 1) {
        if (!writeAttachedRange(volume, sector_index, volume.sector_buffer[0..])) return false;
    }
    return flushAttached(volume);
}

pub fn writeAttachedBytes(volume: anytype, offset: usize, bytes: []const u8) bool {
    if (!withinImageRange(offset, bytes.len)) return false;
    var remaining = bytes.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / volume_layout.sector_size;
        const sector_offset = absolute_offset % volume_layout.sector_size;

        if (sector_offset == 0 and remaining >= volume_layout.sector_size) {
            const run_sectors = remaining / volume_layout.sector_size;
            const run_len = run_sectors * volume_layout.sector_size;
            if (!writeAttachedRange(volume, @intCast(sector_index), bytes[cursor .. cursor + run_len])) return false;
            cursor += run_len;
            remaining -= run_len;
        } else {
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
    if (!withinImageRange(offset, buffer.len)) return false;
    var remaining = buffer.len;
    var cursor: usize = 0;
    while (remaining > 0) {
        const absolute_offset = offset + cursor;
        const sector_index = absolute_offset / volume_layout.sector_size;
        const sector_offset = absolute_offset % volume_layout.sector_size;

        if (sector_offset == 0 and remaining >= volume_layout.sector_size) {
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

inline fn withinImageRange(offset: usize, length: usize) bool {
    return offset <= volume_layout.image_bytes and length <= volume_layout.image_bytes - offset;
}

pub fn readAttachedRange(volume: anytype, start_lba: u64, buffer: []u8) bool {
    return switch (volume.attached_backend_kind) {
        .none => false,
        .generic, .nvme_pci => volume.attached_backend_read(start_lba, buffer.ptr, buffer.len),
    };
}

pub fn writeAttachedRange(volume: anytype, start_lba: u64, buffer: []const u8) bool {
    return switch (volume.attached_backend_kind) {
        .none => false,
        .generic, .nvme_pci => volume.attached_backend_write(start_lba, buffer.ptr, buffer.len),
    };
}

pub fn writeAttachedDurableRange(volume: anytype, start_lba: u64, buffer: []const u8) bool {
    if (!writeAttachedRange(volume, start_lba, buffer)) return false;
    return flushAttached(volume);
}

pub fn flushAttached(volume: anytype) bool {
    return switch (volume.attached_backend_kind) {
        .none => false,
        .generic, .nvme_pci => volume.attached_backend_flush(),
    };
}

const TransferSpy = if (@import("builtin").is_test) struct {
    var reads: usize = 0;
    var writes: usize = 0;
    var last_lba: u64 = 0;
    var last_length: usize = 0;
    var written: [volume_layout.sector_size]u8 = undefined;

    const Volume = struct {
        sector_buffer: [volume_layout.sector_size]u8 = undefined,
        attached_backend_kind: AttachedBackendKind = .generic,
        attached_backend_read: @FieldType(Backend, "read") = read,
        attached_backend_write: @FieldType(Backend, "write") = write,
    };

    fn reset() void {
        reads = 0;
        writes = 0;
        last_lba = 0;
        last_length = 0;
    }

    fn read(start_lba: u64, buffer: [*]u8, length: usize) callconv(.c) bool {
        reads += 1;
        last_lba = start_lba;
        last_length = length;
        for (buffer[0..length], 0..) |*byte, index| byte.* = @truncate(start_lba * volume_layout.sector_size + index);
        return true;
    }

    fn write(start_lba: u64, buffer: [*]const u8, length: usize) callconv(.c) bool {
        writes += 1;
        last_lba = start_lba;
        last_length = length;
        if (length > written.len) return false;
        @memcpy(written[0..length], buffer[0..length]);
        return true;
    }
} else struct {};

test "attached volume byte ranges reject overflow and out-of-image requests before I/O" {
    const std = @import("std");
    var volume = TransferSpy.Volume{};
    var bytes: [8]u8 = @splat(0xa5);
    TransferSpy.reset();
    for ([_]struct { offset: usize, length: usize }{
        .{ .offset = std.math.maxInt(usize), .length = 1 },
        .{ .offset = std.math.maxInt(usize) - 2, .length = bytes.len },
        .{ .offset = volume_layout.image_bytes + 1, .length = 0 },
        .{ .offset = volume_layout.image_bytes, .length = 1 },
        .{ .offset = volume_layout.image_bytes - 1, .length = 2 },
    }) |request| {
        try std.testing.expect(!readAttachedBytes(&volume, request.offset, bytes[0..request.length]));
        try std.testing.expect(!writeAttachedBytes(&volume, request.offset, bytes[0..request.length]));
        try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0xa5)), &bytes);
        try std.testing.expectEqual(@as(usize, 0), TransferSpy.reads);
        try std.testing.expectEqual(@as(usize, 0), TransferSpy.writes);
    }
    for ([_]usize{ 0, volume_layout.image_bytes }) |offset| {
        try std.testing.expect(readAttachedBytes(&volume, offset, bytes[0..0]));
        try std.testing.expect(writeAttachedBytes(&volume, offset, bytes[0..0]));
    }
    try std.testing.expectEqual(@as(usize, 0), TransferSpy.reads);
    try std.testing.expectEqual(@as(usize, 0), TransferSpy.writes);
}

test "attached volume exact-end partial and full-block transfers retain neighboring bytes" {
    const std = @import("std");
    var volume = TransferSpy.Volume{};
    var bytes: [volume_layout.sector_size]u8 = @splat(0x5a);
    TransferSpy.reset();
    try std.testing.expect(readAttachedBytes(&volume, volume_layout.image_bytes - 1, bytes[0..1]));
    try std.testing.expectEqual(@as(u8, 0xff), bytes[0]);
    try std.testing.expectEqual(@as(u64, volume_layout.required_device_sectors - 1), TransferSpy.last_lba);
    try std.testing.expectEqual(volume_layout.sector_size, TransferSpy.last_length);
    bytes[0] = 0x5a;
    try std.testing.expect(writeAttachedBytes(&volume, volume_layout.image_bytes - 1, bytes[0..1]));
    try std.testing.expectEqual(@as(usize, 2), TransferSpy.reads);
    try std.testing.expectEqual(@as(usize, 1), TransferSpy.writes);
    for (TransferSpy.written[0 .. volume_layout.sector_size - 1], 0..) |byte, index| {
        try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    }
    try std.testing.expectEqual(@as(u8, 0x5a), TransferSpy.written[volume_layout.sector_size - 1]);

    TransferSpy.reset();
    const offset = volume_layout.image_bytes - volume_layout.sector_size;
    try std.testing.expect(readAttachedBytes(&volume, offset, &bytes));
    for (bytes, 0..) |byte, index| try std.testing.expectEqual(@as(u8, @truncate(index)), byte);
    @memset(&bytes, 0x6b);
    try std.testing.expect(writeAttachedBytes(&volume, offset, &bytes));
    try std.testing.expectEqual(@as(usize, 1), TransferSpy.reads);
    try std.testing.expectEqual(@as(usize, 1), TransferSpy.writes);
    try std.testing.expectEqual(@as(u64, volume_layout.required_device_sectors - 1), TransferSpy.last_lba);
    try std.testing.expectEqual(volume_layout.sector_size, TransferSpy.last_length);
    try std.testing.expectEqualSlices(u8, &bytes, &TransferSpy.written);
}
