//! Non-transitional VirtIO PCI capability validation (OASIS VirtIO 1.2, 4.1).
const std = @import("std");

pub const VENDOR: u16 = 0x1AF4;
pub const NET_DEVICE: u16 = 0x1041;
pub const REQUIRED_FEATURES: u64 = (@as(u64, 1) << 5) | // MAC
    (@as(u64, 1) << 32) | // VERSION_1
    (@as(u64, 1) << 33); // ACCESS_PLATFORM: never bypass DMA translation
pub const Bar = @import("pci.zig").BarAperture;
pub const Region = struct {
    bar: u8,
    offset: u32,
    length: u32,

    pub fn physical(self: Region, bars: *const [6]Bar) u64 {
        return bars[self.bar].address + self.offset;
    }
};
pub const Layout = struct {
    common: Region,
    notify: Region,
    isr: Region,
    device: Region,
    msix_table: Region,
    msix_capability: u8,
    notify_multiplier: u32,

    pub fn notification(self: Layout, queue_offset: u16) Error!Region {
        const offset = std.math.mul(u32, queue_offset, self.notify_multiplier) catch return error.InvalidRegion;
        if (offset > self.notify.length or self.notify.length - offset < 2 or offset % 2 != 0) return error.InvalidRegion;
        return .{ .bar = self.notify.bar, .offset = self.notify.offset + offset, .length = 2 };
    }
};
pub const Error = error{ UnsupportedDevice, MalformedCapabilities, MissingCapability, InvalidRegion, MissingFeatures };

pub fn negotiate(features: u64) Error!u64 {
    if (features & REQUIRED_FEATURES != REQUIRED_FEATURES) return error.MissingFeatures;
    return REQUIRED_FEATURES;
}

pub fn parse(config: *const [256]u8, bars: *const [6]Bar) Error!Layout {
    if (u16At(config, 0) != VENDOR or u16At(config, 2) != NET_DEVICE or config[0x0E] & 0x7F != 0) return error.UnsupportedDevice;
    if (u16At(config, 6) & 0x10 == 0) return error.MissingCapability;
    var visited: u64 = 0;
    var regions: [5]?Region = .{ null, null, null, null, null };
    var msix: ?Region = null;
    var msix_pba: ?Region = null;
    var msix_capability: u8 = 0;
    var multiplier: u32 = 0;
    var offset: usize = config[0x34];
    while (offset != 0) {
        if (offset < 0x40 or offset > 0xFC or offset % 4 != 0) return error.MalformedCapabilities;
        const bit = @as(u64, 1) << @as(u6, @intCast(offset / 4));
        if (visited & bit != 0) return error.MalformedCapabilities;
        visited |= bit;
        var capability_length: usize = 4;
        switch (config[offset]) {
            0x09 => {
                const length: usize = config[offset + 2];
                if (length < 16 or length > config.len - offset) return error.MalformedCapabilities;
                capability_length = length;
                const kind = config[offset + 3];
                const bar = config[offset + 4];
                if (kind >= 1 and kind <= 4 and bar < bars.len and regions[kind] == null) {
                    const minimum: u32 = switch (kind) {
                        1 => 56,
                        2 => 2,
                        3 => 1,
                        4 => 6,
                        else => unreachable,
                    };
                    const region = Region{ .bar = bar, .offset = u32At(config, offset + 8), .length = u32At(config, offset + 12) };
                    try validate(region, bars, minimum, if (kind == 1) 4 else if (kind == 2) 2 else 1);
                    if (kind == 2) {
                        if (length < 20) return error.MalformedCapabilities;
                        multiplier = u32At(config, offset + 16);
                    }
                    regions[kind] = region;
                }
            },
            0x11 => {
                if (offset > config.len - 12 or msix != null) return error.MalformedCapabilities;
                capability_length = 12;
                const table = u32At(config, offset + 4);
                const count = @as(u32, u16At(config, offset + 2) & 0x7FF) + 1;
                const region = Region{ .bar = @intCast(table & 7), .offset = table & ~@as(u32, 7), .length = count * 16 };
                try validate(region, bars, 16, 8);
                // Validate PBA too, even though queue delivery only maps entry 0.
                const pba = u32At(config, offset + 8);
                msix_pba = .{ .bar = @intCast(pba & 7), .offset = pba & ~@as(u32, 7), .length = ((count + 63) / 64) * 8 };
                try validate(msix_pba.?, bars, 8, 8);
                msix = region;
                msix_capability = @intCast(offset);
            },
            else => {},
        }
        // A next pointer into an earlier capability's payload is malformed too.
        var word = offset / 4 + 1;
        while (word < (offset + capability_length + 3) / 4) : (word += 1) {
            const payload_bit = @as(u64, 1) << @as(u6, @intCast(word));
            if (visited & payload_bit != 0) return error.MalformedCapabilities;
            visited |= payload_bit;
        }
        offset = config[offset + 1];
    }
    const layout = Layout{
        .common = regions[1] orelse return error.MissingCapability,
        .notify = regions[2] orelse return error.MissingCapability,
        .isr = regions[3] orelse return error.MissingCapability,
        .device = regions[4] orelse return error.MissingCapability,
        .msix_table = msix orelse return error.MissingCapability,
        .msix_capability = msix_capability,
        .notify_multiplier = multiplier,
    };
    const windows = [_]Region{ layout.common, layout.notify, layout.isr, layout.device, layout.msix_table, msix_pba.? };
    for (windows, 0..) |region, index| {
        const address = region.physical(bars);
        for (windows[0..index]) |prior| {
            const prior_address = prior.physical(bars);
            if (address <= prior_address + prior.length - 1 and prior_address <= address + region.length - 1) return error.InvalidRegion;
        }
    }
    return layout;
}

fn validate(region: Region, bars: *const [6]Bar, minimum: u32, alignment: u32) Error!void {
    if (region.bar >= bars.len or region.length < minimum or region.offset % alignment != 0) return error.InvalidRegion;
    const bar = bars[region.bar];
    if (bar.address == 0 or bar.length == 0 or region.offset > bar.length or region.length > bar.length - region.offset) return error.InvalidRegion;
    _ = std.math.add(u64, bar.address, bar.length - 1) catch return error.InvalidRegion;
    _ = std.math.add(u32, region.offset, region.length - 1) catch return error.InvalidRegion;
}

fn u16At(bytes: *const [256]u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}
fn u32At(bytes: *const [256]u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn fixture() [256]u8 {
    var bytes = [_]u8{0} ** 256;
    std.mem.writeInt(u16, bytes[0..2], VENDOR, .little);
    std.mem.writeInt(u16, bytes[2..4], NET_DEVICE, .little);
    bytes[6] = 0x10;
    bytes[0x34] = 0x40;
    for (0..4) |i| {
        const offset = 0x40 + i * 20;
        bytes[offset] = 9;
        bytes[offset + 1] = @intCast(offset + 20);
        bytes[offset + 2] = 20;
        bytes[offset + 3] = @intCast(i + 1);
        std.mem.writeInt(u32, bytes[offset + 8 ..][0..4], @intCast(i * 0x100), .little);
        std.mem.writeInt(u32, bytes[offset + 12 ..][0..4], 0x100, .little);
    }
    std.mem.writeInt(u32, bytes[0x64..0x68], 4, .little);
    bytes[0x90] = 0x11;
    std.mem.writeInt(u32, bytes[0x94..0x98], 0x400, .little);
    std.mem.writeInt(u32, bytes[0x98..0x9C], 0x500, .little);
    return bytes;
}

test "virtio pci validates modern regions and bounds queue notifications" {
    const bytes = fixture();
    const bars = [_]Bar{.{ .address = 0x100000, .length = 4096 }} ** 6;
    const layout = try parse(&bytes, &bars);
    try std.testing.expectEqual(@as(u64, 0x100000), layout.common.physical(&bars));
    try std.testing.expectEqual(@as(u32, 0x104), (try layout.notification(1)).offset);
    try std.testing.expectError(error.InvalidRegion, layout.notification(64));
    try std.testing.expectEqual(REQUIRED_FEATURES, try negotiate(std.math.maxInt(u64)));
    for ([_]u6{ 5, 32, 33 }) |bit| try std.testing.expectError(error.MissingFeatures, negotiate(REQUIRED_FEATURES & ~(@as(u64, 1) << bit)));
}

test "virtio pci rejects truncated cyclic and escaping capabilities" {
    const bars = [_]Bar{.{ .address = 0x100000, .length = 4096 }} ** 6;
    var bytes = fixture();
    bytes[0x91] = 0x40;
    try std.testing.expectError(error.MalformedCapabilities, parse(&bytes, &bars));
    bytes = fixture();
    bytes[0x42] = 15;
    try std.testing.expectError(error.MalformedCapabilities, parse(&bytes, &bars));
    bytes = fixture();
    bytes[0x34] = 0xFD;
    try std.testing.expectError(error.MalformedCapabilities, parse(&bytes, &bars));
    bytes = fixture();
    std.mem.writeInt(u32, bytes[0x48..0x4C], 4096, .little);
    try std.testing.expectError(error.InvalidRegion, parse(&bytes, &bars));
    bytes = fixture();
    bytes[0x94] = 7;
    try std.testing.expectError(error.InvalidRegion, parse(&bytes, &bars));
    bytes = fixture();
    bytes[2] = 0;
    try std.testing.expectError(error.UnsupportedDevice, parse(&bytes, &bars));
    bytes = fixture();
    bytes[0x41] = 0x44;
    try std.testing.expectError(error.MalformedCapabilities, parse(&bytes, &bars));
    bytes = fixture();
    std.mem.writeInt(u32, bytes[0x5C..0x60], 0, .little);
    try std.testing.expectError(error.InvalidRegion, parse(&bytes, &bars));
}
