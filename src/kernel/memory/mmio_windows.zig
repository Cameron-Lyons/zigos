const std = @import("std");
const virtual_layout = @import("virtual_layout.zig");

pub const PAGE_BYTES = virtual_layout.PAGE_BYTES;

pub const Region = struct {
    base: usize,
    bytes: usize,

    pub fn endExclusive(self: Region) ?usize {
        return std.math.add(usize, self.base, self.bytes) catch null;
    }
};

pub const nvme = Region{
    .base = virtual_layout.device_memory.base,
    .bytes = 0x2000,
};

pub const pci_ecam = Region{
    .base = virtual_layout.device_memory.base + 0x1000_0000,
    .bytes = PAGE_BYTES,
};

pub const intel_i225 = Region{
    .base = virtual_layout.device_memory.base + 0x1100_0000,
    .bytes = 0x1_0000,
};

pub const xhci = Region{
    .base = virtual_layout.device_memory.base + 0x1200_0000,
    .bytes = PAGE_BYTES,
};

pub const acpi_root = Region{
    .base = virtual_layout.device_memory.base + 0x2000_0000,
    .bytes = 0x101_000,
};

pub const acpi_entry = Region{
    .base = virtual_layout.device_memory.base + 0x2020_0000,
    .bytes = 0x101_000,
};

pub const intel_vtd = Region{
    .base = virtual_layout.device_memory.base + 0x3000_0000,
    .bytes = 16 * 0x4000,
};

pub const all = [_]Region{
    nvme,
    pci_ecam,
    intel_i225,
    xhci,
    acpi_root,
    acpi_entry,
    intel_vtd,
};

pub fn validLayout(regions: []const Region) bool {
    const aperture_end = virtual_layout.device_memory.endExclusive() orelse return false;
    for (regions, 0..) |region, index| {
        if (region.base < virtual_layout.device_memory.base or
            region.base % PAGE_BYTES != 0 or
            region.bytes == 0 or
            region.bytes % PAGE_BYTES != 0)
        {
            return false;
        }
        const region_end = region.endExclusive() orelse return false;
        if (region_end > aperture_end) return false;
        for (regions[0..index]) |prior| {
            const prior_end = prior.endExclusive() orelse return false;
            if (region.base < prior_end and prior.base < region_end) return false;
        }
    }
    return true;
}

comptime {
    if (!validLayout(&all)) @compileError("kernel MMIO windows overlap or are invalid");
}

test "kernel MMIO windows are page aligned bounded and disjoint" {
    try std.testing.expect(validLayout(&all));
    try std.testing.expectEqual(virtual_layout.device_memory.base + 0x1000_1000, pci_ecam.endExclusive().?);
    try std.testing.expectEqual(virtual_layout.device_memory.base + 0x1101_0000, intel_i225.endExclusive().?);
    try std.testing.expect(pci_ecam.endExclusive().? <= intel_i225.base);
    try std.testing.expect(intel_i225.endExclusive().? <= xhci.base);
    try std.testing.expect(xhci.endExclusive().? <= acpi_root.base);
}

test "kernel MMIO layout rejects overlap misalignment and overflow" {
    const overlap = [_]Region{
        .{ .base = virtual_layout.device_memory.base, .bytes = PAGE_BYTES * 2 },
        .{ .base = virtual_layout.device_memory.base + PAGE_BYTES, .bytes = PAGE_BYTES },
    };
    try std.testing.expect(!validLayout(&overlap));

    const misaligned = [_]Region{
        .{ .base = virtual_layout.device_memory.base + 1, .bytes = PAGE_BYTES },
    };
    try std.testing.expect(!validLayout(&misaligned));

    const overflow = [_]Region{
        .{ .base = std.math.maxInt(usize) & ~(PAGE_BYTES - 1), .bytes = PAGE_BYTES * 2 },
    };
    try std.testing.expect(!validLayout(&overflow));
}
