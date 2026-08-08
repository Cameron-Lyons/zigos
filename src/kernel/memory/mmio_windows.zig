const std = @import("std");

pub const PAGE_BYTES: usize = 4096;
const KERNEL_CANONICAL_BASE: usize = 0xFFFF_8000_0000_0000;

pub const Region = struct {
    base: usize,
    bytes: usize,

    pub fn endExclusive(self: Region) ?usize {
        return std.math.add(usize, self.base, self.bytes) catch null;
    }
};

pub const nvme = Region{
    .base = 0xFFFF_8000_0000_0000,
    .bytes = 0x2000,
};

pub const pci_ecam = Region{
    .base = 0xFFFF_8000_1000_0000,
    .bytes = PAGE_BYTES,
};

pub const intel_i225 = Region{
    .base = 0xFFFF_8000_1100_0000,
    .bytes = 0x1_0000,
};

pub const xhci = Region{
    .base = 0xFFFF_8000_1200_0000,
    .bytes = PAGE_BYTES,
};

pub const acpi_root = Region{
    .base = 0xFFFF_8000_2000_0000,
    .bytes = 0x101_000,
};

pub const acpi_entry = Region{
    .base = 0xFFFF_8000_2020_0000,
    .bytes = 0x101_000,
};

pub const intel_vtd = Region{
    .base = 0xFFFF_8000_3000_0000,
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
    for (regions, 0..) |region, index| {
        if (region.base < KERNEL_CANONICAL_BASE or
            region.base % PAGE_BYTES != 0 or
            region.bytes == 0 or
            region.bytes % PAGE_BYTES != 0)
        {
            return false;
        }
        const region_end = region.endExclusive() orelse return false;
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
    try std.testing.expectEqual(@as(usize, 0xFFFF_8000_1000_1000), pci_ecam.endExclusive().?);
    try std.testing.expectEqual(@as(usize, 0xFFFF_8000_1101_0000), intel_i225.endExclusive().?);
    try std.testing.expect(pci_ecam.endExclusive().? <= intel_i225.base);
    try std.testing.expect(intel_i225.endExclusive().? <= xhci.base);
    try std.testing.expect(xhci.endExclusive().? <= acpi_root.base);
}

test "kernel MMIO layout rejects overlap misalignment and overflow" {
    const overlap = [_]Region{
        .{ .base = KERNEL_CANONICAL_BASE, .bytes = PAGE_BYTES * 2 },
        .{ .base = KERNEL_CANONICAL_BASE + PAGE_BYTES, .bytes = PAGE_BYTES },
    };
    try std.testing.expect(!validLayout(&overlap));

    const misaligned = [_]Region{
        .{ .base = KERNEL_CANONICAL_BASE + 1, .bytes = PAGE_BYTES },
    };
    try std.testing.expect(!validLayout(&misaligned));

    const overflow = [_]Region{
        .{ .base = std.math.maxInt(usize) & ~(PAGE_BYTES - 1), .bytes = PAGE_BYTES * 2 },
    };
    try std.testing.expect(!validLayout(&overflow));
}
