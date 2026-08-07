const std = @import("std");
const endian = @import("../utils/endian.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const tsc_clock = @import("../timer/tsc_clock.zig");
const pci = @import("pci.zig");
const xhci = @import("xhci.zig");

const PAGE_BYTES = mmio_windows.PAGE_BYTES;
const OWNERSHIP_TIMEOUT_MILLISECONDS: u64 = 1_000;
const OS_OWNED_BYTE_OFFSET: usize = 3;

comptime {
    if (xhci.CAPABILITY_REGISTERS_BYTES > mmio_windows.xhci.bytes) {
        @compileError("xHCI capability snapshot exceeds its reserved MMIO window");
    }
}

pub const Error = xhci.Error || error{
    NotXhciController,
    BarUnmappable,
    BarMisaligned,
    BarRangeOverflow,
    InvariantClockUnavailable,
};

var active_capabilities: ?xhci.CapabilityRegisters = null;
var active_legacy_ownership: ?xhci.LegacyOwnership = null;

pub fn probe(device_info: pci.PCIDevice) Error!xhci.CapabilityRegisters {
    active_capabilities = null;
    active_legacy_ownership = null;
    const bar = try validateBar(device_info);
    paging.mapKernelBorrowedPage(
        mmio_windows.xhci.base,
        bar.address,
        paging.PAGE_PRESENT | paging.PAGE_CACHE_DISABLE,
    );
    const snapshot = readCapabilitySnapshot(mmio_windows.xhci.base);
    const capabilities = try xhci.parseCapabilityRegisters(&snapshot);
    try validateExtendedCapabilityRange(bar.address, capabilities.extended_capability_offset);
    var reader = ExtendedCapabilityReader{ .bar_address = bar.address };
    const legacy = try xhci.findLegacySupport(capabilities.extended_capability_offset, &reader);
    const legacy_ownership = if (legacy) |support| ownership: {
        if (!tsc_clock.initialized()) return error.InvariantClockUnavailable;
        break :ownership try xhci.claimLegacyOwnership(
            support,
            &reader,
            tsc_clock.afterMilliseconds(OWNERSHIP_TIMEOUT_MILLISECONDS),
        );
    } else xhci.LegacyOwnership.not_present;
    active_capabilities = capabilities;
    active_legacy_ownership = legacy_ownership;
    return capabilities;
}

pub fn validated() bool {
    const ownership = active_legacy_ownership orelse return false;
    return active_capabilities != null and ownership != .firmware_released;
}

pub fn probedCapabilities() ?xhci.CapabilityRegisters {
    return active_capabilities;
}

pub fn probedLegacyOwnership() ?xhci.LegacyOwnership {
    return active_legacy_ownership;
}

fn validateBar(device_info: pci.PCIDevice) Error!pci.MemoryBar {
    if (!pci.isXhciController(device_info)) return error.NotXhciController;
    const bar = pci.memoryBar0(device_info) orelse return error.BarUnmappable;
    if (bar.address == 0) return error.BarUnmappable;
    if (bar.address % PAGE_BYTES != 0) return error.BarMisaligned;
    return bar;
}

fn validateExtendedCapabilityRange(bar_address: usize, first_offset: u32) Error!void {
    if (first_offset == 0) return;
    if (bar_address > std.math.maxInt(usize) - @as(usize, xhci.MAX_EXTENDED_CAPABILITY_OFFSET)) {
        return error.BarRangeOverflow;
    }
}

const ExtendedCapabilityReader = struct {
    bar_address: usize,
    mapped_page_offset: ?usize = null,
    mapped_writable: bool = false,

    pub fn readDword(self: *@This(), offset: u32) u32 {
        const byte_offset: usize = @intCast(offset);
        const page_offset = byte_offset & ~(PAGE_BYTES - 1);
        self.mapPage(page_offset, false);
        const page_byte_offset = byte_offset & (PAGE_BYTES - 1);
        return @as(*volatile u32, @ptrFromInt(mmio_windows.xhci.base + page_byte_offset)).*;
    }

    pub fn writeOsOwnedByte(self: *@This(), legacy_offset: u32, value: u8) void {
        const byte_offset = @as(usize, legacy_offset) + OS_OWNED_BYTE_OFFSET;
        const page_offset = byte_offset & ~(PAGE_BYTES - 1);
        self.mapPage(page_offset, true);
        const page_byte_offset = byte_offset & (PAGE_BYTES - 1);
        @as(*volatile u8, @ptrFromInt(mmio_windows.xhci.base + page_byte_offset)).* = value;
        self.mapPage(page_offset, false);
    }

    fn mapPage(self: *@This(), page_offset: usize, writable: bool) void {
        if (self.mapped_page_offset != null and
            self.mapped_page_offset.? == page_offset and
            self.mapped_writable == writable)
        {
            return;
        }
        paging.mapKernelBorrowedPage(
            mmio_windows.xhci.base,
            self.bar_address + page_offset,
            paging.PAGE_PRESENT |
                paging.PAGE_CACHE_DISABLE |
                (if (writable) paging.PAGE_WRITABLE else 0),
        );
        self.mapped_page_offset = page_offset;
        self.mapped_writable = writable;
    }
};

fn readCapabilitySnapshot(base: usize) [xhci.CAPABILITY_REGISTERS_BYTES]u8 {
    var snapshot = [_]u8{0} ** xhci.CAPABILITY_REGISTERS_BYTES;
    var offset: usize = 0;
    while (offset < snapshot.len) : (offset += @sizeOf(u32)) {
        const value = @as(*volatile u32, @ptrFromInt(base + offset)).*;
        endian.writeU32Le(snapshot[offset..][0..@sizeOf(u32)], value);
    }
    return snapshot;
}

fn validTestSnapshot() [xhci.CAPABILITY_REGISTERS_BYTES]u8 {
    var snapshot = [_]u8{0} ** xhci.CAPABILITY_REGISTERS_BYTES;
    snapshot[0] = 0x40;
    endian.writeU16Le(snapshot[2..4], 0x0110);
    endian.writeU32Le(snapshot[4..8], 32 | (@as(u32, 8) << 8) | (@as(u32, 12) << 24));
    endian.writeU32Le(snapshot[0x10..0x14], @as(u32, 0x2000) << 16);
    endian.writeU32Le(snapshot[0x14..0x18], 0x2000);
    endian.writeU32Le(snapshot[0x18..0x1C], 0x1000);
    return snapshot;
}

fn testDevice(bar0: u32, bar1: u32) pci.PCIDevice {
    return .{
        .bus = 0,
        .device = 20,
        .function = 0,
        .vendor_id = pci.PCI_VENDOR_INTEL,
        .device_id = 0xA0ED,
        .class_code = pci.PCI_CLASS_SERIAL_BUS_CONTROLLER,
        .subclass = pci.PCI_SUBCLASS_USB,
        .prog_if = pci.PCI_PROG_IF_XHCI,
        .bar0 = bar0,
        .bar1 = bar1,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
    };
}

test "xHCI hardware probe validates the controller and BAR before MMIO mapping" {
    const device = testDevice(0xFEB0_0004, 0);
    const bar = try validateBar(device);
    try std.testing.expectEqual(@as(usize, 0xFEB0_0000), bar.address);
    try std.testing.expectEqual(pci.MemoryBarWidth.bits64, bar.width);

    var non_xhci = device;
    non_xhci.prog_if = 0x20;
    try std.testing.expectError(error.NotXhciController, validateBar(non_xhci));
    try std.testing.expectError(error.BarUnmappable, validateBar(testDevice(1, 0)));
    try std.testing.expectError(error.BarMisaligned, validateBar(testDevice(0xFEB0_0104, 0)));
}

test "xHCI hardware capability snapshot uses the shared modern parser" {
    const snapshot = validTestSnapshot();
    const capabilities = try xhci.parseCapabilityRegisters(&snapshot);
    try std.testing.expectEqual(@as(u16, 0x0110), capabilities.interface_version);
    try std.testing.expectEqual(@as(u8, 32), capabilities.max_device_slots);
    try std.testing.expectEqual(@as(u8, 12), capabilities.max_ports);
    try std.testing.expectEqual(@as(u32, 0x8000), capabilities.extended_capability_offset);
}

test "xHCI hardware probe bounds extended capability BAR arithmetic" {
    try validateExtendedCapabilityRange(0xFEB0_0000, 0x8000);
    try validateExtendedCapabilityRange(std.math.maxInt(usize), 0);
    try std.testing.expectError(
        error.BarRangeOverflow,
        validateExtendedCapabilityRange(std.math.maxInt(usize), 0x8000),
    );
}
