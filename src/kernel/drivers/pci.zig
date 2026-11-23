const builtin = @import("builtin");
const std = @import("std");
const table_backing = @import("../../native/core/table_backing.zig");
const spin = @import("../utils/spin.zig");
const mmio_windows = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const mcfg = @import("../platform/mcfg.zig");

const ECAM_BUS_SHIFT: u6 = 20;
const ECAM_DEVICE_SHIFT: u6 = 15;
const ECAM_FUNCTION_SHIFT: u6 = 12;
const ECAM_FUNCTION_BYTES: usize = 1 << ECAM_FUNCTION_SHIFT;
const ECAM_BUS_BYTES: usize = 1 << ECAM_BUS_SHIFT;
const ECAM_CONFIG_OFFSET_MASK: u16 = ECAM_FUNCTION_BYTES - 1;
const MAPPED_BUS_BUDGET: usize = mmio_windows.pci_ecam.bytes / ECAM_BUS_BYTES;
const UNMAPPED_BUS_SLOT: u8 = std.math.maxInt(u8);

const PCI_MAX_BUS_COUNT: u16 = 256;
const PCI_MAX_DEVICE_COUNT: u8 = 32;
const PCI_MAX_FUNCTION_COUNT: u8 = 8;
const PCI_VENDOR_DEVICE_OFFSET: u16 = 0x00;
const PCI_CLASS_INFO_OFFSET: u16 = 0x08;
const PCI_HEADER_TYPE_OFFSET: u16 = 0x0E;
const PCI_SECONDARY_BUS_OFFSET: u16 = 0x19;
const PCI_BAR0_OFFSET: u16 = 0x10;
const PCI_BAR1_OFFSET: u16 = 0x14;
const PCI_COMMAND_OFFSET: u16 = 0x04;
const PCI_STATUS_OFFSET: u16 = 0x06;
const PCI_COMMAND_IO_SPACE: u16 = 1 << 0;
const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
const PCI_COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;
const PCI_BAR_IO_SPACE: u32 = 1 << 0;
const PCI_BAR_MEMORY_TYPE_MASK: u32 = 0x6;
const PCI_BAR_MEMORY_TYPE_32: u32 = 0;
const PCI_BAR_MEMORY_TYPE_64: u32 = 0x4;
const PCI_BAR_ADDRESS_MASK: u32 = 0xFFFF_FFF0;
const PCI_STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
const PCI_CAPABILITY_POINTER_OFFSET: u16 = 0x34;
const PCI_CARDBUS_CAPABILITY_POINTER_OFFSET: u16 = 0x14;
const PCI_HEADER_TYPE_MASK: u8 = 0x7F;
const PCI_HEADER_TYPE_CARDBUS: u8 = 0x02;
const PCI_CAPABILITY_MIN_OFFSET: u8 = 0x40;
const PCI_CAPABILITY_MAX_OFFSET: u8 = 0xFC;
const PCI_CAPABILITY_MSI: u8 = 0x05;
const PCI_CAPABILITY_MSIX: u8 = 0x11;
const PCI_MSI_ENABLE: u16 = 1 << 0;
const PCI_MSI_MULTI_MESSAGE_ENABLE_MASK: u16 = 0x7 << 4;
const PCI_MSI_64_BIT_CAPABLE: u16 = 1 << 7;
const PCI_MSI_PER_VECTOR_MASK_CAPABLE: u16 = 1 << 8;
const PCI_MSIX_FUNCTION_MASK: u16 = 1 << 14;
const PCI_MSIX_ENABLE: u16 = 1 << 15;
const PCI_MSIX_TABLE_SIZE_MASK: u16 = 0x7FF;
const PCI_MSIX_TABLE_BIR_MASK: u32 = 0x7;
const PCI_MSIX_VECTOR_MASKED: u32 = 1 << 0;

const PCI_ABSENT_VENDOR_ID: u16 = 0xFFFF;
const PCI_MULTI_FUNCTION_FLAG: u8 = 0x80;
const PCI_CLASS_BRIDGE: u8 = 0x06;
const PCI_SUBCLASS_PCI_TO_PCI: u8 = 0x04;
const PCI_INVENTORY_CAPACITY: usize = 256;
const PCI_U8_MASK: u32 = 0xFF;
const PCI_U16_MASK: u32 = 0xFFFF;
const PCI_DEVICE_ID_SHIFT = 16;
const PCI_CLASS_CODE_SHIFT = 24;
const PCI_SUBCLASS_SHIFT = 16;
const PCI_PROG_IF_SHIFT = 8;
const STABLE_VENDOR_ID_SHIFT = 32;
const STABLE_DEVICE_ID_SHIFT = 16;
const STABLE_BUS_SHIFT = 8;
const STABLE_DEVICE_SHIFT = 3;

comptime {
    if (mmio_windows.pci_ecam.bytes % ECAM_BUS_BYTES != 0 or MAPPED_BUS_BUDGET == 0 or
        MAPPED_BUS_BUDGET >= UNMAPPED_BUS_SLOT)
    {
        @compileError("PCI ECAM bus window must hold a whole number of bounded bus slots");
    }
    if (ECAM_FUNCTION_BYTES > mmio_windows.pci_ecam_scratch.bytes) {
        @compileError("PCI ECAM scratch window is smaller than one configuration function");
    }
}

pub const PCIDevice = struct {
    bus: u8,
    device: u8,
    function: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    bar0: u32,
    bar1: u32,
};

const PCI_DEVICE_SIZE_CEILING_BYTES: usize = 20;
const PCI_INVENTORY_SIZE_CEILING_BYTES: usize = 5_120;

pub const MemoryBarWidth = enum {
    bits32,
    bits64,
};

pub const MemoryBar = struct {
    address: usize,
    width: MemoryBarWidth,
};

pub const BarAperture = struct { address: u64 = 0, length: u64 = 0 };

pub const BarProbeError = error{ UnsafeBarProbe, InvalidBar };

/// Size endpoint BARs only while DMA and address decoding are stopped. The
/// configuration lock spans the destructive sizing writes and their restoration.
pub fn probeMemoryBars(dev: PCIDevice) BarProbeError![6]BarAperture {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const command = try beginBarProbeUnlocked(dev);
    defer writeUnlocked(u16, dev, PCI_COMMAND_OFFSET, command);
    var bars = @as([6]BarAperture, @splat(.{}));
    var index: u16 = 0;
    while (index < 6) : (index += 1) {
        const sized = try sizeBarUnlocked(dev, index);
        bars[index] = sized.aperture;
        if (sized.wide) index += 1;
    }
    return bars;
}

pub const BarAdmissionError = BarProbeError || error{ BusMasteringNotRevoked, BarUnmappable };

/// Admit the memory BAR0 aperture a driver maps: bus mastering must already be
/// revoked, and the sized aperture must match the decoded BAR0 address and
/// cover at least `min_bytes`. Only BAR0 (with BAR1 for a 64-bit BAR0) is sized.
pub fn admitMemoryBar0(dev: PCIDevice, min_bytes: u64) BarAdmissionError!BarAperture {
    if (busMasteringEnabled(dev)) return error.BusMasteringNotRevoked;
    const bar = memoryBar0(dev) orelse return error.BarUnmappable;
    const aperture = aperture: {
        acquireConfigurationLock();
        defer releaseConfigurationLock();
        const command = try beginBarProbeUnlocked(dev);
        defer writeUnlocked(u16, dev, PCI_COMMAND_OFFSET, command);
        break :aperture (try sizeBarUnlocked(dev, 0)).aperture;
    };
    if (bar.address == 0 or aperture.address != bar.address or aperture.length < min_bytes) return error.BarUnmappable;
    return aperture;
}

fn beginBarProbeUnlocked(dev: PCIDevice) BarProbeError!u16 {
    const command = readUnlocked(u16, dev, PCI_COMMAND_OFFSET);
    if (command & PCI_COMMAND_BUS_MASTER != 0 or
        readUnlocked(u8, dev, PCI_HEADER_TYPE_OFFSET) & PCI_HEADER_TYPE_MASK != 0) return error.UnsafeBarProbe;
    writeUnlocked(u16, dev, PCI_COMMAND_OFFSET, command & ~(PCI_COMMAND_IO_SPACE | PCI_COMMAND_MEMORY_SPACE));
    return command;
}

const SizedBar = struct { aperture: BarAperture = .{}, wide: bool = false };

fn sizeBarUnlocked(dev: PCIDevice, index: u16) BarProbeError!SizedBar {
    const offset: u16 = PCI_BAR0_OFFSET + index * 4;
    const low = readUnlocked(u32, dev, offset);
    if (low & PCI_BAR_IO_SPACE != 0) return .{};
    const wide = low & PCI_BAR_MEMORY_TYPE_MASK == PCI_BAR_MEMORY_TYPE_64;
    if ((low & PCI_BAR_MEMORY_TYPE_MASK != 0 and !wide) or (wide and index == 5)) return error.InvalidBar;
    const high = if (wide) readUnlocked(u32, dev, offset + 4) else 0;
    writeUnlocked(u32, dev, offset, 0xFFFF_FFFF);
    if (wide) writeUnlocked(u32, dev, offset + 4, 0xFFFF_FFFF);
    const mask_low = readUnlocked(u32, dev, offset) & PCI_BAR_ADDRESS_MASK;
    const mask_high = if (wide) readUnlocked(u32, dev, offset + 4) else 0xFFFF_FFFF;
    writeUnlocked(u32, dev, offset, low);
    if (wide) writeUnlocked(u32, dev, offset + 4, high);
    if (mask_low == 0 and !(wide and mask_high != 0)) return .{ .wide = wide };
    const mask = (@as(u64, mask_high) << 32) | mask_low;
    const length = std.math.add(u64, ~mask, 1) catch return error.InvalidBar;
    const address = (@as(u64, high) << 32) | (low & PCI_BAR_ADDRESS_MASK);
    if (!std.math.isPowerOfTwo(length) or address == 0 or address % length != 0) return error.InvalidBar;
    _ = std.math.add(u64, address, length - 1) catch return error.InvalidBar;
    return .{ .aperture = .{ .address = address, .length = length }, .wide = wide };
}

pub fn enableMemoryDecoding(dev: PCIDevice) void {
    const command = readConfigWord(dev.bus, dev.device, dev.function, PCI_COMMAND_OFFSET);
    writeConfigWord(dev.bus, dev.device, dev.function, PCI_COMMAND_OFFSET, command | PCI_COMMAND_MEMORY_SPACE);
}

pub const PCI_CLASS_STORAGE_CONTROLLER: u8 = 0x01;
pub const PCI_SUBCLASS_NVM: u8 = 0x08;
pub const PCI_PROG_IF_NVME: u8 = 0x02;
pub const PCI_CLASS_NETWORK_ADAPTER: u8 = 0x02;
pub const PCI_CLASS_SERIAL_BUS_CONTROLLER: u8 = 0x0C;
pub const PCI_SUBCLASS_USB: u8 = 0x03;
pub const PCI_PROG_IF_XHCI: u8 = 0x30;
pub const PCI_VENDOR_INTEL: u16 = 0x8086;
pub const PCI_DEVICE_INTEL_I225_LM: u16 = 0x15F2;

const PciInventory = [PCI_INVENTORY_CAPACITY]PCIDevice;
var boot_inventory: table_backing.Lazy(PciInventory, null) = .{};
var boot_inventory_count: usize = 0;
var boot_inventory_initialized = false;
var boot_inventory_valid = false;
var ecam_allocation: ?mcfg.Allocation = null;
// Discovered buses stay mapped for the kernel lifetime, so configuration
// access is plain address arithmetic on any CPU and in any context. Buses
// beyond the window budget share one remapped scratch function page.
var bus_slots = @as([PCI_MAX_BUS_COUNT]u8, @splat(UNMAPPED_BUS_SLOT));
var mapped_bus_count: usize = 0;
var scratch_function_page: ?usize = null;
var configuration_lock = spin.Lock.init();

comptime {
    if (@sizeOf(PCIDevice) > PCI_DEVICE_SIZE_CEILING_BYTES) {
        @compileError("cached PCI device record exceeds its compact size ceiling");
    }
    if (@sizeOf(PciInventory) > PCI_INVENTORY_SIZE_CEILING_BYTES) {
        @compileError("cached PCI inventory exceeds its compact size ceiling");
    }
}

pub const InitError = error{InvalidEcamAllocation} || paging.DeviceMapError;
pub const QuiesceError = error{
    MalformedCapabilityList,
    InterruptDisableFailed,
};
pub const MsiError = error{
    MalformedCapabilityList,
    MsiCapabilityMissing,
    MessageAddressUnsupported,
    MsiEnableFailed,
    InterruptDisableFailed,
};

pub const MsiMessage = struct {
    address: u64,
    data: u16,
};

pub fn init(allocation: mcfg.Allocation) InitError!void {
    if (allocation.segment_group != 0 or allocation.start_bus != 0 or
        allocation.start_bus > allocation.end_bus or
        allocation.base_address == 0 or allocation.base_address % mcfg.ECAM_BUS_BYTES != 0)
    {
        return error.InvalidEcamAllocation;
    }
    const span = std.math.mul(u64, allocation.busCount(), mcfg.ECAM_BUS_BYTES) catch
        return error.InvalidEcamAllocation;
    const last_address = std.math.add(u64, allocation.base_address, span - 1) catch
        return error.InvalidEcamAllocation;
    _ = std.math.cast(usize, last_address) orelse return error.InvalidEcamAllocation;
    // Bus slots are mapped for the kernel lifetime against one allocation.
    if (ecam_allocation != null) return error.InvalidEcamAllocation;

    if (comptime builtin.target.os.tag == .freestanding) try paging.registerPciEcam(allocation);

    releaseBootInventory();
    ecam_allocation = allocation;
    boot_inventory_count = 0;
    boot_inventory_initialized = false;
    boot_inventory_valid = false;
}

pub fn ecamPhysicalAddress(
    allocation: mcfg.Allocation,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
) ?usize {
    if (!allocation.containsBus(bus) or device >= PCI_MAX_DEVICE_COUNT or
        function >= PCI_MAX_FUNCTION_COUNT or offset > ECAM_CONFIG_OFFSET_MASK)
    {
        return null;
    }
    const bus_offset = @as(u64, bus - allocation.start_bus) << ECAM_BUS_SHIFT;
    const device_offset = @as(u64, device) << ECAM_DEVICE_SHIFT;
    const function_offset = @as(u64, function) << ECAM_FUNCTION_SHIFT;
    const address = std.math.add(
        u64,
        allocation.base_address,
        bus_offset | device_offset | function_offset | offset,
    ) catch return null;
    return std.math.cast(usize, address);
}

fn acquireConfigurationLock() void {
    configuration_lock.acquire();
}

fn releaseConfigurationLock() void {
    configuration_lock.release();
}

/// Map a whole discovered bus once, before its functions are probed. Fresh
/// absent-to-present leaves need no remote shootdown, and no remap follows.
fn mapBus(bus: u8) void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    if (bus_slots[bus] != UNMAPPED_BUS_SLOT or mapped_bus_count == MAPPED_BUS_BUDGET) return;
    const allocation = ecam_allocation orelse return;
    const physical = ecamPhysicalAddress(allocation, bus, 0, 0, 0) orelse return;
    paging.mapKernelDeviceRange(
        mmio_windows.pci_ecam.base + mapped_bus_count * ECAM_BUS_BYTES,
        physical,
        ECAM_BUS_BYTES,
        true,
    ) catch return;
    bus_slots[bus] = @intCast(mapped_bus_count);
    mapped_bus_count += 1;
}

/// ECAM accesses are naturally aligned 1, 2 or 4 byte loads and stores, so a
/// narrow COMMAND write never rewrites the write-one-to-clear STATUS bits.
fn configAddress(dev: PCIDevice, offset: u16, size: u16) ?usize {
    if (offset % size != 0) return null;
    const allocation = ecam_allocation orelse return null;
    const physical_address = ecamPhysicalAddress(allocation, dev.bus, dev.device, dev.function, offset) orelse return null;
    const slot = bus_slots[dev.bus];
    if (slot != UNMAPPED_BUS_SLOT) {
        return mmio_windows.pci_ecam.base + @as(usize, slot) * ECAM_BUS_BYTES +
            (physical_address & (ECAM_BUS_BYTES - 1));
    }
    const physical_page = physical_address & ~(ECAM_FUNCTION_BYTES - 1);
    if (scratch_function_page != physical_page) {
        paging.mapKernelDeviceRange(
            mmio_windows.pci_ecam_scratch.base,
            physical_page,
            ECAM_FUNCTION_BYTES,
            true,
        ) catch return null;
        scratch_function_page = physical_page;
    }
    return mmio_windows.pci_ecam_scratch.base + (physical_address & (ECAM_FUNCTION_BYTES - 1));
}

inline fn readUnlocked(comptime T: type, dev: PCIDevice, offset: u16) T {
    const address = configAddress(dev, offset, @sizeOf(T)) orelse return std.math.maxInt(T);
    return @as(*volatile T, @ptrFromInt(address)).*;
}

inline fn writeUnlocked(comptime T: type, dev: PCIDevice, offset: u16, value: T) void {
    const address = configAddress(dev, offset, @sizeOf(T)) orelse return;
    @as(*volatile T, @ptrFromInt(address)).* = value;
}

inline fn readLocked(comptime T: type, dev: PCIDevice, offset: u16) T {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    return readUnlocked(T, dev, offset);
}

inline fn writeLocked(comptime T: type, dev: PCIDevice, offset: u16, value: T) void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    writeUnlocked(T, dev, offset, value);
}

inline fn locator(bus: u8, device: u8, function: u8) PCIDevice {
    return .{
        .bus = bus,
        .device = device,
        .function = function,
        .vendor_id = 0,
        .device_id = 0,
        .class_code = 0,
        .subclass = 0,
        .prog_if = 0,
        .bar0 = 0,
        .bar1 = 0,
    };
}

pub fn readConfig(bus: u8, device: u8, function: u8, offset: u16) u32 {
    return readLocked(u32, locator(bus, device, function), offset);
}

pub fn writeConfig(bus: u8, device: u8, function: u8, offset: u16, value: u32) void {
    writeLocked(u32, locator(bus, device, function), offset, value);
}

pub fn readConfigByte(bus: u8, device: u8, function: u8, offset: u16) u8 {
    return readLocked(u8, locator(bus, device, function), offset);
}

pub fn readConfigWord(bus: u8, device: u8, function: u8, offset: u16) u16 {
    return readLocked(u16, locator(bus, device, function), offset);
}

pub fn writeConfigWord(bus: u8, device: u8, function: u8, offset: u16, value: u16) void {
    writeLocked(u16, locator(bus, device, function), offset, value);
}

pub fn checkDevice(bus: u8, device: u8, func: u8) ?PCIDevice {
    const vendor_device = readConfig(bus, device, func, PCI_VENDOR_DEVICE_OFFSET);
    const vendor_id: u16 = @intCast(vendor_device & PCI_U16_MASK);

    if (vendor_id == PCI_ABSENT_VENDOR_ID) {
        return null;
    }

    const device_id: u16 = @intCast((vendor_device >> PCI_DEVICE_ID_SHIFT) & PCI_U16_MASK);
    const class_info = readConfig(bus, device, func, PCI_CLASS_INFO_OFFSET);

    const pci_device = PCIDevice{
        .bus = bus,
        .device = device,
        .function = func,
        .vendor_id = vendor_id,
        .device_id = device_id,
        .class_code = @intCast((class_info >> PCI_CLASS_CODE_SHIFT) & PCI_U8_MASK),
        .subclass = @intCast((class_info >> PCI_SUBCLASS_SHIFT) & PCI_U8_MASK),
        .prog_if = @intCast((class_info >> PCI_PROG_IF_SHIFT) & PCI_U8_MASK),
        .bar0 = readConfig(bus, device, func, PCI_BAR0_OFFSET),
        .bar1 = readConfig(bus, device, func, PCI_BAR1_OFFSET),
    };

    return pci_device;
}

const VendorDeviceQuery = struct {
    vendor_id: u16,
    device_id: u16,
};

const ClassQuery = struct {
    class_code: u8,
};

const ClassSubclassProgIfQuery = struct {
    class_code: u8,
    subclass: u8,
    prog_if: u8,
};

const StableIdQuery = struct {
    device_id: u64,
};

fn matchesVendorDevice(query: VendorDeviceQuery, device_info: PCIDevice) bool {
    return device_info.vendor_id == query.vendor_id and device_info.device_id == query.device_id;
}

fn matchesClassOnly(query: ClassQuery, device_info: PCIDevice) bool {
    return device_info.class_code == query.class_code;
}

fn matchesClassSubclassProgIfQuery(query: ClassSubclassProgIfQuery, device_info: PCIDevice) bool {
    return matchesClass(device_info, query.class_code, query.subclass, query.prog_if);
}

fn matchesStableId(query: StableIdQuery, device_info: PCIDevice) bool {
    return stableDeviceId(device_info) == query.device_id;
}

fn deviceHasMultipleFunctions(bus: u8, device: u8) bool {
    return (readConfigByte(bus, device, 0, PCI_HEADER_TYPE_OFFSET) & PCI_MULTI_FUNCTION_FLAG) != 0;
}

fn isPciBridge(device_info: PCIDevice) bool {
    return device_info.class_code == PCI_CLASS_BRIDGE and
        device_info.subclass == PCI_SUBCLASS_PCI_TO_PCI;
}

fn bootInventory() ?*PciInventory {
    return boot_inventory.get();
}

fn ensureBootInventory() ?*PciInventory {
    return boot_inventory.ensure() catch null;
}

fn releaseBootInventory() void {
    boot_inventory.release();
}

fn appendBootDevice(inventory: *PciInventory, device_info: PCIDevice) bool {
    if (boot_inventory_count == inventory.len) return false;
    inventory[boot_inventory_count] = device_info;
    boot_inventory_count += 1;
    return true;
}

fn enqueueSecondaryBus(
    device_info: PCIDevice,
    visited: *[PCI_MAX_BUS_COUNT]bool,
    queue: *[PCI_MAX_BUS_COUNT]u8,
    queue_tail: *usize,
) bool {
    if (!isPciBridge(device_info)) return true;
    const secondary_bus = readConfigByte(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_SECONDARY_BUS_OFFSET,
    );
    if (secondary_bus == 0 or visited[secondary_bus]) return true;
    if (queue_tail.* == queue.len) return false;
    visited[secondary_bus] = true;
    queue[queue_tail.*] = secondary_bus;
    queue_tail.* += 1;
    return true;
}

fn buildBootInventory() void {
    if (boot_inventory_initialized) return;
    boot_inventory_initialized = true;
    boot_inventory_count = 0;
    boot_inventory_valid = false;
    const inventory = ensureBootInventory() orelse return;

    var visited = @as([PCI_MAX_BUS_COUNT]bool, @splat(false));
    var queue = @as([PCI_MAX_BUS_COUNT]u8, @splat(0));
    var queue_head: usize = 0;
    var queue_tail: usize = 1;
    visited[0] = true;

    while (queue_head < queue_tail) : (queue_head += 1) {
        const bus = queue[queue_head];
        mapBus(bus);
        var device: u8 = 0;
        while (device < PCI_MAX_DEVICE_COUNT) : (device += 1) {
            const function_zero = checkDevice(bus, device, 0) orelse continue;
            if (!appendBootDevice(inventory, function_zero) or
                !enqueueSecondaryBus(function_zero, &visited, &queue, &queue_tail))
            {
                boot_inventory_count = 0;
                return;
            }
            if (!deviceHasMultipleFunctions(bus, device)) continue;

            var function: u8 = 1;
            while (function < PCI_MAX_FUNCTION_COUNT) : (function += 1) {
                const device_info = checkDevice(bus, device, function) orelse continue;
                if (!appendBootDevice(inventory, device_info) or
                    !enqueueSecondaryBus(device_info, &visited, &queue, &queue_tail))
                {
                    boot_inventory_count = 0;
                    return;
                }
            }
        }
    }
    boot_inventory_valid = true;
}

fn bootDevices() []const PCIDevice {
    buildBootInventory();
    if (!boot_inventory_valid) return &.{};
    const inventory = bootInventory() orelse return &.{};
    return inventory[0..boot_inventory_count];
}

pub fn disableBusMastering(device_info: PCIDevice) void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const command = readUnlocked(u16, device_info, PCI_COMMAND_OFFSET);
    writeUnlocked(
        u16,
        device_info,
        PCI_COMMAND_OFFSET,
        (command & ~PCI_COMMAND_BUS_MASTER) | PCI_COMMAND_INTERRUPT_DISABLE,
    );
}

const BUS_MASTER_COMMAND = PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER;
pub const BusMasterError = error{ ConfigurationUnavailable, BusMasterEnableFailed };

pub fn enableMemoryBusMastering(device_info: PCIDevice) BusMasterError!void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const command = readUnlocked(u16, device_info, PCI_COMMAND_OFFSET);
    if (command == std.math.maxInt(u16)) return error.ConfigurationUnavailable;
    writeUnlocked(u16, device_info, PCI_COMMAND_OFFSET, command | BUS_MASTER_COMMAND);
    try verifyBusMasterCommand(readUnlocked(u16, device_info, PCI_COMMAND_OFFSET));
}

fn verifyBusMasterCommand(observed: u16) BusMasterError!void {
    if (observed == std.math.maxInt(u16)) return error.ConfigurationUnavailable;
    if (observed & BUS_MASTER_COMMAND != BUS_MASTER_COMMAND) return error.BusMasterEnableFailed;
}

test "PCI bus mastering requires verified memory decoding and DMA enable" {
    try verifyBusMasterCommand(0x0406);
    try std.testing.expectError(error.ConfigurationUnavailable, verifyBusMasterCommand(std.math.maxInt(u16)));
    for ([_]u16{ PCI_COMMAND_MEMORY_SPACE, PCI_COMMAND_BUS_MASTER }) |rejected| {
        try std.testing.expectError(error.BusMasterEnableFailed, verifyBusMasterCommand(0x0406 & ~rejected));
    }
}

pub fn busMasteringEnabled(device_info: PCIDevice) bool {
    return (readConfigWord(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_COMMAND_OFFSET,
    ) & PCI_COMMAND_BUS_MASTER) != 0;
}

pub fn revokeBootBusMasters() usize {
    var revoked: usize = 0;
    for (bootDevices()) |device_info| {
        const was_enabled = busMasteringEnabled(device_info);
        disableBusMastering(device_info);
        if (was_enabled and !busMasteringEnabled(device_info)) revoked += 1;
    }
    return revoked;
}

fn messageInterruptControl(capability_id: u8, control: u16) ?struct { enabled: bool, disabled: u16 } {
    return switch (capability_id) {
        PCI_CAPABILITY_MSI => .{
            .enabled = (control & PCI_MSI_ENABLE) != 0,
            .disabled = control & ~PCI_MSI_ENABLE,
        },
        PCI_CAPABILITY_MSIX => .{
            .enabled = (control & PCI_MSIX_ENABLE) != 0,
            .disabled = (control | PCI_MSIX_FUNCTION_MASK) & ~PCI_MSIX_ENABLE,
        },
        else => null,
    };
}

const Capability = struct {
    id: u8,
    offset: u8,
};

const CapabilityIterator = struct {
    device_info: PCIDevice,
    offset: u8,
    visited: u64 = 0,

    fn init(device_info: PCIDevice) CapabilityIterator {
        if ((readConfigWord(
            device_info.bus,
            device_info.device,
            device_info.function,
            PCI_STATUS_OFFSET,
        ) & PCI_STATUS_CAPABILITIES_LIST) == 0) {
            return .{ .device_info = device_info, .offset = 0 };
        }
        const header_type = readConfigByte(
            device_info.bus,
            device_info.device,
            device_info.function,
            PCI_HEADER_TYPE_OFFSET,
        ) & PCI_HEADER_TYPE_MASK;
        const pointer_offset: u16 = if (header_type == PCI_HEADER_TYPE_CARDBUS)
            PCI_CARDBUS_CAPABILITY_POINTER_OFFSET
        else
            PCI_CAPABILITY_POINTER_OFFSET;
        return .{
            .device_info = device_info,
            .offset = readConfigByte(
                device_info.bus,
                device_info.device,
                device_info.function,
                pointer_offset,
            ),
        };
    }

    fn next(self: *CapabilityIterator) error{MalformedCapabilityList}!?Capability {
        if (self.offset == 0) return null;
        const offset = self.offset;
        if (offset < PCI_CAPABILITY_MIN_OFFSET or offset > PCI_CAPABILITY_MAX_OFFSET or
            offset & 3 != 0)
        {
            return error.MalformedCapabilityList;
        }
        const slot: u6 = @intCast(offset >> 2);
        const slot_bit = @as(u64, 1) << slot;
        if ((self.visited & slot_bit) != 0) return error.MalformedCapabilityList;
        self.visited |= slot_bit;
        self.offset = readConfigByte(
            self.device_info.bus,
            self.device_info.device,
            self.device_info.function,
            @as(u16, offset) + 1,
        );
        return .{
            .id = readConfigByte(
                self.device_info.bus,
                self.device_info.device,
                self.device_info.function,
                offset,
            ),
            .offset = offset,
        };
    }
};

const MsiLayout = struct {
    data_offset: u16,
    mask_offset: ?u16,
};

fn msiLayout(capability_offset: u8, control: u16) ?MsiLayout {
    const base: u16 = capability_offset;
    const address_bytes: u16 = if ((control & PCI_MSI_64_BIT_CAPABLE) != 0) 12 else 8;
    const data_offset = base + address_bytes;
    const mask_offset: ?u16 = if ((control & PCI_MSI_PER_VECTOR_MASK_CAPABLE) != 0)
        data_offset + 4
    else
        null;
    const end = if (mask_offset) |offset| offset + 4 else data_offset + 2;
    if (end > 0x100) return null;
    return .{ .data_offset = data_offset, .mask_offset = mask_offset };
}

fn findCapabilityOffset(device_info: PCIDevice, wanted_id: u8) MsiError!?u8 {
    var capabilities = CapabilityIterator.init(device_info);
    while (try capabilities.next()) |capability| {
        if (capability.id == wanted_id) return capability.offset;
    }
    return null;
}

pub fn hasMsi(device_info: PCIDevice) MsiError!bool {
    return try findCapabilityOffset(device_info, PCI_CAPABILITY_MSI) != null;
}

pub fn hasMsix(device_info: PCIDevice) MsiError!bool {
    return try findCapabilityOffset(device_info, PCI_CAPABILITY_MSIX) != null;
}

pub fn enableSingleMsi(device_info: PCIDevice, message: MsiMessage) MsiError!void {
    const capability = try findCapabilityOffset(device_info, PCI_CAPABILITY_MSI) orelse
        return error.MsiCapabilityMissing;
    const control_offset = @as(u16, capability) + 2;
    const address_offset = @as(u16, capability) + 4;
    const control = readLocked(u16, device_info, control_offset);
    const layout = msiLayout(capability, control) orelse
        return error.MalformedCapabilityList;
    if ((control & PCI_MSI_64_BIT_CAPABLE) == 0 and message.address >> 32 != 0) {
        return error.MessageAddressUnsupported;
    }

    const disabled = control & ~(PCI_MSI_ENABLE | PCI_MSI_MULTI_MESSAGE_ENABLE_MASK);
    writeLocked(u16, device_info, control_offset, disabled);
    writeLocked(u32, device_info, address_offset, @truncate(message.address));
    if ((control & PCI_MSI_64_BIT_CAPABLE) != 0) {
        writeLocked(u32, device_info, address_offset + 4, @truncate(message.address >> 32));
    }
    writeLocked(u16, device_info, layout.data_offset, message.data);
    if (layout.mask_offset) |mask_offset| {
        writeLocked(u32, device_info, mask_offset, readLocked(u32, device_info, mask_offset) & ~@as(u32, 1));
    }
    writeLocked(u16, device_info, control_offset, disabled | PCI_MSI_ENABLE);
    const verified = readLocked(u16, device_info, control_offset);
    if ((verified & PCI_MSI_ENABLE) == 0 or
        (verified & PCI_MSI_MULTI_MESSAGE_ENABLE_MASK) != 0 or
        readLocked(u32, device_info, address_offset) != @as(u32, @truncate(message.address)) or
        readLocked(u16, device_info, layout.data_offset) != message.data)
    {
        writeLocked(u16, device_info, control_offset, disabled);
        return error.MsiEnableFailed;
    }
}

pub const MsixTable = struct {
    bar_index: u3,
    offset: u32,
    entries: u16,
};

/// Locate the MSI-X table. Callers bound it by the sized BAR aperture before
/// mapping entry 0.
pub fn msixTable(device_info: PCIDevice) MsiError!?MsixTable {
    const capability = try findCapabilityOffset(device_info, PCI_CAPABILITY_MSIX) orelse return null;
    const control = readLocked(u16, device_info, @as(u16, capability) + 2);
    const table = readLocked(u32, device_info, @as(u16, capability) + 4);
    return .{
        .bar_index = @truncate(table & PCI_MSIX_TABLE_BIR_MASK),
        .offset = table & ~PCI_MSIX_TABLE_BIR_MASK,
        .entries = (control & PCI_MSIX_TABLE_SIZE_MASK) + 1,
    };
}

/// MSI-X table entry: message address low/high, data and vector control.
pub const MsixEntry = *volatile [4]u32;

fn msixControlOffset(device_info: PCIDevice) MsiError!u16 {
    const capability = try findCapabilityOffset(device_info, PCI_CAPABILITY_MSIX) orelse
        return error.MsiCapabilityMissing;
    return @as(u16, capability) + 2;
}

fn maskMsix(device_info: PCIDevice, control_offset: u16) void {
    const control = readLocked(u16, device_info, control_offset);
    writeLocked(u16, device_info, control_offset, (control | PCI_MSIX_FUNCTION_MASK) & ~PCI_MSIX_ENABLE);
}

/// Enable MSI-X with the whole function masked and program entry 0 with its
/// vector masked. `unmaskSingleMsix` later opens delivery.
pub fn beginSingleMsix(device_info: PCIDevice, entry: MsixEntry, message: MsiMessage) MsiError!void {
    const control_offset = try msixControlOffset(device_info);
    const masked_enable = PCI_MSIX_ENABLE | PCI_MSIX_FUNCTION_MASK;
    writeLocked(u16, device_info, control_offset, readLocked(u16, device_info, control_offset) | masked_enable);
    errdefer maskMsix(device_info, control_offset);
    if (readLocked(u16, device_info, control_offset) & masked_enable != masked_enable) return error.MsiEnableFailed;
    entry[3] = PCI_MSIX_VECTOR_MASKED;
    entry[0] = @truncate(message.address);
    entry[1] = @truncate(message.address >> 32);
    entry[2] = message.data;
    if (entry[0] != @as(u32, @truncate(message.address)) or
        entry[1] != @as(u32, @truncate(message.address >> 32)) or
        entry[2] != message.data or
        entry[3] & PCI_MSIX_VECTOR_MASKED == 0) return error.MsiEnableFailed;
}

pub fn unmaskSingleMsix(device_info: PCIDevice, entry: MsixEntry) MsiError!void {
    const control_offset = try msixControlOffset(device_info);
    errdefer maskMsix(device_info, control_offset);
    entry[3] = 0;
    const control = readLocked(u16, device_info, control_offset);
    writeLocked(u16, device_info, control_offset, (control | PCI_MSIX_ENABLE) & ~PCI_MSIX_FUNCTION_MASK);
    if (readLocked(u16, device_info, control_offset) & (PCI_MSIX_ENABLE | PCI_MSIX_FUNCTION_MASK) != PCI_MSIX_ENABLE or
        entry[3] & PCI_MSIX_VECTOR_MASKED != 0) return error.MsiEnableFailed;
}

pub fn enableSingleMsix(device_info: PCIDevice, entry: MsixEntry, message: MsiMessage) MsiError!void {
    try beginSingleMsix(device_info, entry, message);
    try unmaskSingleMsix(device_info, entry);
}

/// Disable MSI and mask and disable MSI-X on every capability the function
/// exposes.
pub fn disableMessageInterrupts(device_info: PCIDevice) QuiesceError!void {
    _ = try inspectMessageSignaledInterrupts(device_info, true);
}

fn inspectMessageSignaledInterrupts(device_info: PCIDevice, disable: bool) QuiesceError!usize {
    var capabilities = CapabilityIterator.init(device_info);
    var enabled_count: usize = 0;
    while (try capabilities.next()) |capability| {
        if (messageInterruptControl(
            capability.id,
            readConfigWord(
                device_info.bus,
                device_info.device,
                device_info.function,
                @as(u16, capability.offset) + 2,
            ),
        )) |message_control| {
            if (message_control.enabled) enabled_count += 1;
            if (disable) {
                writeConfigWord(
                    device_info.bus,
                    device_info.device,
                    device_info.function,
                    @as(u16, capability.offset) + 2,
                    message_control.disabled,
                );
                const verified = readConfigWord(
                    device_info.bus,
                    device_info.device,
                    device_info.function,
                    @as(u16, capability.offset) + 2,
                );
                if (messageInterruptControl(capability.id, verified).?.enabled or
                    (capability.id == PCI_CAPABILITY_MSIX and
                        (verified & PCI_MSIX_FUNCTION_MASK) == 0))
                {
                    return error.InterruptDisableFailed;
                }
            }
        }
    }
    return enabled_count;
}

pub fn disableBootMessageSignaledInterrupts() QuiesceError!usize {
    var disabled: usize = 0;
    for (bootDevices()) |device_info| {
        disabled += try inspectMessageSignaledInterrupts(device_info, true);
    }
    return disabled;
}

pub fn bootMessageSignaledInterruptCount() QuiesceError!usize {
    var enabled_count: usize = 0;
    for (bootDevices()) |device_info| {
        enabled_count += try inspectMessageSignaledInterrupts(device_info, false);
    }
    return enabled_count;
}

pub fn bootLegacyInterruptCount() usize {
    var enabled_count: usize = 0;
    for (bootDevices()) |device_info| {
        if ((readConfigWord(
            device_info.bus,
            device_info.device,
            device_info.function,
            PCI_COMMAND_OFFSET,
        ) & PCI_COMMAND_INTERRUPT_DISABLE) == 0) enabled_count += 1;
    }
    return enabled_count;
}

pub fn bootBusMasterCount() usize {
    var count: usize = 0;
    for (bootDevices()) |device_info| {
        if (busMasteringEnabled(device_info)) count += 1;
    }
    return count;
}

fn firstMatchingIn(
    comptime Query: type,
    devices: []const PCIDevice,
    query: Query,
    comptime matches: fn (Query, PCIDevice) bool,
) ?PCIDevice {
    for (devices) |device_info| {
        if (matches(query, device_info)) return device_info;
    }
    return null;
}

fn firstMatchingDevice(
    comptime Query: type,
    query: Query,
    comptime matches: fn (Query, PCIDevice) bool,
) ?PCIDevice {
    return firstMatchingIn(Query, bootDevices(), query, matches);
}

pub fn findDevice(vendor_id: u16, device_id: u16) ?PCIDevice {
    return firstMatchingDevice(
        VendorDeviceQuery,
        .{ .vendor_id = vendor_id, .device_id = device_id },
        matchesVendorDevice,
    );
}

pub fn firstDeviceByClass(class_code: u8) ?PCIDevice {
    return firstMatchingDevice(ClassQuery, .{ .class_code = class_code }, matchesClassOnly);
}

pub fn firstDeviceByClassSubclassProgIf(class_code: u8, subclass: u8, prog_if: u8) ?PCIDevice {
    return firstMatchingDevice(
        ClassSubclassProgIfQuery,
        .{ .class_code = class_code, .subclass = subclass, .prog_if = prog_if },
        matchesClassSubclassProgIfQuery,
    );
}

pub fn firstNvmeController() ?PCIDevice {
    return firstDeviceByClassSubclassProgIf(PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME);
}

pub fn firstIntelI225Lm() ?PCIDevice {
    return findDevice(PCI_VENDOR_INTEL, PCI_DEVICE_INTEL_I225_LM);
}

pub fn firstXhciController() ?PCIDevice {
    return firstDeviceByClassSubclassProgIf(PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
}

pub fn matchesClass(device_info: PCIDevice, class_code: u8, subclass: u8, prog_if: u8) bool {
    return device_info.class_code == class_code and
        device_info.subclass == subclass and
        device_info.prog_if == prog_if;
}

pub fn isIntelI225Lm(device_info: PCIDevice) bool {
    return device_info.vendor_id == PCI_VENDOR_INTEL and device_info.device_id == PCI_DEVICE_INTEL_I225_LM;
}

pub fn isXhciController(device_info: PCIDevice) bool {
    return matchesClass(device_info, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
}

pub fn memoryBar0(device_info: PCIDevice) ?MemoryBar {
    if ((device_info.bar0 & PCI_BAR_IO_SPACE) != 0) return null;
    const low = @as(usize, device_info.bar0 & PCI_BAR_ADDRESS_MASK);
    return switch (device_info.bar0 & PCI_BAR_MEMORY_TYPE_MASK) {
        PCI_BAR_MEMORY_TYPE_32 => .{ .address = low, .width = .bits32 },
        PCI_BAR_MEMORY_TYPE_64 => .{
            .address = (@as(usize, device_info.bar1) << 32) | low,
            .width = .bits64,
        },
        else => null,
    };
}

pub fn stableDeviceId(device_info: PCIDevice) u64 {
    return (@as(u64, device_info.vendor_id) << STABLE_VENDOR_ID_SHIFT) |
        (@as(u64, device_info.device_id) << STABLE_DEVICE_ID_SHIFT) |
        (@as(u64, device_info.bus) << STABLE_BUS_SHIFT) |
        (@as(u64, device_info.device) << STABLE_DEVICE_SHIFT) |
        @as(u64, device_info.function);
}

pub fn findDeviceByStableId(target_device_id: u64) ?PCIDevice {
    return firstMatchingDevice(StableIdQuery, .{ .device_id = target_device_id }, matchesStableId);
}

fn syntheticPciDevice(vendor_id: u16, device_id: u16, class_code: u8, subclass: u8, prog_if: u8) PCIDevice {
    return .{
        .bus = 0,
        .device = 0,
        .function = 0,
        .vendor_id = vendor_id,
        .device_id = device_id,
        .class_code = class_code,
        .subclass = subclass,
        .prog_if = prog_if,
        .bar0 = 0,
        .bar1 = 0,
    };
}

test "PCIe ECAM address calculation covers buses devices functions and extended configuration" {
    const allocation = mcfg.Allocation{
        .base_address = 0xB000_0000,
        .segment_group = 0,
        .start_bus = 0,
        .end_bus = 0xFF,
    };
    try std.testing.expectEqual(
        @as(?usize, 0xB000_0000),
        ecamPhysicalAddress(allocation, 0, 0, 0, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, 0xB123_4ABC),
        ecamPhysicalAddress(allocation, 0x12, 6, 4, 0xABC),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        ecamPhysicalAddress(allocation, 0, PCI_MAX_DEVICE_COUNT, 0, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        ecamPhysicalAddress(allocation, 0, 0, PCI_MAX_FUNCTION_COUNT, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        ecamPhysicalAddress(allocation, 0, 0, 0, ECAM_CONFIG_OFFSET_MASK + 1),
    );
}

test "PCIe ECAM address calculation honors allocation bus origins" {
    const allocation = mcfg.Allocation{
        .base_address = 0x8000_0000,
        .segment_group = 7,
        .start_bus = 0x40,
        .end_bus = 0x4F,
    };
    try std.testing.expectEqual(
        @as(?usize, 0x8000_1000),
        ecamPhysicalAddress(allocation, 0x40, 0, 1, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, 0x80F0_0000),
        ecamPhysicalAddress(allocation, 0x4F, 0, 0, 0),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        ecamPhysicalAddress(allocation, 0x3F, 0, 0, 0),
    );
}

test "PCI helpers identify Intel I225-LM network controller" {
    const i225_lm = syntheticPciDevice(PCI_VENDOR_INTEL, PCI_DEVICE_INTEL_I225_LM, PCI_CLASS_NETWORK_ADAPTER, 0, 0);
    try @import("std").testing.expect(isIntelI225Lm(i225_lm));

    const e1000 = syntheticPciDevice(PCI_VENDOR_INTEL, 0x100E, PCI_CLASS_NETWORK_ADAPTER, 0, 0);
    try @import("std").testing.expect(!isIntelI225Lm(e1000));
}

test "PCI helpers identify xHCI USB controllers" {
    const xhci = syntheticPciDevice(PCI_VENDOR_INTEL, 0xA0ED, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
    try @import("std").testing.expect(isXhciController(xhci));

    const ehci = syntheticPciDevice(PCI_VENDOR_INTEL, 0x1E26, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, 0x20);
    try @import("std").testing.expect(!isXhciController(ehci));
}

test "PCI BAR0 decoder accepts current memory BARs and rejects I/O or reserved encodings" {
    var device = syntheticPciDevice(PCI_VENDOR_INTEL, 0xA0ED, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
    device.bar0 = 0xFEB0_0000;
    try std.testing.expectEqual(MemoryBar{ .address = 0xFEB0_0000, .width = .bits32 }, memoryBar0(device).?);

    device.bar0 = 0xABC0_0004;
    device.bar1 = 0x0000_0001;
    try std.testing.expectEqual(MemoryBar{ .address = 0x1_ABC0_0000, .width = .bits64 }, memoryBar0(device).?);

    device.bar0 = 0xFEB0_0001;
    try std.testing.expect(memoryBar0(device) == null);
    device.bar0 = 0xFEB0_0002;
    try std.testing.expect(memoryBar0(device) == null);
}

test "PCI inventory queries reuse one discovered device set" {
    const devices = [_]PCIDevice{
        syntheticPciDevice(0x1234, 0x0001, PCI_CLASS_NETWORK_ADAPTER, 0, 0),
        syntheticPciDevice(0x144D, 0xA80A, PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME),
    };
    const nvme = firstMatchingIn(
        ClassSubclassProgIfQuery,
        &devices,
        .{
            .class_code = PCI_CLASS_STORAGE_CONTROLLER,
            .subclass = PCI_SUBCLASS_NVM,
            .prog_if = PCI_PROG_IF_NVME,
        },
        matchesClassSubclassProgIfQuery,
    ) orelse return error.MissingDevice;
    try std.testing.expectEqual(@as(u16, 0xA80A), nvme.device_id);
}

test "PCI interrupt quiesce disables MSI and masks MSI-X" {
    const msi = messageInterruptControl(PCI_CAPABILITY_MSI, PCI_MSI_ENABLE | 0x0180).?;
    try std.testing.expect(msi.enabled);
    try std.testing.expectEqual(@as(u16, 0x0180), msi.disabled);

    const msix = messageInterruptControl(PCI_CAPABILITY_MSIX, PCI_MSIX_ENABLE | 0x0007).?;
    try std.testing.expect(msix.enabled);
    try std.testing.expectEqual(@as(u16, PCI_MSIX_FUNCTION_MASK | 0x0007), msix.disabled);
    try std.testing.expect(messageInterruptControl(0x10, 0xFFFF) == null);
}

test "PCI MSI layout supports one 32-bit or 64-bit message" {
    const simple = msiLayout(0x40, 0).?;
    try std.testing.expectEqual(@as(u16, 0x48), simple.data_offset);
    try std.testing.expectEqual(@as(?u16, null), simple.mask_offset);

    const extended = msiLayout(
        0x40,
        PCI_MSI_64_BIT_CAPABLE | PCI_MSI_PER_VECTOR_MASK_CAPABLE,
    ).?;
    try std.testing.expectEqual(@as(u16, 0x4C), extended.data_offset);
    try std.testing.expectEqual(@as(?u16, 0x50), extended.mask_offset);
    try std.testing.expect(msiLayout(0xF8, PCI_MSI_64_BIT_CAPABLE) == null);
}
