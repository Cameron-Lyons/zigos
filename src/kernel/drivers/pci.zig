const std = @import("std");
const console = @import("../utils/console.zig");
const spin = @import("../utils/spin.zig");
const paging = @import("../memory/paging64.zig");
const mcfg = @import("../platform/mcfg.zig");

const ECAM_BUS_SHIFT: u6 = 20;
const ECAM_DEVICE_SHIFT: u6 = 15;
const ECAM_FUNCTION_SHIFT: u6 = 12;
const ECAM_FUNCTION_BYTES: usize = 1 << ECAM_FUNCTION_SHIFT;
const ECAM_CONFIG_OFFSET_MASK: u16 = ECAM_FUNCTION_BYTES - 1;
const CONFIG_DWORD_ALIGNMENT_MASK: u16 = 0x0FFC;
const KERNEL_ECAM_WINDOW_VIRTUAL_BASE: usize = 0xFFFF_8000_1000_0000;

const PCI_MAX_BUS_COUNT: u16 = 256;
const PCI_MAX_DEVICE_COUNT: u8 = 32;
const PCI_MAX_FUNCTION_COUNT: u8 = 8;
const PCI_VENDOR_DEVICE_OFFSET: u16 = 0x00;
const PCI_CLASS_INFO_OFFSET: u16 = 0x08;
const PCI_HEADER_TYPE_OFFSET: u16 = 0x0E;
const PCI_SECONDARY_BUS_OFFSET: u16 = 0x19;
const PCI_BAR0_OFFSET: u16 = 0x10;
const PCI_BAR1_OFFSET: u16 = 0x14;
const PCI_BAR2_OFFSET: u16 = 0x18;
const PCI_BAR3_OFFSET: u16 = 0x1C;
const PCI_BAR4_OFFSET: u16 = 0x20;
const PCI_BAR5_OFFSET: u16 = 0x24;
const PCI_COMMAND_OFFSET: u16 = 0x04;
const PCI_STATUS_OFFSET: u16 = 0x06;
const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
const PCI_COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;
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
const PCI_MSIX_FUNCTION_MASK: u16 = 1 << 14;
const PCI_MSIX_ENABLE: u16 = 1 << 15;

const PCI_ABSENT_VENDOR_ID: u16 = 0xFFFF;
const PCI_MULTI_FUNCTION_FLAG: u8 = 0x80;
const PCI_CLASS_BRIDGE: u8 = 0x06;
const PCI_SUBCLASS_PCI_TO_PCI: u8 = 0x04;
const PCI_INVENTORY_CAPACITY: usize = 256;
const PCI_U8_MASK: u32 = 0xFF;
const PCI_U16_MASK: u32 = 0xFFFF;
const BITS_PER_BYTE: u5 = 8;
const U16_HIGH_BYTE_SHIFT = 8;
const PCI_DEVICE_ID_SHIFT = 16;
const PCI_CLASS_CODE_SHIFT = 24;
const PCI_SUBCLASS_SHIFT = 16;
const PCI_PROG_IF_SHIFT = 8;
const STABLE_VENDOR_ID_SHIFT = 32;
const STABLE_DEVICE_ID_SHIFT = 16;
const STABLE_BUS_SHIFT = 8;
const STABLE_DEVICE_SHIFT = 3;

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
    bar2: u32,
    bar3: u32,
    bar4: u32,
    bar5: u32,
};

pub const PCI_CLASS_STORAGE_CONTROLLER: u8 = 0x01;
pub const PCI_SUBCLASS_NVM: u8 = 0x08;
pub const PCI_PROG_IF_NVME: u8 = 0x02;
pub const PCI_CLASS_NETWORK_ADAPTER: u8 = 0x02;
pub const PCI_CLASS_SERIAL_BUS_CONTROLLER: u8 = 0x0C;
pub const PCI_SUBCLASS_USB: u8 = 0x03;
pub const PCI_PROG_IF_XHCI: u8 = 0x30;
pub const PCI_VENDOR_INTEL: u16 = 0x8086;
pub const PCI_DEVICE_INTEL_I225_LM: u16 = 0x15F2;

var boot_inventory: [PCI_INVENTORY_CAPACITY]PCIDevice = undefined;
var boot_inventory_count: usize = 0;
var boot_inventory_initialized = false;
var boot_inventory_valid = false;
var ecam_allocation: ?mcfg.Allocation = null;
var mapped_configuration_page: ?usize = null;
var configuration_lock: bool = false;

pub const InitError = error{InvalidEcamAllocation};
pub const QuiesceError = error{
    MalformedCapabilityList,
    InterruptDisableFailed,
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

    ecam_allocation = allocation;
    mapped_configuration_page = null;
    boot_inventory_count = 0;
    boot_inventory_initialized = false;
    boot_inventory_valid = false;
}

pub fn initialized() bool {
    return ecam_allocation != null;
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
    while (@atomicRmw(bool, &configuration_lock, .Xchg, true, .seq_cst)) {
        spin.hint();
    }
}

fn releaseConfigurationLock() void {
    @atomicStore(bool, &configuration_lock, false, .seq_cst);
}

fn mappedRegister(bus: u8, device: u8, function: u8, offset: u16) ?*volatile u32 {
    const allocation = ecam_allocation orelse return null;
    const aligned_offset = offset & CONFIG_DWORD_ALIGNMENT_MASK;
    const physical_address = ecamPhysicalAddress(allocation, bus, device, function, aligned_offset) orelse return null;
    const physical_page = physical_address & ~(ECAM_FUNCTION_BYTES - 1);
    if (mapped_configuration_page == null or mapped_configuration_page.? != physical_page) {
        paging.mapKernelBorrowedPage(
            KERNEL_ECAM_WINDOW_VIRTUAL_BASE,
            physical_page,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
        );
        mapped_configuration_page = physical_page;
    }
    return @ptrFromInt(KERNEL_ECAM_WINDOW_VIRTUAL_BASE + (physical_address & (ECAM_FUNCTION_BYTES - 1)));
}

fn readConfigUnlocked(bus: u8, device: u8, function: u8, offset: u16) u32 {
    const register = mappedRegister(bus, device, function, offset) orelse return std.math.maxInt(u32);
    return register.*;
}

fn writeConfigUnlocked(bus: u8, device: u8, function: u8, offset: u16, value: u32) void {
    const register = mappedRegister(bus, device, function, offset) orelse return;
    register.* = value;
}

pub fn readConfig(bus: u8, device: u8, function: u8, offset: u16) u32 {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    return readConfigUnlocked(bus, device, function, offset);
}

pub fn writeConfig(bus: u8, device: u8, function: u8, offset: u16, value: u32) void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    writeConfigUnlocked(bus, device, function, offset, value);
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
        .bar2 = readConfig(bus, device, func, PCI_BAR2_OFFSET),
        .bar3 = readConfig(bus, device, func, PCI_BAR3_OFFSET),
        .bar4 = readConfig(bus, device, func, PCI_BAR4_OFFSET),
        .bar5 = readConfig(bus, device, func, PCI_BAR5_OFFSET),
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

fn appendBootDevice(device_info: PCIDevice) bool {
    if (boot_inventory_count == boot_inventory.len) return false;
    boot_inventory[boot_inventory_count] = device_info;
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

    var visited = [_]bool{false} ** PCI_MAX_BUS_COUNT;
    var queue = [_]u8{0} ** PCI_MAX_BUS_COUNT;
    var queue_head: usize = 0;
    var queue_tail: usize = 1;
    visited[0] = true;

    while (queue_head < queue_tail) : (queue_head += 1) {
        const bus = queue[queue_head];
        var device: u8 = 0;
        while (device < PCI_MAX_DEVICE_COUNT) : (device += 1) {
            const function_zero = checkDevice(bus, device, 0) orelse continue;
            if (!appendBootDevice(function_zero) or
                !enqueueSecondaryBus(function_zero, &visited, &queue, &queue_tail))
            {
                boot_inventory_count = 0;
                return;
            }
            if (!deviceHasMultipleFunctions(bus, device)) continue;

            var function: u8 = 1;
            while (function < PCI_MAX_FUNCTION_COUNT) : (function += 1) {
                const device_info = checkDevice(bus, device, function) orelse continue;
                if (!appendBootDevice(device_info) or
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
    return boot_inventory[0..boot_inventory_count];
}

pub fn disableBusMastering(device_info: PCIDevice) void {
    const command = readConfigWord(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_COMMAND_OFFSET,
    );
    writeConfigWord(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_COMMAND_OFFSET,
        (command & ~PCI_COMMAND_BUS_MASTER) | PCI_COMMAND_INTERRUPT_DISABLE,
    );
}

pub fn enableMemoryBusMastering(device_info: PCIDevice) void {
    const command = readConfigWord(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_COMMAND_OFFSET,
    );
    writeConfigWord(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_COMMAND_OFFSET,
        command | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER,
    );
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

fn inspectMessageSignaledInterrupts(device_info: PCIDevice, disable: bool) QuiesceError!usize {
    if ((readConfigWord(
        device_info.bus,
        device_info.device,
        device_info.function,
        PCI_STATUS_OFFSET,
    ) & PCI_STATUS_CAPABILITIES_LIST) == 0) return 0;

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
    var offset = readConfigByte(
        device_info.bus,
        device_info.device,
        device_info.function,
        pointer_offset,
    );
    var visited: u64 = 0;
    var enabled_count: usize = 0;
    while (offset != 0) {
        if (offset < PCI_CAPABILITY_MIN_OFFSET or offset > PCI_CAPABILITY_MAX_OFFSET or offset & 3 != 0) {
            return error.MalformedCapabilityList;
        }
        const slot: u6 = @intCast(offset >> 2);
        const slot_bit = @as(u64, 1) << slot;
        if ((visited & slot_bit) != 0) return error.MalformedCapabilityList;
        visited |= slot_bit;

        const capability_id = readConfigByte(
            device_info.bus,
            device_info.device,
            device_info.function,
            offset,
        );
        const next = readConfigByte(
            device_info.bus,
            device_info.device,
            device_info.function,
            @as(u16, offset) + 1,
        );
        if (messageInterruptControl(
            capability_id,
            readConfigWord(
                device_info.bus,
                device_info.device,
                device_info.function,
                @as(u16, offset) + 2,
            ),
        )) |message_control| {
            if (message_control.enabled) enabled_count += 1;
            if (disable) {
                writeConfigWord(
                    device_info.bus,
                    device_info.device,
                    device_info.function,
                    @as(u16, offset) + 2,
                    message_control.disabled,
                );
                const verified = readConfigWord(
                    device_info.bus,
                    device_info.device,
                    device_info.function,
                    @as(u16, offset) + 2,
                );
                if (messageInterruptControl(capability_id, verified).?.enabled or
                    (capability_id == PCI_CAPABILITY_MSIX and
                        (verified & PCI_MSIX_FUNCTION_MASK) == 0))
                {
                    return error.InterruptDisableFailed;
                }
            }
        }
        offset = next;
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

pub fn isNvmeController(device_info: PCIDevice) bool {
    return matchesClass(device_info, PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME);
}

pub fn isIntelI225Lm(device_info: PCIDevice) bool {
    return device_info.vendor_id == PCI_VENDOR_INTEL and device_info.device_id == PCI_DEVICE_INTEL_I225_LM;
}

pub fn isXhciController(device_info: PCIDevice) bool {
    return matchesClass(device_info, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
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

pub fn scanBus() void {
    console.print("Scanning PCI bus...\n");

    for (bootDevices()) |pci_device| {
        console.print("PCI ");
        printHex8(pci_device.bus);
        console.print(":");
        printHex8(pci_device.device);
        console.print(".");
        printHex8(pci_device.function);
        console.print(" - Vendor: ");
        printHex16(pci_device.vendor_id);
        console.print(" Device: ");
        printHex16(pci_device.device_id);
        console.print(" Class: ");
        printHex8(pci_device.class_code);
        console.print(":");
        printHex8(pci_device.subclass);
        console.print("\n");
    }
}

fn printHex8(value: u8) void {
    const high = value >> 4;
    const low = value & 0x0F;
    console.printChar(if (high < 10) '0' + high else 'A' + high - 10);
    console.printChar(if (low < 10) '0' + low else 'A' + low - 10);
}

fn printHex16(value: u16) void {
    printHex8(@intCast((value >> U16_HIGH_BYTE_SHIFT) & PCI_U8_MASK));
    printHex8(@intCast(value & PCI_U8_MASK));
}

pub fn readConfigByte(bus: u8, device: u8, function: u8, offset: u16) u8 {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const data = readConfigUnlocked(bus, device, function, offset);
    const shift: u5 = @intCast((offset & 3) * BITS_PER_BYTE);
    return @as(u8, @truncate(data >> shift));
}

pub fn readConfigWord(bus: u8, device: u8, function: u8, offset: u16) u16 {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const data = readConfigUnlocked(bus, device, function, offset);
    const shift: u5 = @intCast((offset & 2) * BITS_PER_BYTE);
    return @as(u16, @truncate(data >> shift));
}

pub fn readConfigDword(bus: u8, device: u8, function: u8, offset: u16) u32 {
    return readConfig(bus, device, function, offset);
}

pub fn writeConfigByte(bus: u8, device: u8, function: u8, offset: u16, value: u8) void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const old_data = readConfigUnlocked(bus, device, function, offset);
    const shift = (offset & 3) * BITS_PER_BYTE;
    const mask = ~(PCI_U8_MASK << shift);
    const new_data = (old_data & mask) | (@as(u32, value) << shift);
    writeConfigUnlocked(bus, device, function, offset, new_data);
}

pub fn writeConfigWord(bus: u8, device: u8, function: u8, offset: u16, value: u16) void {
    acquireConfigurationLock();
    defer releaseConfigurationLock();
    const old_data = readConfigUnlocked(bus, device, function, offset);
    const shift: u5 = @intCast((offset & 2) * BITS_PER_BYTE);
    const mask = ~(PCI_U16_MASK << shift);
    const new_data = (old_data & mask) | (@as(u32, value) << shift);
    writeConfigUnlocked(bus, device, function, offset, new_data);
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
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
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

test "PCI helpers identify NVMe controllers" {
    const nvme = syntheticPciDevice(0x144D, 0xA80A, PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME);
    try @import("std").testing.expect(isNvmeController(nvme));

    const ahci = syntheticPciDevice(0x8086, 0x2922, PCI_CLASS_STORAGE_CONTROLLER, 0x06, 0x01);
    try @import("std").testing.expect(!isNvmeController(ahci));
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

pub fn writeConfigDword(bus: u8, device: u8, function: u8, offset: u16, value: u32) void {
    writeConfig(bus, device, function, offset, value);
}
