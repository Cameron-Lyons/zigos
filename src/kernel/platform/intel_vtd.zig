const std = @import("std");
const builtin = @import("builtin");
const pci = @import("../drivers/pci.zig");
const paging = @import("../memory/paging64.zig");
const dmar = @import("dmar.zig");

const PAGE_SIZE: u32 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;
const MANAGED_DMA_LIMIT: u64 = 128 * 1024 * 1024;
const TABLE_ENTRY_COUNT: usize = 512;
const TABLE_PAGE_COUNT: u32 = 10;
const ROOT_PAGE: u32 = 0;
const CONTEXT_PAGE: u32 = 1;
const L4_PAGE: u32 = 2;
const L3_PAGE: u32 = 3;
const L2_PAGE: u32 = 4;
const FIRST_LEAF_PAGE: u32 = 5;
const MAX_DMA_WINDOWS: usize = TABLE_PAGE_COUNT - FIRST_LEAF_PAGE;
const SECOND_STAGE_READ: u64 = 1 << 0;
const SECOND_STAGE_WRITE: u64 = 1 << 1;
const PRESENT: u64 = 1;
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const STORAGE_DOMAIN_ID: u16 = 1;

const KERNEL_VTD_MMIO_VIRTUAL_BASE: usize = 0xFFFF_8000_3000_0000;
const UNIT_MMIO_STRIDE: usize = 0x2000;
const UNIT_IOTLB_PAGE_OFFSET: usize = 0x1000;

const REG_VERSION: usize = 0x000;
const REG_CAPABILITY: usize = 0x008;
const REG_EXTENDED_CAPABILITY: usize = 0x010;
const REG_GLOBAL_COMMAND: usize = 0x018;
const REG_GLOBAL_STATUS: usize = 0x01C;
const REG_ROOT_TABLE_ADDRESS: usize = 0x020;
const REG_CONTEXT_COMMAND: usize = 0x028;

const GLOBAL_TRANSLATION_ENABLE: u32 = 1 << 31;
const GLOBAL_SET_ROOT_TABLE_POINTER: u32 = 1 << 30;
const GLOBAL_QUEUED_INVALIDATION_ENABLE: u32 = 1 << 26;
const GLOBAL_INTERRUPT_REMAP_ENABLE: u32 = 1 << 25;
const GLOBAL_COMMAND_STATUS_MASK: u32 = 0x96FF_FFFF;
const CONTEXT_INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL_INVALIDATION: u64 = 1 << 61;
const CONTEXT_ACTUAL_GRANULARITY_MASK: u64 = 0b11 << 59;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL_INVALIDATION: u64 = 1 << 60;
const IOTLB_ACTUAL_GRANULARITY_MASK: u64 = 0b11 << 57;
const COMMAND_SPIN_LIMIT: u64 = 50_000_000;

const CAP_ENHANCED_SRTP: u64 = 1 << 63;
const CAP_MGAW_SHIFT: u6 = 16;
const CAP_MGAW_MASK: u64 = 0x3F;
const CAP_SAGAW_SHIFT: u6 = 8;
const CAP_SAGAW_MASK: u64 = 0x1F;
const ECAP_IOTLB_REGISTER_OFFSET_SHIFT: u6 = 8;
const ECAP_IOTLB_REGISTER_OFFSET_MASK: u64 = 0x3FF;
const ECAP_PAGE_WALK_COHERENT: u64 = 1 << 0;
const ECAP_INTERRUPT_REMAP_REQUIRED: u64 = 1 << 62;

const PageTable = [TABLE_ENTRY_COUNT]u64;
const Tables = [TABLE_PAGE_COUNT]PageTable;

pub const DmaWindow = struct {
    base: u32,
    length: u32 = PAGE_SIZE,
    device_readable: bool,
    device_writable: bool,
};

pub const Error = error{
    AlreadyEnabled,
    FirmwarePolicyUnsupported,
    ActiveBusMaster,
    InvalidDmaWindow,
    UnsupportedHardwareVersion,
    UnsupportedAddressWidth,
    NonCoherentPageWalk,
    InterruptRemappingRequired,
    InvalidRegisterRange,
    FirmwareRemappingActive,
    TableAllocationFailed,
    CommandTimeout,
    CommandRejected,
};

const AddressWidth = enum(u3) {
    bits39 = 1,
    bits48 = 2,
};

const UnitRegisters = struct {
    base: usize,
    iotlb: usize,
    capability: u64,
    enhanced_srtp: bool,
};

var enabled = false;
var active_table_base: u32 = 0;
var protected_requester_id: u16 = 0;

pub fn storageIsolationEnabled() bool {
    return enabled;
}

pub fn protectedRequesterId() ?u16 {
    if (!enabled) return null;
    return protected_requester_id;
}

pub fn enforceNvme(
    summary: *const dmar.Summary,
    device_info: pci.PCIDevice,
    windows: []const DmaWindow,
) Error!void {
    if (enabled) return error.AlreadyEnabled;
    if (!summary.productionEnforcementReady()) return error.FirmwarePolicyUnsupported;
    if (pci.bootBusMasterCount() != 0) return error.ActiveBusMaster;
    try validateWindows(windows);

    var units: [dmar.MAX_REMAPPING_UNITS]UnitRegisters = undefined;
    var common_sagaw: u8 = CAP_SAGAW_MASK;
    for (summary.units(), 0..) |unit, index| {
        const registers = try probeUnit(unit, index, summary.host_address_width);
        units[index] = registers;
        common_sagaw &= @intCast((registers.capability >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK);
    }
    const address_width = chooseAddressWidth(common_sagaw) orelse
        return error.UnsupportedAddressWidth;

    const table_base = paging.alloc_frames(TABLE_PAGE_COUNT) orelse
        return error.TableAllocationFailed;
    var may_release_tables = true;
    errdefer if (may_release_tables) paging.release_frames(table_base, TABLE_PAGE_COUNT) catch {};
    const tables: *Tables = @ptrFromInt(table_base);
    populateTables(tables, table_base, device_info, windows, address_width);
    publishTables();

    // From this point onward a unit may retain the table pointer even if a later
    // unit fails. Keep the frames permanently reserved on every such failure.
    may_release_tables = false;
    for (units[0..summary.remapping_unit_count]) |unit| {
        try programUnit(unit, table_base);
    }

    active_table_base = table_base;
    protected_requester_id = requesterId(device_info);
    enabled = true;
}

fn validateWindows(windows: []const DmaWindow) Error!void {
    if (windows.len == 0 or windows.len > MAX_DMA_WINDOWS) return error.InvalidDmaWindow;
    for (windows, 0..) |window, index| {
        if (window.length != PAGE_SIZE or window.base % PAGE_SIZE != 0 or
            (!window.device_readable and !window.device_writable) or
            @as(u64, window.base) + window.length > MANAGED_DMA_LIMIT)
        {
            return error.InvalidDmaWindow;
        }
        for (windows[0..index]) |prior| {
            if (prior.base == window.base) return error.InvalidDmaWindow;
        }
    }
}

fn chooseAddressWidth(sagaw: u8) ?AddressWidth {
    // The current physical aperture fits comfortably in 39 bits. Prefer the
    // three-level walk to remove one dependent memory access from every miss.
    if ((sagaw & (@as(u8, 1) << @intFromEnum(AddressWidth.bits39))) != 0) return .bits39;
    if ((sagaw & (@as(u8, 1) << @intFromEnum(AddressWidth.bits48))) != 0) return .bits48;
    return null;
}

fn probeUnit(unit: dmar.RemappingUnit, index: usize, host_address_width: u8) Error!UnitRegisters {
    if (unit.segment != 0) return error.FirmwarePolicyUnsupported;
    const register_base = std.math.cast(usize, unit.register_base_address) orelse
        return error.InvalidRegisterRange;
    const virtual_base = KERNEL_VTD_MMIO_VIRTUAL_BASE + index * UNIT_MMIO_STRIDE;
    paging.mapKernelBorrowedPage(
        virtual_base,
        register_base,
        paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
    );

    const version = read32(virtual_base + REG_VERSION);
    const major: u8 = @intCast((version >> 4) & 0xF);
    // Major version 6 removes register-based invalidation. The first supported
    // target exposes the current legacy interface; a later queued-invalidation
    // backend should be explicit instead of silently changing semantics here.
    if (major == 0 or major >= 6) return error.UnsupportedHardwareVersion;

    const capability = read64(virtual_base + REG_CAPABILITY);
    const extended = read64(virtual_base + REG_EXTENDED_CAPABILITY);
    if ((extended & ECAP_PAGE_WALK_COHERENT) == 0) return error.NonCoherentPageWalk;
    if ((extended & ECAP_INTERRUPT_REMAP_REQUIRED) != 0) return error.InterruptRemappingRequired;
    const maximum_guest_width: u8 = @intCast(((capability >> CAP_MGAW_SHIFT) & CAP_MGAW_MASK) + 1);
    if (maximum_guest_width < host_address_width) return error.UnsupportedAddressWidth;

    var iotlb_virtual: usize = 0;
    const enhanced_srtp = (capability & CAP_ENHANCED_SRTP) != 0;
    if (!enhanced_srtp) {
        const invalidate_address_offset =
            ((extended >> ECAP_IOTLB_REGISTER_OFFSET_SHIFT) & ECAP_IOTLB_REGISTER_OFFSET_MASK) * 16;
        const iotlb_offset = invalidate_address_offset + 8;
        if (iotlb_offset + @sizeOf(u64) > unit.registerBytes()) return error.InvalidRegisterRange;
        const iotlb_physical = std.math.add(u64, unit.register_base_address, iotlb_offset) catch
            return error.InvalidRegisterRange;
        const iotlb_page = std.math.cast(usize, iotlb_physical & ~PAGE_MASK) orelse
            return error.InvalidRegisterRange;
        if (iotlb_page == register_base) {
            iotlb_virtual = virtual_base + @as(usize, @intCast(iotlb_offset));
        } else {
            paging.mapKernelBorrowedPage(
                virtual_base + UNIT_IOTLB_PAGE_OFFSET,
                iotlb_page,
                paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE,
            );
            iotlb_virtual = virtual_base + UNIT_IOTLB_PAGE_OFFSET +
                @as(usize, @intCast(iotlb_physical & PAGE_MASK));
        }
    }
    return .{
        .base = virtual_base,
        .iotlb = iotlb_virtual,
        .capability = capability,
        .enhanced_srtp = enhanced_srtp,
    };
}

fn populateTables(
    tables: *Tables,
    table_base: u32,
    device_info: pci.PCIDevice,
    windows: []const DmaWindow,
    address_width: AddressWidth,
) void {
    @memset(std.mem.asBytes(tables), 0);

    const root = &tables.*[ROOT_PAGE];
    const context = &tables.*[CONTEXT_PAGE];
    const l4 = &tables.*[L4_PAGE];
    const l3 = &tables.*[L3_PAGE];
    const l2 = &tables.*[L2_PAGE];
    const context_phys = tablePagePhysical(table_base, CONTEXT_PAGE);
    const l4_phys = tablePagePhysical(table_base, L4_PAGE);
    const l3_phys = tablePagePhysical(table_base, L3_PAGE);
    const l2_phys = tablePagePhysical(table_base, L2_PAGE);

    const root_index = @as(usize, device_info.bus) * 2;
    root[root_index] = context_phys | PRESENT;

    const context_index = (@as(usize, device_info.device) * 8 + device_info.function) * 2;
    const second_stage_root = switch (address_width) {
        .bits39 => l3_phys,
        .bits48 => l4_phys,
    };
    context[context_index] = second_stage_root | PRESENT;
    context[context_index + 1] = (@as(u64, STORAGE_DOMAIN_ID) << 8) |
        @intFromEnum(address_width);

    if (address_width == .bits48) l4[0] = l3_phys | SECOND_STAGE_READ | SECOND_STAGE_WRITE;
    l3[0] = l2_phys | SECOND_STAGE_READ | SECOND_STAGE_WRITE;

    var mapped_l2_indices: [MAX_DMA_WINDOWS]u16 = undefined;
    var mapped_leaf_count: usize = 0;
    for (windows) |window| {
        const l2_index: u16 = @intCast((window.base >> 21) & 0x1FF);
        var leaf_slot: ?usize = null;
        for (mapped_l2_indices[0..mapped_leaf_count], 0..) |mapped_index, slot| {
            if (mapped_index == l2_index) {
                leaf_slot = slot;
                break;
            }
        }
        if (leaf_slot == null) {
            leaf_slot = mapped_leaf_count;
            mapped_l2_indices[mapped_leaf_count] = l2_index;
            const leaf_page = FIRST_LEAF_PAGE + @as(u32, @intCast(mapped_leaf_count));
            l2[l2_index] = tablePagePhysical(table_base, leaf_page) |
                SECOND_STAGE_READ | SECOND_STAGE_WRITE;
            mapped_leaf_count += 1;
        }

        const leaf_page = FIRST_LEAF_PAGE + @as(u32, @intCast(leaf_slot.?));
        const leaf = &tables.*[leaf_page];
        const leaf_index: usize = @intCast((window.base >> 12) & 0x1FF);
        var permissions: u64 = 0;
        if (window.device_readable) permissions |= SECOND_STAGE_READ;
        if (window.device_writable) permissions |= SECOND_STAGE_WRITE;
        leaf[leaf_index] = @as(u64, window.base) | permissions;
    }
}

fn programUnit(unit: UnitRegisters, root_table_base: u32) Error!void {
    var status = read32(unit.base + REG_GLOBAL_STATUS);
    if ((status & (GLOBAL_QUEUED_INVALIDATION_ENABLE | GLOBAL_INTERRUPT_REMAP_ENABLE)) != 0) {
        return error.FirmwareRemappingActive;
    }
    if ((status & GLOBAL_TRANSLATION_ENABLE) != 0) {
        writeGlobalCommand(unit.base, 0, GLOBAL_TRANSLATION_ENABLE);
        try waitForStatus(unit.base, GLOBAL_TRANSLATION_ENABLE, false);
    }

    write64(unit.base + REG_ROOT_TABLE_ADDRESS, root_table_base);
    publishTables();
    writeGlobalCommand(unit.base, GLOBAL_SET_ROOT_TABLE_POINTER, 0);
    try waitForStatus(unit.base, GLOBAL_SET_ROOT_TABLE_POINTER, true);

    if (!unit.enhanced_srtp) {
        write64(
            unit.base + REG_CONTEXT_COMMAND,
            CONTEXT_INVALIDATE | CONTEXT_GLOBAL_INVALIDATION,
        );
        try waitForCommand(unit.base + REG_CONTEXT_COMMAND, CONTEXT_INVALIDATE);
        if ((read64(unit.base + REG_CONTEXT_COMMAND) & CONTEXT_ACTUAL_GRANULARITY_MASK) == 0) {
            return error.CommandRejected;
        }

        write64(unit.iotlb, IOTLB_INVALIDATE | IOTLB_GLOBAL_INVALIDATION);
        try waitForCommand(unit.iotlb, IOTLB_INVALIDATE);
        if ((read64(unit.iotlb) & IOTLB_ACTUAL_GRANULARITY_MASK) == 0) {
            return error.CommandRejected;
        }
    }

    status = read32(unit.base + REG_GLOBAL_STATUS);
    if ((status & GLOBAL_TRANSLATION_ENABLE) == 0) {
        writeGlobalCommand(unit.base, GLOBAL_TRANSLATION_ENABLE, 0);
        try waitForStatus(unit.base, GLOBAL_TRANSLATION_ENABLE, true);
    }
}

fn writeGlobalCommand(base: usize, set_bits: u32, clear_bits: u32) void {
    const status = read32(base + REG_GLOBAL_STATUS);
    const command = ((status & GLOBAL_COMMAND_STATUS_MASK) & ~clear_bits) | set_bits;
    write32(base + REG_GLOBAL_COMMAND, command);
}

fn waitForStatus(base: usize, mask: u32, expected_set: bool) Error!void {
    var spins: u64 = 0;
    while (spins < COMMAND_SPIN_LIMIT) : (spins += 1) {
        const set = (read32(base + REG_GLOBAL_STATUS) & mask) != 0;
        if (set == expected_set) return;
        asm volatile ("pause");
    }
    return error.CommandTimeout;
}

fn waitForCommand(address: usize, pending_mask: u64) Error!void {
    var spins: u64 = 0;
    while (spins < COMMAND_SPIN_LIMIT) : (spins += 1) {
        if ((read64(address) & pending_mask) == 0) return;
        asm volatile ("pause");
    }
    return error.CommandTimeout;
}

fn requesterId(device_info: pci.PCIDevice) u16 {
    return (@as(u16, device_info.bus) << 8) |
        (@as(u16, device_info.device) << 3) |
        device_info.function;
}

fn tablePagePhysical(table_base: u32, page: u32) u64 {
    return @as(u64, table_base) + @as(u64, page) * PAGE_SIZE;
}

fn publishTables() void {
    if (comptime builtin.cpu.arch == .x86_64) {
        asm volatile ("mfence" ::: .{ .memory = true });
    } else {
        asm volatile ("" ::: .{ .memory = true });
    }
}

fn read32(address: usize) u32 {
    return @as(*volatile u32, @ptrFromInt(address)).*;
}

fn write32(address: usize, value: u32) void {
    @as(*volatile u32, @ptrFromInt(address)).* = value;
}

fn read64(address: usize) u64 {
    return @as(*volatile u64, @ptrFromInt(address)).*;
}

fn write64(address: usize, value: u64) void {
    @as(*volatile u64, @ptrFromInt(address)).* = value;
}

fn syntheticNvme() pci.PCIDevice {
    return .{
        .bus = 3,
        .device = 1,
        .function = 2,
        .vendor_id = 0x8086,
        .device_id = 0xF1A8,
        .class_code = pci.PCI_CLASS_STORAGE_CONTROLLER,
        .subclass = pci.PCI_SUBCLASS_NVM,
        .prog_if = pci.PCI_PROG_IF_NVME,
        .bar0 = 0,
        .bar1 = 0,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
    };
}

test "VT-d tables expose only the NVMe requester and exact DMA pages" {
    var tables: Tables align(PAGE_SIZE) = undefined;
    const table_base: u32 = 0x0100_0000;
    const windows = [_]DmaWindow{
        .{ .base = 0x0200_0000, .device_readable = true, .device_writable = false },
        .{ .base = 0x0200_1000, .device_readable = false, .device_writable = true },
        .{ .base = 0x0200_2000, .device_readable = true, .device_writable = true },
    };
    const device_info = syntheticNvme();
    populateTables(&tables, table_base, device_info, &windows, .bits39);

    const root_index = @as(usize, device_info.bus) * 2;
    try std.testing.expectEqual(tablePagePhysical(table_base, CONTEXT_PAGE) | PRESENT, tables[ROOT_PAGE][root_index]);
    try std.testing.expectEqual(@as(u64, 0), tables[ROOT_PAGE][0]);

    const context_index = (@as(usize, device_info.device) * 8 + device_info.function) * 2;
    try std.testing.expectEqual(tablePagePhysical(table_base, L3_PAGE) | PRESENT, tables[CONTEXT_PAGE][context_index]);
    try std.testing.expectEqual(
        (@as(u64, STORAGE_DOMAIN_ID) << 8) | @intFromEnum(AddressWidth.bits39),
        tables[CONTEXT_PAGE][context_index + 1],
    );
    try std.testing.expectEqual(@as(u64, 0), tables[CONTEXT_PAGE][0]);

    const leaf = tables[FIRST_LEAF_PAGE];
    try std.testing.expectEqual(@as(u64, windows[0].base) | SECOND_STAGE_READ, leaf[0]);
    try std.testing.expectEqual(@as(u64, windows[1].base) | SECOND_STAGE_WRITE, leaf[1]);
    try std.testing.expectEqual(
        @as(u64, windows[2].base) | SECOND_STAGE_READ | SECOND_STAGE_WRITE,
        leaf[2],
    );
    try std.testing.expectEqual(@as(u64, 0), leaf[3]);
}

test "VT-d tables allocate a distinct leaf table across a 2 MiB boundary" {
    var tables: Tables align(PAGE_SIZE) = undefined;
    const windows = [_]DmaWindow{
        .{ .base = 0x021F_F000, .device_readable = true, .device_writable = false },
        .{ .base = 0x0220_0000, .device_readable = false, .device_writable = true },
    };
    populateTables(&tables, 0x0100_0000, syntheticNvme(), &windows, .bits48);

    const first_l2: usize = @intCast((windows[0].base >> 21) & 0x1FF);
    const second_l2: usize = @intCast((windows[1].base >> 21) & 0x1FF);
    try std.testing.expect(first_l2 != second_l2);
    try std.testing.expectEqual(tablePagePhysical(0x0100_0000, FIRST_LEAF_PAGE) | 3, tables[L2_PAGE][first_l2]);
    try std.testing.expectEqual(tablePagePhysical(0x0100_0000, FIRST_LEAF_PAGE + 1) | 3, tables[L2_PAGE][second_l2]);
    try std.testing.expectEqual(tablePagePhysical(0x0100_0000, L3_PAGE) | 3, tables[L4_PAGE][0]);
}

test "VT-d window policy rejects aliases and capability selection prefers fewer walks" {
    const aliased = [_]DmaWindow{
        .{ .base = 0x0200_0000, .device_readable = true, .device_writable = false },
        .{ .base = 0x0200_0000, .device_readable = false, .device_writable = true },
    };
    try std.testing.expectError(error.InvalidDmaWindow, validateWindows(&aliased));
    try std.testing.expectEqual(AddressWidth.bits39, chooseAddressWidth(0b00110).?);
    try std.testing.expectEqual(AddressWidth.bits48, chooseAddressWidth(0b00100).?);
    try std.testing.expect(chooseAddressWidth(0b00001) == null);
}
