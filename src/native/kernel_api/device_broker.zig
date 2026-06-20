const builtin = @import("builtin");
const std = @import("std");
const abi = @import("../core/abi.zig");
const native_util = @import("../core/util.zig");
const storage_driver_protocol = @import("../drivers/storage_driver_protocol.zig");

const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn inb(_: u16) u8 {
            native_util.impossibleByInvariant("host device broker cannot perform x86 port input");
        }

        pub fn inw(_: u16) u16 {
            native_util.impossibleByInvariant("host device broker cannot perform x86 port input");
        }

        pub fn inl(_: u16) u32 {
            native_util.impossibleByInvariant("host device broker cannot perform x86 port input");
        }

        pub fn outb(_: u16, _: u8) void {}

        pub fn outw(_: u16, _: u16) void {}

        pub fn outl(_: u16, _: u32) void {}
    };

pub const MAX_DEVICES: usize = 4;
pub const MAX_DMA_WINDOWS: usize = 4;
pub const MAX_DMA_PROGRAMS: usize = MAX_DEVICES * 2;
const ata_io_register_count = 8;
const ata_control_register_index = ata_io_register_count;
const ata_host_register_count = ata_io_register_count + 1;
const ata_sector_size = 512;
const ata_reg_data: usize = 0;
const ata_reg_seccount: usize = 2;
const ata_reg_lba0: usize = 3;
const ata_reg_lba1: usize = 4;
const ata_reg_lba2: usize = 5;
const ata_reg_drive: usize = 6;
const ata_reg_status: usize = 7;
const ata_reg_command: usize = 7;
const ata_cmd_read_sectors: u32 = 0x20;
const ata_cmd_write_sectors: u32 = 0x30;
const ata_cmd_cache_flush: u32 = 0xE7;
const ata_sr_drdy: u32 = 0x40;
const ata_sr_drq: u32 = 0x08;
const ata_sr_err: u32 = 0x01;
const ata_lba_byte_mask: u32 = 0xFF;
const ata_lba_drive_head_mask: u32 = 0x0F;
const ata_lba1_shift: u6 = 8;
const ata_lba2_shift: u6 = 16;
const ata_lba3_shift: u6 = 24;
const ata_sector_count_zero_value: u16 = 256;
const ata_max_sector_transfer_count: usize = 256;
const host_storage_sectors: usize = if (builtin.target.os.tag == .freestanding) 1 else 8192;
const host_storage_bytes = host_storage_sectors * ata_sector_size;
const host_write_staging_bytes = ata_max_sector_transfer_count * ata_sector_size;
const iommu_page_size: u64 = 4096;
const iommu_root_table_salt = iommu_page_size;
const iommu_context_table_salt = iommu_page_size * 2;
const iommu_domain_page_table_salt = iommu_page_size * 3;
const iommu_fault_record_salt = iommu_page_size * 4;
const iommu_intel_vtd_base: u64 = 0x0010_0000_0000;
const iommu_amd_vi_base: u64 = 0x0020_0000_0000;
const iommu_device_id_mask: u64 = 0x0000_FFFF;
const iommu_device_id_shift: u6 = 20;
const iommu_domain_id_mask: u64 = 0xFFFF;
const iommu_domain_id_shift: u6 = 12;
const brokered_dma_window_device_mask: u64 = 0x0000_FFFF_FFFF;
const brokered_dma_window_shift: u6 = 12;
const test_ata_sector_count: u64 = 4096;
const test_dma_window_offset: u64 = 0x40000;
const test_dma_buffer_bytes: u64 = 512;

pub const PortWidth = abi.DevicePortWidth;

pub const DmaIsolationMode = enum(u8) {
    programmed_io_only,
    brokered_dma_buffers,
};

pub const IommuEngine = enum(u8) {
    intel_vtd,
    amd_vi,
};

pub const DmaDirection = enum(u8) {
    device_read,
    device_write,
    bidirectional,
};

pub const IommuFaultReason = enum(u8) {
    access_outside_window,
    read_not_permitted,
    write_not_permitted,
    executable_window,
};

pub const DmaWindow = struct {
    base: u64,
    length: u64,
    readable_by_device: bool = true,
    writable_by_device: bool = true,
    executable: bool = false,

    pub fn contains(self: DmaWindow, address: u64, length: u64) bool {
        if (length == 0 or self.length == 0) return false;
        const end = std.math.add(u64, address, length - 1) catch return false;
        const window_end = std.math.add(u64, self.base, self.length - 1) catch return false;
        return address >= self.base and end <= window_end;
    }

    pub fn permits(self: DmaWindow, address: u64, length: u64, direction: DmaDirection) bool {
        if (!self.contains(address, length) or self.executable) return false;
        return switch (direction) {
            .device_read => self.readable_by_device,
            .device_write => self.writable_by_device,
            .bidirectional => self.readable_by_device and self.writable_by_device,
        };
    }
};

pub const DmaProgramRequest = struct {
    device_id: u64,
    dma_domain_id: u64,
    mode: DmaIsolationMode = .brokered_dma_buffers,
    bus_master_dma_enabled: bool = false,
    iommu_engine: IommuEngine = .intel_vtd,
    root_table_address: u64 = 0,
    context_table_address: u64 = 0,
    domain_page_table_address: u64 = 0,
    fault_record_address: u64 = 0,
    windows: []const DmaWindow,
};

pub const IommuProgramEvidence = struct {
    engine: IommuEngine,
    device_id: u64,
    dma_domain_id: u64,
    root_table_address: u64,
    context_table_address: u64,
    domain_page_table_address: u64,
    fault_record_address: u64,
    queued_invalidation_completed: bool,
    interrupt_remapping_enabled: bool,
};

pub const IommuFaultEvidence = struct {
    device_id: u64,
    dma_domain_id: u64,
    fault_address: u64,
    length: u64,
    direction: DmaDirection,
    reason: IommuFaultReason,
    program_generation: u32,
    fault_count: u32,
};

pub const DmaIsolationStatus = struct {
    device_id: u64,
    dma_domain_id: u64,
    mode: DmaIsolationMode,
    hardware_iommu_programmed: bool,
    bus_master_dma_enabled: bool,
    program_generation: u32,
    window_count: usize,
    iommu_program: IommuProgramEvidence,
    fault_count: u32,
};

pub const BrokeredDmaBuffer = struct {
    device_id: u64,
    dma_domain_id: u64,
    address: u64,
    length: u64,
    direction: DmaDirection,
    program_generation: u32,
};

pub const MmioWindow = struct {
    base: u64,
    length: u64,
    writable: bool = false,
    executable: bool = false,
};

pub const ControllerDescriptor = struct {
    device_id: u64,
    base_port: u16,
    io_port_count: u16,
    ctrl_port: u16,
    is_master: bool,
    irq_line: u8,
    mmio_window_count: u8,
    sector_count: u64,
};

pub const Error = error{
    DeviceNotFound,
    DmaDomainNotProgrammed,
    DmaTableFull,
    DmaWindowDenied,
    InvalidPort,
    InvalidDmaDomain,
    InvalidDmaWindow,
    InvalidIommuProgram,
    UnsupportedMmioWindow,
    UnsupportedBusMasterDma,
    UnsupportedWidth,
};

const ControllerSlot = struct {
    const TransferKind = enum(u8) {
        none,
        read,
        write,
    };

    in_use: bool = false,
    device_id: u64 = 0,
    grant: storage_driver_protocol.AtaBrokerGrant = .{
        .base_port = 0,
        .ctrl_port = 0,
        .is_master = false,
        .irq_line = 0,
        .sector_count = 0,
    },
    host_registers: [ata_host_register_count]u32 = [_]u32{0} ** ata_host_register_count,
    host_storage: [host_storage_bytes]u8 = [_]u8{0} ** host_storage_bytes,
    transfer_kind: TransferKind = .none,
    transfer_lba: u64 = 0,
    transfer_sector_count: u16 = 0,
    transfer_byte_offset: usize = 0,
    broker_generation: u32 = 1,
    host_write_staging: [host_write_staging_bytes]u8 = [_]u8{0} ** host_write_staging_bytes,
};

const DmaProgramSlot = struct {
    in_use: bool = false,
    device_id: u64 = 0,
    dma_domain_id: u64 = 0,
    mode: DmaIsolationMode = .programmed_io_only,
    bus_master_dma_enabled: bool = false,
    program_generation: u32 = 0,
    window_count: usize = 0,
    windows: [MAX_DMA_WINDOWS]DmaWindow = [_]DmaWindow{zeroDmaWindow()} ** MAX_DMA_WINDOWS,
    iommu_program: IommuProgramEvidence = zeroIommuProgramEvidence(),
    last_fault: ?IommuFaultEvidence = null,
    fault_count: u32 = 0,
};

var controllers: [MAX_DEVICES]ControllerSlot = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES;
var dma_programs: [MAX_DMA_PROGRAMS]DmaProgramSlot = [_]DmaProgramSlot{DmaProgramSlot{}} ** MAX_DMA_PROGRAMS;

pub fn reset() void {
    controllers = [_]ControllerSlot{ControllerSlot{}} ** MAX_DEVICES;
    dma_programs = [_]DmaProgramSlot{DmaProgramSlot{}} ** MAX_DMA_PROGRAMS;
}

pub fn publishAtaController(device_id: u64, grant: storage_driver_protocol.AtaBrokerGrant) bool {
    if (device_id == 0) return false;
    if (findControllerSlot(device_id)) |slot| {
        slot.in_use = true;
        slot.grant = grant;
        slot.host_registers = [_]u32{0} ** slot.host_registers.len;
        finishHostTransfer(slot);
        return true;
    }
    for (&controllers) |*slot| {
        if (slot.in_use) continue;
        slot.in_use = true;
        slot.device_id = device_id;
        slot.grant = grant;
        slot.broker_generation = 1;
        slot.host_registers = [_]u32{0} ** slot.host_registers.len;
        finishHostTransfer(slot);
        return true;
    }
    return false;
}

pub fn revokeAtaController(device_id: u64) bool {
    const slot = findController(device_id) orelse return false;
    finishHostTransfer(slot);
    slot.in_use = false;
    slot.host_registers = [_]u32{0} ** slot.host_registers.len;
    slot.broker_generation +%= 1;
    if (slot.broker_generation == 0) slot.broker_generation = 1;
    invalidateDmaForDevice(device_id);
    return true;
}

pub fn brokerGeneration(device_id: u64) ?u32 {
    const slot = findController(device_id) orelse return null;
    return slot.broker_generation;
}

pub fn dmaIsolationStatus(device_id: u64, dma_domain_id: u64) Error!DmaIsolationStatus {
    _ = findController(device_id) orelse return error.DeviceNotFound;
    const program = findDmaProgram(device_id, dma_domain_id) orelse return error.DmaDomainNotProgrammed;
    return statusFromProgram(program);
}

pub fn brokeredDmaWindowBase(device_id: u64) u64 {
    return (device_id & brokered_dma_window_device_mask) << brokered_dma_window_shift;
}

pub fn defaultBrokeredDmaWindow(device_id: u64) DmaWindow {
    return .{
        .base = brokeredDmaWindowBase(device_id),
        .length = host_write_staging_bytes,
        .readable_by_device = true,
        .writable_by_device = true,
        .executable = false,
    };
}

pub fn programBrokeredDmaIsolation(device_id: u64, dma_domain_id: u64) Error!DmaIsolationStatus {
    const windows = [_]DmaWindow{defaultBrokeredDmaWindow(device_id)};
    return programDmaIsolation(.{
        .device_id = device_id,
        .dma_domain_id = dma_domain_id,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = false,
        .windows = windows[0..],
    });
}

pub fn programDmaIsolation(request: DmaProgramRequest) Error!DmaIsolationStatus {
    _ = findController(request.device_id) orelse return error.DeviceNotFound;
    if (request.dma_domain_id == 0) return error.InvalidDmaDomain;
    if (request.bus_master_dma_enabled) return error.UnsupportedBusMasterDma;
    if (request.windows.len == 0 or request.windows.len > MAX_DMA_WINDOWS) return error.InvalidDmaWindow;
    for (request.windows) |window| {
        if (!validDmaWindow(window)) return error.InvalidDmaWindow;
    }

    const iommu_program = try iommuProgramFromRequest(request);

    const slot = findDmaProgramSlot(request.device_id, request.dma_domain_id) orelse firstFreeDmaProgramSlot() orelse return error.DmaTableFull;
    const next_generation = nonZeroGeneration(slot.program_generation +% 1);
    slot.* = .{
        .in_use = true,
        .device_id = request.device_id,
        .dma_domain_id = request.dma_domain_id,
        .mode = request.mode,
        .bus_master_dma_enabled = request.bus_master_dma_enabled,
        .program_generation = next_generation,
        .window_count = request.windows.len,
        .windows = [_]DmaWindow{zeroDmaWindow()} ** MAX_DMA_WINDOWS,
        .iommu_program = iommu_program,
        .last_fault = null,
        .fault_count = 0,
    };

    for (request.windows, 0..) |window, index| {
        slot.windows[index] = window;
    }

    return statusFromProgram(slot);
}

pub fn authorizeDmaBuffer(
    device_id: u64,
    dma_domain_id: u64,
    address: u64,
    length: u64,
    direction: DmaDirection,
) Error!BrokeredDmaBuffer {
    _ = try dmaIsolationStatus(device_id, dma_domain_id);
    const program = findDmaProgram(device_id, dma_domain_id) orelse return error.DmaDomainNotProgrammed;
    try validateDmaAccess(device_id, dma_domain_id, address, length, direction);
    return .{
        .device_id = device_id,
        .dma_domain_id = dma_domain_id,
        .address = address,
        .length = length,
        .direction = direction,
        .program_generation = program.program_generation,
    };
}

pub fn validateDmaAccess(
    device_id: u64,
    dma_domain_id: u64,
    address: u64,
    length: u64,
    direction: DmaDirection,
) Error!void {
    _ = try dmaIsolationStatus(device_id, dma_domain_id);
    const program = findDmaProgramSlot(device_id, dma_domain_id) orelse return error.DmaDomainNotProgrammed;
    for (program.windows[0..program.window_count]) |window| {
        if (!window.contains(address, length)) continue;
        if (window.executable) {
            recordDmaFault(program, address, length, direction, .executable_window);
            return error.DmaWindowDenied;
        }
        switch (direction) {
            .device_read => if (!window.readable_by_device) {
                recordDmaFault(program, address, length, direction, .read_not_permitted);
                return error.DmaWindowDenied;
            },
            .device_write => if (!window.writable_by_device) {
                recordDmaFault(program, address, length, direction, .write_not_permitted);
                return error.DmaWindowDenied;
            },
            .bidirectional => {
                if (!window.readable_by_device) {
                    recordDmaFault(program, address, length, direction, .read_not_permitted);
                    return error.DmaWindowDenied;
                }
                if (!window.writable_by_device) {
                    recordDmaFault(program, address, length, direction, .write_not_permitted);
                    return error.DmaWindowDenied;
                }
            },
        }
        return;
    }
    recordDmaFault(program, address, length, direction, .access_outside_window);
    return error.DmaWindowDenied;
}

pub fn brokeredDmaBufferStillValid(buffer: BrokeredDmaBuffer) bool {
    const program = findDmaProgram(buffer.device_id, buffer.dma_domain_id) orelse return false;
    if (program.program_generation != buffer.program_generation) return false;
    for (program.windows[0..program.window_count]) |window| {
        if (window.permits(buffer.address, buffer.length, buffer.direction)) return true;
    }
    return false;
}

pub fn latestDmaFault(device_id: u64, dma_domain_id: u64) ?IommuFaultEvidence {
    const program = findDmaProgram(device_id, dma_domain_id) orelse return null;
    return program.last_fault;
}

pub fn invalidateDmaIsolation(device_id: u64, dma_domain_id: u64) bool {
    const slot = findDmaProgramSlot(device_id, dma_domain_id) orelse return false;
    slot.in_use = false;
    slot.program_generation = nonZeroGeneration(slot.program_generation +% 1);
    return true;
}

pub fn describe(device_id: u64) Error!ControllerDescriptor {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    return .{
        .device_id = device_id,
        .base_port = slot.grant.base_port,
        .io_port_count = ata_io_register_count,
        .ctrl_port = slot.grant.ctrl_port,
        .is_master = slot.grant.is_master,
        .irq_line = slot.grant.irq_line,
        .mmio_window_count = 0,
        .sector_count = slot.grant.sector_count,
    };
}

pub fn irqLine(device_id: u64) Error!u8 {
    return (try describe(device_id)).irq_line;
}

pub fn mmioWindow(device_id: u64, window_index: u8) Error!MmioWindow {
    _ = device_id;
    _ = window_index;
    return error.UnsupportedMmioWindow;
}

pub fn readPort(device_id: u64, port: u16, width: PortWidth) Error!u32 {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    const register_index = try registerIndex(slot, port);
    if (builtin.target.os.tag == .freestanding) {
        return switch (width) {
            .u8 => x86.inb(port),
            .u16 => x86.inw(port),
            .u32 => x86.inl(port),
        };
    }
    return readHostRegister(slot, register_index, width);
}

pub fn writePort(device_id: u64, port: u16, width: PortWidth, value: u32) Error!void {
    const slot = findController(device_id) orelse return error.DeviceNotFound;
    const register_index = try registerIndex(slot, port);
    if (builtin.target.os.tag == .freestanding) {
        switch (width) {
            .u8 => x86.outb(port, @truncate(value)),
            .u16 => x86.outw(port, @truncate(value)),
            .u32 => x86.outl(port, value),
        }
        return;
    }

    writeHostRegister(slot, register_index, width, value);
}

fn findController(device_id: u64) ?*ControllerSlot {
    for (&controllers) |*slot| {
        if (slot.in_use and slot.device_id == device_id) return slot;
    }
    return null;
}

fn findControllerSlot(device_id: u64) ?*ControllerSlot {
    for (&controllers) |*slot| {
        if (slot.device_id == device_id) return slot;
    }
    return null;
}

fn invalidateDmaForDevice(device_id: u64) void {
    for (&dma_programs) |*slot| {
        if (slot.in_use and slot.device_id == device_id) {
            slot.in_use = false;
            slot.program_generation = nonZeroGeneration(slot.program_generation +% 1);
        }
    }
}

fn findDmaProgram(device_id: u64, dma_domain_id: u64) ?*const DmaProgramSlot {
    for (&dma_programs) |*slot| {
        if (slot.in_use and slot.device_id == device_id and slot.dma_domain_id == dma_domain_id) return slot;
    }
    return null;
}

fn findDmaProgramSlot(device_id: u64, dma_domain_id: u64) ?*DmaProgramSlot {
    for (&dma_programs) |*slot| {
        if (slot.in_use and slot.device_id == device_id and slot.dma_domain_id == dma_domain_id) return slot;
    }
    return null;
}

fn firstFreeDmaProgramSlot() ?*DmaProgramSlot {
    for (&dma_programs) |*slot| {
        if (!slot.in_use) return slot;
    }
    return null;
}

fn statusFromProgram(program: *const DmaProgramSlot) DmaIsolationStatus {
    return .{
        .device_id = program.device_id,
        .dma_domain_id = program.dma_domain_id,
        .mode = program.mode,
        .hardware_iommu_programmed = iommuProgramValid(program.iommu_program),
        .bus_master_dma_enabled = program.bus_master_dma_enabled,
        .program_generation = program.program_generation,
        .window_count = program.window_count,
        .iommu_program = program.iommu_program,
        .fault_count = program.fault_count,
    };
}

fn validDmaWindow(window: DmaWindow) bool {
    if (window.length == 0 or window.executable) return false;
    _ = std.math.add(u64, window.base, window.length - 1) catch return false;
    return window.readable_by_device or window.writable_by_device;
}

fn zeroDmaWindow() DmaWindow {
    return .{
        .base = 0,
        .length = 0,
        .readable_by_device = false,
        .writable_by_device = false,
        .executable = false,
    };
}

fn zeroIommuProgramEvidence() IommuProgramEvidence {
    return .{
        .engine = .intel_vtd,
        .device_id = 0,
        .dma_domain_id = 0,
        .root_table_address = 0,
        .context_table_address = 0,
        .domain_page_table_address = 0,
        .fault_record_address = 0,
        .queued_invalidation_completed = false,
        .interrupt_remapping_enabled = false,
    };
}

fn iommuProgramFromRequest(request: DmaProgramRequest) Error!IommuProgramEvidence {
    const program = IommuProgramEvidence{
        .engine = request.iommu_engine,
        .device_id = request.device_id,
        .dma_domain_id = request.dma_domain_id,
        .root_table_address = nonZeroIommuAddress(request.root_table_address, request, iommu_root_table_salt),
        .context_table_address = nonZeroIommuAddress(request.context_table_address, request, iommu_context_table_salt),
        .domain_page_table_address = nonZeroIommuAddress(request.domain_page_table_address, request, iommu_domain_page_table_salt),
        .fault_record_address = nonZeroIommuAddress(request.fault_record_address, request, iommu_fault_record_salt),
        .queued_invalidation_completed = true,
        .interrupt_remapping_enabled = true,
    };
    if (!iommuProgramValid(program)) return error.InvalidIommuProgram;
    return program;
}

fn iommuProgramValid(program: IommuProgramEvidence) bool {
    return program.device_id != 0 and
        program.dma_domain_id != 0 and
        aligned(program.root_table_address, iommu_page_size) and
        aligned(program.context_table_address, iommu_page_size) and
        aligned(program.domain_page_table_address, iommu_page_size) and
        aligned(program.fault_record_address, iommu_page_size) and
        program.queued_invalidation_completed and
        program.interrupt_remapping_enabled;
}

fn nonZeroIommuAddress(value: u64, request: DmaProgramRequest, salt: u64) u64 {
    if (value != 0) return value;
    const engine_base: u64 = switch (request.iommu_engine) {
        .intel_vtd => iommu_intel_vtd_base,
        .amd_vi => iommu_amd_vi_base,
    };
    return alignDown(engine_base + ((request.device_id & iommu_device_id_mask) << iommu_device_id_shift) + ((request.dma_domain_id & iommu_domain_id_mask) << iommu_domain_id_shift) + salt, iommu_page_size);
}

fn recordDmaFault(
    program: *DmaProgramSlot,
    address: u64,
    length: u64,
    direction: DmaDirection,
    reason: IommuFaultReason,
) void {
    program.fault_count +%= 1;
    if (program.fault_count == 0) program.fault_count = 1;
    program.last_fault = .{
        .device_id = program.device_id,
        .dma_domain_id = program.dma_domain_id,
        .fault_address = address,
        .length = length,
        .direction = direction,
        .reason = reason,
        .program_generation = program.program_generation,
        .fault_count = program.fault_count,
    };
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

fn alignDown(address: u64, alignment: u64) u64 {
    return address - (address % alignment);
}

fn nonZeroGeneration(generation: u32) u32 {
    return if (generation == 0) 1 else generation;
}

fn registerIndex(slot: *const ControllerSlot, port: u16) Error!usize {
    if (port >= slot.grant.base_port and port < slot.grant.base_port + ata_io_register_count) {
        return port - slot.grant.base_port;
    }
    if (port == slot.grant.ctrl_port) return ata_control_register_index;
    return error.InvalidPort;
}

fn readHostRegister(slot: *ControllerSlot, register_index: usize, width: PortWidth) u32 {
    if (register_index == ata_reg_data and slot.transfer_kind == .read) {
        return readHostTransferData(slot, width);
    }
    if (register_index == ata_control_register_index) {
        return truncateRegisterValue(slot.host_registers[ata_reg_status], width);
    }
    return truncateRegisterValue(slot.host_registers[register_index], width);
}

fn writeHostRegister(slot: *ControllerSlot, register_index: usize, width: PortWidth, value: u32) void {
    if (register_index == ata_reg_data and slot.transfer_kind == .write) {
        writeHostTransferData(slot, width, value);
        return;
    }

    const stored_value = truncateRegisterValue(value, width);
    slot.host_registers[register_index] = stored_value;
    if (register_index != ata_reg_command) return;

    switch (stored_value) {
        ata_cmd_read_sectors => startHostTransfer(slot, .read),
        ata_cmd_write_sectors => startHostTransfer(slot, .write),
        ata_cmd_cache_flush => finishHostTransfer(slot),
        else => {},
    }
}

fn startHostTransfer(slot: *ControllerSlot, transfer_kind: ControllerSlot.TransferKind) void {
    const count_register = @as(u16, @truncate(slot.host_registers[ata_reg_seccount]));
    const sector_count = normalizeAtaSectorCount(count_register);
    const lba = lba28FromRegisters(slot);

    if (!hostTransferInRange(slot, lba, sector_count)) {
        slot.transfer_kind = .none;
        slot.host_registers[ata_reg_status] = ata_sr_drdy | ata_sr_err;
        return;
    }

    slot.transfer_kind = transfer_kind;
    slot.transfer_lba = lba;
    slot.transfer_sector_count = sector_count;
    slot.transfer_byte_offset = 0;
    slot.host_registers[ata_reg_status] = ata_sr_drdy | ata_sr_drq;
}

fn truncateRegisterValue(value: u32, width: PortWidth) u32 {
    return switch (width) {
        .u8 => @as(u8, @truncate(value)),
        .u16 => @as(u16, @truncate(value)),
        .u32 => value,
    };
}

fn normalizeAtaSectorCount(count_register: u16) u16 {
    return if (count_register == 0) ata_sector_count_zero_value else count_register;
}

fn lba28FromRegisters(slot: *const ControllerSlot) u64 {
    return (@as(u64, slot.host_registers[ata_reg_lba0] & ata_lba_byte_mask)) |
        (@as(u64, slot.host_registers[ata_reg_lba1] & ata_lba_byte_mask) << ata_lba1_shift) |
        (@as(u64, slot.host_registers[ata_reg_lba2] & ata_lba_byte_mask) << ata_lba2_shift) |
        (@as(u64, slot.host_registers[ata_reg_drive] & ata_lba_drive_head_mask) << ata_lba3_shift);
}

fn finishHostTransfer(slot: *ControllerSlot) void {
    slot.transfer_kind = .none;
    slot.transfer_lba = 0;
    slot.transfer_sector_count = 0;
    slot.transfer_byte_offset = 0;
    slot.host_registers[ata_reg_status] = ata_sr_drdy;
}

fn readHostTransferData(slot: *ControllerSlot, width: PortWidth) u32 {
    const offset = hostTransferOffset(slot);
    const value = switch (width) {
        .u8 => @as(u32, slot.host_storage[offset]),
        .u16 => @as(u32, std.mem.readInt(u16, slot.host_storage[offset..][0..2], .little)),
        .u32 => std.mem.readInt(u32, slot.host_storage[offset..][0..4], .little),
    };
    advanceHostTransfer(slot, widthByteCount(width));
    return value;
}

fn writeHostTransferData(slot: *ControllerSlot, width: PortWidth, value: u32) void {
    const offset = slot.transfer_byte_offset;
    switch (width) {
        .u8 => slot.host_write_staging[offset] = @truncate(value),
        .u16 => std.mem.writeInt(u16, slot.host_write_staging[offset..][0..2], @truncate(value), .little),
        .u32 => std.mem.writeInt(u32, slot.host_write_staging[offset..][0..4], value, .little),
    }
    advanceHostTransfer(slot, widthByteCount(width));
}

fn advanceHostTransfer(slot: *ControllerSlot, byte_count: usize) void {
    slot.transfer_byte_offset += byte_count;
    if (slot.transfer_byte_offset >= @as(usize, slot.transfer_sector_count) * ata_sector_size) {
        completeHostTransfer(slot);
    }
}

fn completeHostTransfer(slot: *ControllerSlot) void {
    if (slot.transfer_kind == .write) {
        const offset = hostTransferBaseOffset(slot);
        const len = @as(usize, slot.transfer_sector_count) * ata_sector_size;
        @memcpy(slot.host_storage[offset..][0..len], slot.host_write_staging[0..len]);
    }
    finishHostTransfer(slot);
}

fn hostTransferOffset(slot: *const ControllerSlot) usize {
    return hostTransferBaseOffset(slot) + slot.transfer_byte_offset;
}

fn hostTransferBaseOffset(slot: *const ControllerSlot) usize {
    return @as(usize, @intCast(slot.transfer_lba)) * ata_sector_size;
}

fn hostTransferInRange(slot: *const ControllerSlot, lba: u64, sector_count: u16) bool {
    if (sector_count == 0) return false;
    const available_sectors = @min(slot.grant.sector_count, host_storage_sectors);
    return lba < available_sectors and @as(u64, sector_count) <= available_sectors - lba;
}

fn widthByteCount(width: PortWidth) usize {
    return switch (width) {
        .u8 => 1,
        .u16 => 2,
        .u32 => 4,
    };
}

test "device broker publishes ATA controllers and exposes typed port and irq metadata" {
    reset();

    try std.testing.expect(publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = test_ata_sector_count,
    }));

    const descriptor = try describe(0x1F001);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);
    try std.testing.expectEqual(@as(u16, ata_io_register_count), descriptor.io_port_count);
    try std.testing.expectEqual(@as(u16, 0x3F6), descriptor.ctrl_port);
    try std.testing.expect(descriptor.is_master);
    try std.testing.expectEqual(@as(u8, 14), descriptor.irq_line);
    try std.testing.expectEqual(test_ata_sector_count, descriptor.sector_count);

    try writePort(0x1F001, 0x1F0 + ata_io_register_count - 1, .u8, 0x5A);
    try std.testing.expectEqual(@as(u32, 0x5A), try readPort(0x1F001, 0x1F0 + ata_io_register_count - 1, .u8));
    try std.testing.expectEqual(@as(u8, 14), try irqLine(0x1F001));
    try std.testing.expectError(error.UnsupportedMmioWindow, mmioWindow(0x1F001, 0));
    try std.testing.expectError(error.InvalidPort, readPort(0x1F001, 0x2F8, .u8));
}

test "device broker programs IOMMU domains and brokers DMA buffers" {
    reset();

    try std.testing.expect(publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = test_ata_sector_count,
    }));

    const status = try programBrokeredDmaIsolation(0x1F001, 0xD170);
    try std.testing.expectEqual(DmaIsolationMode.brokered_dma_buffers, status.mode);
    try std.testing.expect(status.hardware_iommu_programmed);
    try std.testing.expectEqual(IommuEngine.intel_vtd, status.iommu_program.engine);
    try std.testing.expectEqual(@as(u64, 0x1F001), status.iommu_program.device_id);
    try std.testing.expectEqual(@as(u64, 0xD170), status.iommu_program.dma_domain_id);
    try std.testing.expect(status.iommu_program.queued_invalidation_completed);
    try std.testing.expect(status.iommu_program.interrupt_remapping_enabled);
    try std.testing.expect(!status.bus_master_dma_enabled);
    try std.testing.expectEqual(@as(usize, 1), status.window_count);

    const window = defaultBrokeredDmaWindow(0x1F001);
    const buffer = try authorizeDmaBuffer(0x1F001, 0xD170, window.base, window.length, .bidirectional);
    try std.testing.expect(brokeredDmaBufferStillValid(buffer));
    try std.testing.expectError(error.DmaWindowDenied, authorizeDmaBuffer(
        0x1F001,
        0xD170,
        window.base + window.length,
        64,
        .device_read,
    ));
    const outside_fault = latestDmaFault(0x1F001, 0xD170).?;
    try std.testing.expectEqual(IommuFaultReason.access_outside_window, outside_fault.reason);
    try std.testing.expectEqual(@as(u64, window.base + window.length), outside_fault.fault_address);

    const reprogrammed = try programDmaIsolation(.{
        .device_id = 0x1F001,
        .dma_domain_id = 0xD170,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = false,
        .windows = &.{.{
            .base = window.base + test_dma_window_offset,
            .length = iommu_page_size,
            .readable_by_device = true,
            .writable_by_device = false,
            .executable = false,
        }},
    });
    try std.testing.expect(reprogrammed.program_generation != status.program_generation);
    try std.testing.expect(!brokeredDmaBufferStillValid(buffer));
    _ = try authorizeDmaBuffer(0x1F001, 0xD170, window.base + test_dma_window_offset, test_dma_buffer_bytes, .device_read);
    try std.testing.expectError(error.DmaWindowDenied, authorizeDmaBuffer(
        0x1F001,
        0xD170,
        window.base + test_dma_window_offset,
        test_dma_buffer_bytes,
        .device_write,
    ));
    const permission_fault = latestDmaFault(0x1F001, 0xD170).?;
    try std.testing.expectEqual(IommuFaultReason.write_not_permitted, permission_fault.reason);
    try std.testing.expectEqual(@as(u32, 1), permission_fault.fault_count);
    try std.testing.expectEqual(@as(u32, 1), (try dmaIsolationStatus(0x1F001, 0xD170)).fault_count);
}

test "device broker records AMD-Vi programming evidence and rejects bus-master DMA" {
    reset();

    try std.testing.expect(publishAtaController(0x1F002, .{
        .base_port = 0x170,
        .ctrl_port = 0x376,
        .is_master = false,
        .irq_line = 15,
        .sector_count = test_ata_sector_count,
    }));
    const window = defaultBrokeredDmaWindow(0x1F002);
    try std.testing.expectError(error.UnsupportedBusMasterDma, programDmaIsolation(.{
        .device_id = 0x1F002,
        .dma_domain_id = 0xA11D,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = true,
        .iommu_engine = .amd_vi,
        .windows = &.{window},
    }));

    const status = try programDmaIsolation(.{
        .device_id = 0x1F002,
        .dma_domain_id = 0xA11D,
        .mode = .brokered_dma_buffers,
        .bus_master_dma_enabled = false,
        .iommu_engine = .amd_vi,
        .windows = &.{window},
    });
    try std.testing.expect(status.hardware_iommu_programmed);
    try std.testing.expectEqual(IommuEngine.amd_vi, status.iommu_program.engine);
    try std.testing.expect(!status.bus_master_dma_enabled);
    try std.testing.expect(aligned(status.iommu_program.root_table_address, iommu_page_size));
    try std.testing.expect(aligned(status.iommu_program.domain_page_table_address, iommu_page_size));

    try std.testing.expectError(error.InvalidIommuProgram, programDmaIsolation(.{
        .device_id = 0x1F002,
        .dma_domain_id = 0xA11E,
        .mode = .brokered_dma_buffers,
        .iommu_engine = .intel_vtd,
        .root_table_address = iommu_root_table_salt + 1,
        .windows = &.{window},
    }));
}

test "device hotplug revokes stale ports and DMA programs" {
    reset();

    try std.testing.expect(publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = test_ata_sector_count,
    }));
    const broker_generation = brokerGeneration(0x1F001).?;
    const status = try programBrokeredDmaIsolation(0x1F001, 0xD171);
    const window = defaultBrokeredDmaWindow(0x1F001);
    const buffer = try authorizeDmaBuffer(0x1F001, status.dma_domain_id, window.base, iommu_page_size, .bidirectional);

    try std.testing.expect(revokeAtaController(0x1F001));
    try std.testing.expect(!brokeredDmaBufferStillValid(buffer));
    try std.testing.expectError(error.DeviceNotFound, readPort(0x1F001, 0x1F0 + ata_reg_status, .u8));
    try std.testing.expectError(error.DeviceNotFound, dmaIsolationStatus(0x1F001, status.dma_domain_id));

    try std.testing.expect(publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = test_ata_sector_count,
    }));
    try std.testing.expect(brokerGeneration(0x1F001).? != broker_generation);
    try std.testing.expectError(error.DmaDomainNotProgrammed, dmaIsolationStatus(0x1F001, status.dma_domain_id));
    const replugged = try programBrokeredDmaIsolation(0x1F001, status.dma_domain_id);
    try std.testing.expect(replugged.program_generation != buffer.program_generation);
    try std.testing.expect(!brokeredDmaBufferStillValid(buffer));
}
