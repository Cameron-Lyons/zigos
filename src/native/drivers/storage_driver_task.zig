const std = @import("std");
const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const device_broker_client = @import("../kernel_api/device_broker_client.zig");
const root = @import("root");
const storage_volume = if (builtin.target.os.tag == .freestanding and @hasDecl(root, "storage_volume"))
    root.storage_volume
else
    @import("../storage/storage_volume.zig");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {};
const units = @import("../core/units.zig");

const ATA_REG_DATA: u16 = 0;
const ATA_REG_SECCOUNT: u16 = 2;
const ATA_REG_LBA0: u16 = 3;
const ATA_REG_LBA1: u16 = 4;
const ATA_REG_LBA2: u16 = 5;
const ATA_REG_DRIVE: u16 = 6;
const ATA_REG_STATUS: u16 = 7;
const ATA_REG_COMMAND: u16 = 7;

const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;

const ATA_SR_BSY: u8 = 0x80;
const ATA_SR_DF: u8 = 0x20;
const ATA_SR_DRQ: u8 = 0x08;
const ATA_SR_ERR: u8 = 0x01;

const ATA_MAX_SECTOR_TRANSFER: u8 = 128;
const ATA_WORDS_PER_SECTOR: usize = storage_volume.sector_size / @sizeOf(u16);
const ATA_DRIVE_SELECT_MASTER: u8 = 0xE0;
const ATA_DRIVE_SELECT_SLAVE: u8 = 0xF0;
const ATA_LBA28_HEAD_MASK: u64 = 0x0F;
// LBA28 addresses 2^28 sectors; issueLba28Command only programs the low 28 bits,
// so a transfer reaching past this would silently wrap to the wrong sector.
const ATA_LBA28_SECTOR_LIMIT: u64 = 0x1000_0000;
const ATA_ALT_STATUS_SETTLE_READS: usize = 4;
const ATA_POLL_LIMIT: u32 = 100_000;

pub const AtaDriverError = error{
    Timeout,
    DriveError,
    InvalidParameter,
    BrokerRevoked,
    BrokerUnavailable,
    StaleBrokerSession,
    StaleGeneration,
};

pub const AtaControllerSession = struct {
    client: device_broker_client.Client,
    device_id: u64,
    base_port: u16,
    ctrl_port: u16,
    is_master: bool,
    irq_line: u8,
    sector_count: u64,
    process_generation: u32,
    dma_domain_id: u64,
    dma_isolation: device_broker.DmaIsolationStatus,
    brokered_dma_buffer: device_broker.BrokeredDmaBuffer,
    fault_injection: AtaFaultInjection = .{},
};

pub const AtaFaultInjection = struct {
    force_next_timeout: bool = false,
};

pub fn establishAtaBootstrapSession(
    kernel_port: *component_port.KernelPort,
    device_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    dma_domain_id: u64,
    now_ticks: u64,
) ?AtaControllerSession {
    var client = device_broker_client.Client.init(kernel_port, authority_capability_id, task_id, now_ticks);
    const descriptor = client.describe() catch return null;
    if (descriptor.device_id != device_id) return null;
    const task = kernel_port.kernel.runtime.find(task_id) orelse return null;
    const dma_isolation = device_broker.dmaIsolationStatus(device_id, dma_domain_id) catch return null;
    const brokered_dma_window = device_broker.defaultBrokeredDmaWindow(device_id);
    const brokered_dma_buffer = device_broker.authorizeDmaBuffer(
        device_id,
        dma_domain_id,
        brokered_dma_window.base,
        brokered_dma_window.length,
        .bidirectional,
    ) catch return null;

    return .{
        .client = client,
        .device_id = device_id,
        .base_port = descriptor.base_port,
        .ctrl_port = descriptor.ctrl_port,
        .is_master = (descriptor.flags & abi.DEVICE_DESCRIPTOR_FLAG_ATA_MASTER) != 0,
        .irq_line = descriptor.irq_line,
        .sector_count = descriptor.sector_count,
        .process_generation = task.process_generation,
        .dma_domain_id = dma_domain_id,
        .dma_isolation = dma_isolation,
        .brokered_dma_buffer = brokered_dma_buffer,
        .fault_injection = .{},
    };
}

pub fn attachAtaBootstrapSession(session: *AtaControllerSession) void {
    storage_volume.attachAtaBootstrapDevice(@ptrCast(session), session.sector_count);
}

pub fn readAtaBootstrapSession(session: *AtaControllerSession, start_lba: u64, buffer: []u8) bool {
    readAtaBootstrapSessionChecked(session, start_lba, buffer) catch return false;
    return true;
}

pub fn writeAtaBootstrapSession(session: *AtaControllerSession, start_lba: u64, buffer: []const u8) bool {
    writeAtaBootstrapSessionChecked(session, start_lba, buffer) catch return false;
    return true;
}

pub fn readAtaBootstrapSessionChecked(session: *AtaControllerSession, start_lba: u64, buffer: []u8) AtaDriverError!void {
    try transferReadRangeChecked(session, start_lba, buffer);
}

pub fn writeAtaBootstrapSessionChecked(session: *AtaControllerSession, start_lba: u64, buffer: []const u8) AtaDriverError!void {
    try transferWriteRangeChecked(session, start_lba, buffer);
}

pub fn forceNextAtaTimeout(session: *AtaControllerSession) void {
    session.fault_injection.force_next_timeout = true;
}

pub fn constrainedProgrammedIoFirstTarget(session: *const AtaControllerSession) bool {
    return session.dma_isolation.mode == .brokered_dma_buffers and
        session.dma_isolation.hardware_iommu_programmed and
        !session.dma_isolation.bus_master_dma_enabled and
        brokeredDmaBufferReady(session);
}

// The first-target storage data plane is constrained in one of two accepted
// shapes: the modeled ATA bridge (programmed I/O, no bus mastering) or the
// real NVMe engine (bus mastering confined to its declared queue/bounce
// windows alongside the staging window). Both require brokered-buffer mode,
// IOMMU programming evidence, and a live staging-buffer authorization;
// unconfined bus mastering is never accepted.
pub fn constrainedStorageDataPlane(session: *const AtaControllerSession) bool {
    if (constrainedProgrammedIoFirstTarget(session)) return true;
    return session.dma_isolation.mode == .brokered_dma_buffers and
        session.dma_isolation.hardware_iommu_programmed and
        session.dma_isolation.bus_master_dma_enabled and
        session.dma_isolation.window_count > 1 and
        brokeredDmaBufferReady(session);
}

pub fn brokeredDmaBufferReady(session: *const AtaControllerSession) bool {
    return device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
}

pub fn staleAuthorityRejectedAfterGenerationChange(session: *const AtaControllerSession) bool {
    var stale_session = session.*;
    _ = stale_session.client.describe() catch |err| return err == error.StaleGeneration;
    return false;
}

pub fn staleDmaPortAccessRejectedAfterGenerationChange(session: *const AtaControllerSession) bool {
    var stale_session = session.*;
    _ = stale_session.client.readPort(stale_session.base_port + ATA_REG_STATUS, .u8) catch |err| return err == error.StaleGeneration;
    return false;
}

pub fn staleBrokeredDmaBufferRejectedAfterGenerationChange(session: *const AtaControllerSession) bool {
    return !device_broker.brokeredDmaBufferStillValid(session.brokered_dma_buffer);
}

export fn zigosStorageBootstrapAtaRead(
    device_ptr: *const anyopaque,
    start_lba: u64,
    buffer_ptr: [*]u8,
    buffer_len: usize,
) callconv(.c) bool {
    const session: *AtaControllerSession = @ptrCast(@alignCast(@constCast(device_ptr)));
    return readAtaBootstrapSession(session, start_lba, buffer_ptr[0..buffer_len]);
}

export fn zigosStorageBootstrapAtaWrite(
    device_ptr: *const anyopaque,
    start_lba: u64,
    buffer_ptr: [*]const u8,
    buffer_len: usize,
) callconv(.c) bool {
    const session: *AtaControllerSession = @ptrCast(@alignCast(@constCast(device_ptr)));
    return writeAtaBootstrapSession(session, start_lba, buffer_ptr[0..buffer_len]);
}

fn readSectors(session: *AtaControllerSession, lba: u64, count: u8, buffer: []u8) AtaDriverError!void {
    if (count == 0 or count > ATA_MAX_SECTOR_TRANSFER) return error.InvalidParameter;
    if (buffer.len < @as(usize, count) * storage_volume.sector_size) return error.InvalidParameter;

    try waitDriveReady(session);
    try issueLba28Command(session, lba, count, ATA_CMD_READ_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(session);
        for (0..ATA_WORDS_PER_SECTOR) |_| {
            const word = try readPortU16(session, session.base_port + ATA_REG_DATA);
            buffer[buffer_offset] = @as(u8, @truncate(word));
            buffer[buffer_offset + 1] = @as(u8, @truncate(word >> 8));
            buffer_offset += 2;
        }
    }
}

fn validateAtaTransferRange(session: *const AtaControllerSession, start_lba: u64, buffer_len: usize) AtaDriverError!void {
    if (buffer_len == 0 or buffer_len % storage_volume.sector_size != 0) return error.InvalidParameter;
    const total_sectors = buffer_len / storage_volume.sector_size;
    // Fail closed before issuing any chunk: the transfer must fit the device and
    // be addressable in 28-bit LBA. The `or` short-circuits each subtraction so
    // the bound stays overflow-safe for a hostile start_lba.
    if (start_lba > session.sector_count or session.sector_count - start_lba < total_sectors) return error.InvalidParameter;
    if (start_lba >= ATA_LBA28_SECTOR_LIMIT or ATA_LBA28_SECTOR_LIMIT - start_lba < total_sectors) return error.InvalidParameter;
}

fn transferReadRangeChecked(session: *AtaControllerSession, start_lba: u64, buffer: []u8) AtaDriverError!void {
    try validateAtaTransferRange(session, start_lba, buffer.len);

    var offset: usize = 0;
    var lba = start_lba;
    while (offset < buffer.len) {
        const remaining_sectors = (buffer.len - offset) / storage_volume.sector_size;
        const chunk_sectors: u8 = @intCast(@min(remaining_sectors, @as(usize, ATA_MAX_SECTOR_TRANSFER)));
        const chunk_len = @as(usize, chunk_sectors) * storage_volume.sector_size;
        try readSectors(session, lba, chunk_sectors, buffer[offset .. offset + chunk_len]);
        lba += chunk_sectors;
        offset += chunk_len;
    }
}

fn writeSectors(session: *AtaControllerSession, lba: u64, count: u8, buffer: []const u8) AtaDriverError!void {
    if (count == 0 or count > ATA_MAX_SECTOR_TRANSFER) return error.InvalidParameter;
    if (buffer.len < @as(usize, count) * storage_volume.sector_size) return error.InvalidParameter;

    try waitDriveReady(session);
    try issueLba28Command(session, lba, count, ATA_CMD_WRITE_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(session);
        for (0..ATA_WORDS_PER_SECTOR) |_| {
            const word = @as(u16, buffer[buffer_offset]) |
                (@as(u16, buffer[buffer_offset + 1]) << 8);
            try writePortU16(session, session.base_port + ATA_REG_DATA, word);
            buffer_offset += 2;
        }
    }

    try writePortU8(session, session.base_port + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    try waitDriveReady(session);
}

fn transferWriteRangeChecked(session: *AtaControllerSession, start_lba: u64, buffer: []const u8) AtaDriverError!void {
    try validateAtaTransferRange(session, start_lba, buffer.len);

    var offset: usize = 0;
    var lba = start_lba;
    while (offset < buffer.len) {
        const remaining_sectors = (buffer.len - offset) / storage_volume.sector_size;
        const chunk_sectors: u8 = @intCast(@min(remaining_sectors, @as(usize, ATA_MAX_SECTOR_TRANSFER)));
        const chunk_len = @as(usize, chunk_sectors) * storage_volume.sector_size;
        try writeSectors(session, lba, chunk_sectors, buffer[offset .. offset + chunk_len]);
        lba += chunk_sectors;
        offset += chunk_len;
    }
}

fn issueLba28Command(session: *AtaControllerSession, lba: u64, count: u8, command: u8) AtaDriverError!void {
    const drive_select = if (session.is_master) ATA_DRIVE_SELECT_MASTER else ATA_DRIVE_SELECT_SLAVE;
    try writePortU8(session, session.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & ATA_LBA28_HEAD_MASK)));
    for (0..ATA_ALT_STATUS_SETTLE_READS) |_| {
        _ = try readPortU8(session, session.ctrl_port);
    }

    try writePortU8(session, session.base_port + ATA_REG_SECCOUNT, count);
    try writePortU8(session, session.base_port + ATA_REG_LBA0, @as(u8, @truncate(lba)));
    try writePortU8(session, session.base_port + ATA_REG_LBA1, @as(u8, @truncate(lba >> 8)));
    try writePortU8(session, session.base_port + ATA_REG_LBA2, @as(u8, @truncate(lba >> 16)));
    try writePortU8(session, session.base_port + ATA_REG_COMMAND, command);
}

fn waitDriveReady(session: *AtaControllerSession) AtaDriverError!void {
    if (consumeForcedTimeout(session)) {
        try requireCurrentGeneration(session);
        return error.Timeout;
    }
    var timeout: u32 = ATA_POLL_LIMIT;
    while (timeout > 0) : (timeout -= 1) {
        const status = try readPortU8(session, session.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) return error.DriveError;
        if ((status & ATA_SR_BSY) == 0) return;
    }
    return error.Timeout;
}

fn waitDataReady(session: *AtaControllerSession) AtaDriverError!void {
    if (consumeForcedTimeout(session)) {
        try requireCurrentGeneration(session);
        return error.Timeout;
    }
    var timeout: u32 = ATA_POLL_LIMIT;
    while (timeout > 0) : (timeout -= 1) {
        const status = try readPortU8(session, session.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) return error.DriveError;
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRQ) != 0) return;
    }
    return error.Timeout;
}

fn consumeForcedTimeout(session: *AtaControllerSession) bool {
    if (!session.fault_injection.force_next_timeout) return false;
    session.fault_injection.force_next_timeout = false;
    return true;
}

fn readPortU8(session: *AtaControllerSession, port: u16) AtaDriverError!u8 {
    try requireCurrentGeneration(session);
    if (builtin.target.os.tag == .freestanding) return x86.inb(port);
    return @truncate(session.client.readPort(port, .u8) catch |err| return mapBrokerError(err));
}

fn readPortU16(session: *AtaControllerSession, port: u16) AtaDriverError!u16 {
    try requireCurrentGeneration(session);
    if (builtin.target.os.tag == .freestanding) return x86.inw(port);
    return @truncate(session.client.readPort(port, .u16) catch |err| return mapBrokerError(err));
}

fn writePortU8(session: *AtaControllerSession, port: u16, value: u8) AtaDriverError!void {
    try requireCurrentGeneration(session);
    if (builtin.target.os.tag == .freestanding) {
        x86.outb(port, value);
        return;
    }
    session.client.writePort(port, .u8, value) catch |err| return mapBrokerError(err);
}

fn writePortU16(session: *AtaControllerSession, port: u16, value: u16) AtaDriverError!void {
    try requireCurrentGeneration(session);
    if (builtin.target.os.tag == .freestanding) {
        x86.outw(port, value);
        return;
    }
    session.client.writePort(port, .u16, value) catch |err| return mapBrokerError(err);
}

fn requireCurrentGeneration(session: *AtaControllerSession) AtaDriverError!void {
    const task = session.client.kernel_port.kernel.runtime.find(session.client.task_id) orelse return error.BrokerUnavailable;
    if (task.process_generation != session.process_generation) return error.StaleGeneration;
    if (session.client.device_id != 0) {
        const current_generation = device_broker.brokerGeneration(session.client.device_id) orelse return error.BrokerRevoked;
        if (current_generation != session.client.broker_generation) return error.StaleBrokerSession;
    }
}

fn mapBrokerError(err: anyerror) AtaDriverError {
    return switch (err) {
        error.BrokerRevoked => error.BrokerRevoked,
        error.StaleBrokerSession => error.StaleBrokerSession,
        error.StaleGeneration => error.StaleGeneration,
        else => error.BrokerUnavailable,
    };
}

test "storage driver task attaches only through the kernel device broker" {
    const capability = @import("../kernel_api/capability.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const principal = @import("../core/principal.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
    const generated_image_fixtures = @import("../task/generated_image_fixtures.zig");
    const task_runtime = @import("../task/task_runtime.zig");

    storage_volume.clearAttachedBackend();
    defer storage_volume.clearAttachedBackend();
    device_broker.reset();
    defer device_broker.reset();

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 1 },
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var kernel_port = component_port.KernelPort.init(&kernel);

    const storage_driver_broker_image = try generated_image_fixtures.storageDriverImage();
    const driver_task = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .service, .serial = 30 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = units.kibibytes(1),
            .endpoint_slots = 4,
            .shared_memory_bytes = units.kibibytes(1),
        },
        .local_only = true,
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 30,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &storage_driver_broker_image,
    });
    const device_capability = try capabilities.mintBootRoot(.{
        .holder = driver_task.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .device, .id = 0x1F001 },
        .rights = .{ .device = .{ .device_use = true } },
        .scope = .{
            .task_id = driver_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 9,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
    });
    try runtime.grantCapability(driver_task.id, device_capability.id);

    try std.testing.expect(
        establishAtaBootstrapSession(&kernel_port, 0x1F001, device_capability.id, driver_task.id, 11, 9) == null,
    );

    try std.testing.expect(device_broker.publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = storage_volume.required_device_sectors,
    }));
    _ = try device_broker.programBrokeredDmaIsolation(0x1F001, 11);
    var session = establishAtaBootstrapSession(&kernel_port, 0x1F001, device_capability.id, driver_task.id, 11, 9).?;
    try std.testing.expect(constrainedProgrammedIoFirstTarget(&session));
    try std.testing.expect(brokeredDmaBufferReady(&session));
    var readback: [storage_volume.sector_size]u8 = undefined;
    forceNextAtaTimeout(&session);
    try std.testing.expectError(error.Timeout, readAtaBootstrapSessionChecked(&session, 0, readback[0..]));
    try std.testing.expectError(
        error.InvalidParameter,
        writeAtaBootstrapSessionChecked(&session, 0, readback[0 .. storage_volume.sector_size / 2]),
    );
    attachAtaBootstrapSession(&session);
    try std.testing.expect(storage_volume.hasAttachedDevice());
}
