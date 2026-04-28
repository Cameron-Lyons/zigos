const std = @import("std");
const abi = @import("../core/abi.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker_client = @import("../kernel_api/device_broker_client.zig");
const storage_volume = @import("../storage/storage_volume.zig");
const storage_volume_backend = @import("../storage/storage_volume_backend.zig");

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

pub const AtaDriverError = error{
    Timeout,
    DriveError,
    InvalidParameter,
    BrokerUnavailable,
};

pub const AtaControllerSession = struct {
    client: device_broker_client.Client,
    device_id: u64,
    base_port: u16,
    ctrl_port: u16,
    is_master: bool,
    irq_line: u8,
    sector_count: u64,
};

const ReadContext = struct {
    session: *const AtaControllerSession,

    pub fn read(self: *const @This(), lba: u64, sector_count: u8, buffer: []u8) bool {
        readSectors(@constCast(self.session), lba, sector_count, buffer) catch return false;
        return true;
    }
};

const WriteContext = struct {
    session: *const AtaControllerSession,

    pub fn write(self: *const @This(), lba: u64, sector_count: u8, buffer: []const u8) bool {
        writeSectors(@constCast(self.session), lba, sector_count, buffer) catch return false;
        return true;
    }
};

pub fn establishAtaBootstrapSession(
    kernel_port: *component_port.KernelPort,
    device_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    now_ticks: u64,
) ?AtaControllerSession {
    var client = device_broker_client.Client.init(kernel_port, authority_capability_id, task_id, now_ticks);
    const descriptor = client.describe() catch return null;
    if (descriptor.device_id != device_id) return null;

    return .{
        .client = client,
        .device_id = device_id,
        .base_port = descriptor.base_port,
        .ctrl_port = descriptor.ctrl_port,
        .is_master = (descriptor.flags & abi.DEVICE_DESCRIPTOR_FLAG_ATA_MASTER) != 0,
        .irq_line = descriptor.irq_line,
        .sector_count = descriptor.sector_count,
    };
}

pub fn attachAtaBootstrapSession(session: *AtaControllerSession) void {
    storage_volume.attachAtaBootstrapDevice(@ptrCast(session), session.sector_count);
}

export fn zigosStorageBootstrapAtaRead(
    device_ptr: *const anyopaque,
    start_lba: u64,
    buffer_ptr: [*]u8,
    buffer_len: usize,
) callconv(.c) bool {
    const session: *AtaControllerSession = @ptrCast(@alignCast(@constCast(device_ptr)));
    const context = ReadContext{ .session = session };
    return storage_volume_backend.transferReadRange(start_lba, buffer_ptr[0..buffer_len], &context);
}

export fn zigosStorageBootstrapAtaWrite(
    device_ptr: *const anyopaque,
    start_lba: u64,
    buffer_ptr: [*]const u8,
    buffer_len: usize,
) callconv(.c) bool {
    const session: *AtaControllerSession = @ptrCast(@alignCast(@constCast(device_ptr)));
    const context = WriteContext{ .session = session };
    return storage_volume_backend.transferWriteRange(start_lba, buffer_ptr[0..buffer_len], &context);
}

fn readSectors(session: *AtaControllerSession, lba: u64, count: u8, buffer: []u8) AtaDriverError!void {
    if (count == 0 or count > 128) return error.InvalidParameter;
    if (buffer.len < @as(usize, count) * storage_volume.sector_size) return error.InvalidParameter;

    try waitDriveReady(session);

    const drive_select: u8 = if (session.is_master) 0xE0 else 0xF0;
    try writePortU8(session, session.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & 0x0F)));
    for (0..4) |_| {
        _ = try readPortU8(session, session.ctrl_port);
    }

    try writePortU8(session, session.base_port + ATA_REG_SECCOUNT, count);
    try writePortU8(session, session.base_port + ATA_REG_LBA0, @as(u8, @intCast(lba & 0xFF)));
    try writePortU8(session, session.base_port + ATA_REG_LBA1, @as(u8, @intCast((lba >> 8) & 0xFF)));
    try writePortU8(session, session.base_port + ATA_REG_LBA2, @as(u8, @intCast((lba >> 16) & 0xFF)));
    try writePortU8(session, session.base_port + ATA_REG_COMMAND, ATA_CMD_READ_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(session);
        for (0..256) |_| {
            const word = try readPortU16(session, session.base_port + ATA_REG_DATA);
            buffer[buffer_offset] = @as(u8, @truncate(word));
            buffer[buffer_offset + 1] = @as(u8, @truncate(word >> 8));
            buffer_offset += 2;
        }
    }
}

fn writeSectors(session: *AtaControllerSession, lba: u64, count: u8, buffer: []const u8) AtaDriverError!void {
    if (count == 0 or count > 128) return error.InvalidParameter;
    if (buffer.len < @as(usize, count) * storage_volume.sector_size) return error.InvalidParameter;

    try waitDriveReady(session);

    const drive_select: u8 = if (session.is_master) 0xE0 else 0xF0;
    try writePortU8(session, session.base_port + ATA_REG_DRIVE, drive_select | @as(u8, @intCast((lba >> 24) & 0x0F)));
    for (0..4) |_| {
        _ = try readPortU8(session, session.ctrl_port);
    }

    try writePortU8(session, session.base_port + ATA_REG_SECCOUNT, count);
    try writePortU8(session, session.base_port + ATA_REG_LBA0, @as(u8, @intCast(lba & 0xFF)));
    try writePortU8(session, session.base_port + ATA_REG_LBA1, @as(u8, @intCast((lba >> 8) & 0xFF)));
    try writePortU8(session, session.base_port + ATA_REG_LBA2, @as(u8, @intCast((lba >> 16) & 0xFF)));
    try writePortU8(session, session.base_port + ATA_REG_COMMAND, ATA_CMD_WRITE_SECTORS);

    var buffer_offset: usize = 0;
    for (0..count) |_| {
        try waitDataReady(session);
        for (0..256) |_| {
            const word = @as(u16, buffer[buffer_offset]) |
                (@as(u16, buffer[buffer_offset + 1]) << 8);
            try writePortU16(session, session.base_port + ATA_REG_DATA, word);
            buffer_offset += 2;
        }
    }

    try writePortU8(session, session.base_port + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    try waitDriveReady(session);
}

fn waitDriveReady(session: *AtaControllerSession) AtaDriverError!void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const status = try readPortU8(session, session.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0) return;
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) return error.DriveError;
    }
    return error.Timeout;
}

fn waitDataReady(session: *AtaControllerSession) AtaDriverError!void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const status = try readPortU8(session, session.base_port + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRQ) != 0) return;
        if ((status & ATA_SR_ERR) != 0 or (status & ATA_SR_DF) != 0) return error.DriveError;
    }
    return error.Timeout;
}

fn readPortU8(session: *AtaControllerSession, port: u16) AtaDriverError!u8 {
    return @truncate(session.client.readPort(port, .u8) catch return error.BrokerUnavailable);
}

fn readPortU16(session: *AtaControllerSession, port: u16) AtaDriverError!u16 {
    return @truncate(session.client.readPort(port, .u16) catch return error.BrokerUnavailable);
}

fn writePortU8(session: *AtaControllerSession, port: u16, value: u8) AtaDriverError!void {
    session.client.writePort(port, .u8, value) catch return error.BrokerUnavailable;
}

fn writePortU16(session: *AtaControllerSession, port: u16, value: u16) AtaDriverError!void {
    session.client.writePort(port, .u16, value) catch return error.BrokerUnavailable;
}

test "storage driver task attaches only through the kernel device broker" {
    const capability = @import("../kernel_api/capability.zig");
    const device_broker = @import("../kernel_api/device_broker.zig");
    const endpoint = @import("../kernel_api/endpoint.zig");
    const native_kernel = @import("../kernel_api/native_kernel.zig");
    const principal = @import("../core/principal.zig");
    const shared_memory = @import("../kernel_api/shared_memory.zig");
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

    const storage_driver_broker_image = task_runtime.syntheticUserspaceImage(
        "storage-driver-broker-test",
        "zigos.system.storage-driver",
    );
    const driver_task = try runtime.createTask(.{
        .owner = principal.PrincipalId{ .kind = .service, .serial = 30 },
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 1_000,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
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
        establishAtaBootstrapSession(&kernel_port, 0x1F001, device_capability.id, driver_task.id, 9) == null,
    );

    try std.testing.expect(device_broker.publishAtaController(0x1F001, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = storage_volume.required_device_sectors,
    }));
    var session = establishAtaBootstrapSession(&kernel_port, 0x1F001, device_capability.id, driver_task.id, 9).?;
    attachAtaBootstrapSession(&session);
    try std.testing.expect(storage_volume.hasAttachedDevice());
}
