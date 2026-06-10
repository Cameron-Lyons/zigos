const std = @import("std");

pub const kernel_boundary_role = "bootstrap_nvme_inventory_shim";
pub const publishes_full_storage_service = false;
pub const nvme_data_plane_exports_fail_closed = true;

pub const DEFAULT_PAGE_SIZE: u64 = 4096;
pub const DOORBELL_REGISTER_BYTES: u32 = 4;
pub const SECTOR_BYTES: usize = 512;

pub const Error = error{
    KernelStorageDataPlaneDisabled,
    UnsupportedCommandSet,
    QueueTooSmall,
    QueueTooLarge,
    QueueAddressUnaligned,
    PageSizeUnsupported,
    QueueNotReady,
    NamespaceNotFound,
    TransferOutOfRange,
    BufferSizeInvalid,
};

pub const DataPlaneTransferRequest = struct {
    device_id: u64,
    namespace_id: u32,
    lba: u64,
    sector_count: u16,
};

pub const ControllerCapabilities = struct {
    raw: u64,

    pub fn maxQueueEntries(self: ControllerCapabilities) u32 {
        return @as(u32, @intCast(self.raw & 0xFFFF)) + 1;
    }

    pub fn contiguousQueuesRequired(self: ControllerCapabilities) bool {
        return ((self.raw >> 16) & 0x1) != 0;
    }

    pub fn timeoutMilliseconds(self: ControllerCapabilities) u32 {
        return @as(u32, @intCast((self.raw >> 24) & 0xFF)) * 500;
    }

    pub fn doorbellStrideBytes(self: ControllerCapabilities) u32 {
        const dstrd: u5 = @intCast((self.raw >> 32) & 0xF);
        return DOORBELL_REGISTER_BYTES << dstrd;
    }

    pub fn supportsNvmCommandSet(self: ControllerCapabilities) bool {
        return ((self.raw >> 37) & 0x1) != 0;
    }

    pub fn minPageSizeBytes(self: ControllerCapabilities) u64 {
        const mpsmin: u6 = @intCast((self.raw >> 48) & 0xF);
        return @as(u64, 1) << (12 + mpsmin);
    }

    pub fn maxPageSizeBytes(self: ControllerCapabilities) u64 {
        const mpsmax: u6 = @intCast((self.raw >> 52) & 0xF);
        return @as(u64, 1) << (12 + mpsmax);
    }
};

pub const AdminQueuePlan = struct {
    submission_queue_entries: u32,
    completion_queue_entries: u32,
    submission_queue_address: u64,
    completion_queue_address: u64,
    page_size_bytes: u64 = DEFAULT_PAGE_SIZE,
};

pub const CompletionStatus = enum(u8) {
    success,
};

pub const IoCompletion = struct {
    command_id: u16,
    namespace_id: u32,
    lba: u64,
    sector_count: u16,
    status: CompletionStatus,
    submission_tail: u16,
    completion_head: u16,
};

pub const Namespace = struct {
    id: u32,
    sector_count: u64,
    image: []u8,
};

pub const Controller = struct {
    capabilities: ControllerCapabilities,
    namespaces: []Namespace,
    queue_depth: u16,
    next_command_id: u16 = 1,
    submission_tail: u16 = 0,
    completion_head: u16 = 0,

    pub fn init(capabilities: ControllerCapabilities, namespaces: []Namespace, queue_depth: u16) Error!Controller {
        try validateQueueEntries(capabilities, queue_depth);
        if (!capabilities.supportsNvmCommandSet()) return error.UnsupportedCommandSet;
        return .{
            .capabilities = capabilities,
            .namespaces = namespaces,
            .queue_depth = queue_depth,
        };
    }

    pub fn read(self: *Controller, namespace_id: u32, lba: u64, buffer: []u8) Error!IoCompletion {
        const sectors = try sectorCountForBuffer(buffer.len);
        const target_namespace = try self.namespace(namespace_id);
        const offset = try transferOffset(target_namespace, lba, sectors);
        @memcpy(buffer, target_namespace.image[offset..][0..buffer.len]);
        return self.completeIo(namespace_id, lba, sectors);
    }

    pub fn write(self: *Controller, namespace_id: u32, lba: u64, buffer: []const u8) Error!IoCompletion {
        const sectors = try sectorCountForBuffer(buffer.len);
        const target_namespace = try self.namespace(namespace_id);
        const offset = try transferOffset(target_namespace, lba, sectors);
        @memcpy(target_namespace.image[offset..][0..buffer.len], buffer);
        return self.completeIo(namespace_id, lba, sectors);
    }

    fn namespace(self: *Controller, namespace_id: u32) Error!*Namespace {
        for (self.namespaces) |*candidate| {
            if (candidate.id == namespace_id) return candidate;
        }
        return error.NamespaceNotFound;
    }

    fn completeIo(self: *Controller, namespace_id: u32, lba: u64, sectors: u16) Error!IoCompletion {
        if (self.queue_depth < 2) return error.QueueNotReady;
        const command_id = self.next_command_id;
        self.next_command_id +%= 1;
        if (self.next_command_id == 0) self.next_command_id = 1;
        self.submission_tail = nextQueueIndex(self.submission_tail, self.queue_depth);
        self.completion_head = nextQueueIndex(self.completion_head, self.queue_depth);
        return .{
            .command_id = command_id,
            .namespace_id = namespace_id,
            .lba = lba,
            .sector_count = sectors,
            .status = .success,
            .submission_tail = self.submission_tail,
            .completion_head = self.completion_head,
        };
    }
};

pub fn validateAdminQueuePlan(capabilities: ControllerCapabilities, plan: AdminQueuePlan) Error!void {
    if (!capabilities.supportsNvmCommandSet()) return error.UnsupportedCommandSet;
    if (plan.page_size_bytes < capabilities.minPageSizeBytes() or
        plan.page_size_bytes > capabilities.maxPageSizeBytes())
    {
        return error.PageSizeUnsupported;
    }

    try validateQueueEntries(capabilities, plan.submission_queue_entries);
    try validateQueueEntries(capabilities, plan.completion_queue_entries);
    if (!aligned(plan.submission_queue_address, plan.page_size_bytes)) return error.QueueAddressUnaligned;
    if (!aligned(plan.completion_queue_address, plan.page_size_bytes)) return error.QueueAddressUnaligned;
}

pub fn rejectKernelDataPlaneTransfer(_: DataPlaneTransferRequest) Error!void {
    return error.KernelStorageDataPlaneDisabled;
}

fn validateQueueEntries(capabilities: ControllerCapabilities, entries: u32) Error!void {
    if (entries < 2) return error.QueueTooSmall;
    if (entries > capabilities.maxQueueEntries()) return error.QueueTooLarge;
}

fn sectorCountForBuffer(buffer_len: usize) Error!u16 {
    if (buffer_len == 0 or (buffer_len % SECTOR_BYTES) != 0) return error.BufferSizeInvalid;
    const sectors = buffer_len / SECTOR_BYTES;
    if (sectors == 0 or sectors > std.math.maxInt(u16)) return error.BufferSizeInvalid;
    return @intCast(sectors);
}

fn transferOffset(namespace: *const Namespace, lba: u64, sectors: u16) Error!usize {
    if (sectors == 0 or lba >= namespace.sector_count or @as(u64, sectors) > namespace.sector_count - lba) {
        return error.TransferOutOfRange;
    }
    const byte_offset = lba * SECTOR_BYTES;
    const byte_len = @as(u64, sectors) * SECTOR_BYTES;
    if (byte_offset + byte_len > namespace.image.len) return error.TransferOutOfRange;
    return @intCast(byte_offset);
}

fn nextQueueIndex(index: u16, depth: u16) u16 {
    return @intCast((@as(u32, index) + 1) % @as(u32, depth));
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

fn makeCapabilities(
    mqes_zero_based: u16,
    dstrd: u4,
    nvm_command_set: bool,
    mpsmin: u4,
    mpsmax: u4,
) ControllerCapabilities {
    var raw: u64 = mqes_zero_based;
    raw |= @as(u64, 1) << 16;
    raw |= @as(u64, 10) << 24;
    raw |= @as(u64, dstrd) << 32;
    if (nvm_command_set) raw |= @as(u64, 1) << 37;
    raw |= @as(u64, mpsmin) << 48;
    raw |= @as(u64, mpsmax) << 52;
    return .{ .raw = raw };
}

test "NVMe capabilities expose queue and doorbell geometry" {
    const cap = makeCapabilities(1023, 2, true, 0, 4);
    try std.testing.expectEqual(@as(u32, 1024), cap.maxQueueEntries());
    try std.testing.expect(cap.contiguousQueuesRequired());
    try std.testing.expectEqual(@as(u32, 5000), cap.timeoutMilliseconds());
    try std.testing.expectEqual(@as(u32, 16), cap.doorbellStrideBytes());
    try std.testing.expect(cap.supportsNvmCommandSet());
    try std.testing.expectEqual(@as(u64, 4096), cap.minPageSizeBytes());
    try std.testing.expectEqual(@as(u64, 65536), cap.maxPageSizeBytes());
}

test "NVMe admin queue plan validates command set page and alignment" {
    const cap = makeCapabilities(63, 0, true, 0, 0);
    try validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = 0x1000,
        .completion_queue_address = 0x2000,
    });

    try std.testing.expectError(error.QueueAddressUnaligned, validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = 0x1001,
        .completion_queue_address = 0x2000,
    }));

    try std.testing.expectError(error.QueueTooLarge, validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 65,
        .completion_queue_entries = 32,
        .submission_queue_address = 0x1000,
        .completion_queue_address = 0x2000,
    }));
}

test "NVMe admin queue plan rejects unsupported command sets" {
    const cap = makeCapabilities(63, 0, false, 0, 0);
    try std.testing.expectError(error.UnsupportedCommandSet, validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = 0x1000,
        .completion_queue_address = 0x2000,
    }));
}

test "NVMe kernel shim rejects direct data-plane transfer attempts" {
    try std.testing.expectError(error.KernelStorageDataPlaneDisabled, rejectKernelDataPlaneTransfer(.{
        .device_id = 0x8086_15F2_0000,
        .namespace_id = 1,
        .lba = 7,
        .sector_count = 1,
    }));
}

test "NVMe userspace controller path writes reads and completes queue entries" {
    const cap = makeCapabilities(63, 0, true, 0, 0);
    var image = [_]u8{0} ** (SECTOR_BYTES * 8);
    var namespaces = [_]Namespace{.{
        .id = 1,
        .sector_count = 8,
        .image = image[0..],
    }};
    var controller = try Controller.init(cap, namespaces[0..], 32);
    var write_buffer = [_]u8{0xA5} ** SECTOR_BYTES;
    @memcpy(write_buffer[0..4], "nvme");
    const write_completion = try controller.write(1, 3, write_buffer[0..]);
    try std.testing.expectEqual(CompletionStatus.success, write_completion.status);
    try std.testing.expectEqual(@as(u16, 1), write_completion.command_id);
    try std.testing.expectEqual(@as(u16, 1), write_completion.submission_tail);

    var read_buffer = [_]u8{0} ** SECTOR_BYTES;
    const read_completion = try controller.read(1, 3, read_buffer[0..]);
    try std.testing.expectEqual(@as(u16, 2), read_completion.command_id);
    try std.testing.expectEqual(@as(u16, 2), read_completion.completion_head);
    try std.testing.expect(std.mem.eql(u8, write_buffer[0..], read_buffer[0..]));
}

test "NVMe userspace controller path rejects bad namespace geometry" {
    const cap = makeCapabilities(63, 0, true, 0, 0);
    var image = [_]u8{0} ** (SECTOR_BYTES * 2);
    var namespaces = [_]Namespace{.{
        .id = 7,
        .sector_count = 2,
        .image = image[0..],
    }};
    var controller = try Controller.init(cap, namespaces[0..], 16);
    var buffer = [_]u8{0} ** SECTOR_BYTES;
    try std.testing.expectError(error.NamespaceNotFound, controller.read(8, 0, buffer[0..]));
    try std.testing.expectError(error.TransferOutOfRange, controller.read(7, 2, buffer[0..]));
    try std.testing.expectError(error.BufferSizeInvalid, controller.write(7, 0, buffer[0..17]));
}
