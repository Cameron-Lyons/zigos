const std = @import("std");

pub const kernel_boundary_role = "bootstrap_nvme_inventory_shim";
pub const publishes_full_storage_service = false;
pub const nvme_data_plane_exports_fail_closed = true;

pub const DEFAULT_PAGE_SIZE: u64 = 4096;
pub const DOORBELL_REGISTER_BYTES: u32 = 4;

pub const Error = error{
    KernelStorageDataPlaneDisabled,
    UnsupportedCommandSet,
    QueueTooSmall,
    QueueTooLarge,
    QueueAddressUnaligned,
    PageSizeUnsupported,
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
