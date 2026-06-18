const std = @import("std");

pub const kernel_boundary_role = "bootstrap_nvme_inventory_shim";
pub const publishes_full_storage_service = false;
pub const nvme_data_plane_exports_fail_closed = true;

pub const DEFAULT_PAGE_SIZE: u64 = 4096;
pub const DOORBELL_REGISTER_BYTES: u32 = 4;
pub const SECTOR_BYTES: usize = 512;

const CAP_MQES_MASK: u64 = 0xFFFF;
const CAP_CQR_SHIFT = 16;
const CAP_CQR_MASK: u64 = 0x1;
const CAP_TO_SHIFT = 24;
const CAP_TO_MASK: u64 = 0xFF;
const CAP_TIMEOUT_UNIT_MS: u32 = 500;
const CAP_DSTRD_SHIFT = 32;
const CAP_DSTRD_MASK: u64 = 0xF;
const CAP_CSS_NVM_SHIFT = 37;
const CAP_MPSMIN_SHIFT = 48;
const CAP_MPSMAX_SHIFT = 52;
const CAP_MPS_MASK: u64 = 0xF;
const NVME_BASE_PAGE_SHIFT = 12;
const MIN_QUEUE_ENTRIES: u32 = 2;
const ZERO_BASED_FIELD_INCREMENT: u32 = 1;
const TEST_SUBMISSION_QUEUE_ADDRESS: u64 = 0x1000;
const TEST_COMPLETION_QUEUE_ADDRESS: u64 = 0x2000;
const TEST_PRP1_ADDRESS: u64 = 0x3000;
const TEST_UNALIGNED_QUEUE_ADDRESS: u64 = TEST_SUBMISSION_QUEUE_ADDRESS + 1;

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
    ProofCycleCountInvalid,
    ProofMismatch,
    MissingDmaBuffer,
    PrpAddressUnaligned,
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
        return @as(u32, @intCast(self.raw & CAP_MQES_MASK)) + ZERO_BASED_FIELD_INCREMENT;
    }

    pub fn contiguousQueuesRequired(self: ControllerCapabilities) bool {
        return ((self.raw >> CAP_CQR_SHIFT) & CAP_CQR_MASK) != 0;
    }

    pub fn timeoutMilliseconds(self: ControllerCapabilities) u32 {
        return @as(u32, @intCast((self.raw >> CAP_TO_SHIFT) & CAP_TO_MASK)) * CAP_TIMEOUT_UNIT_MS;
    }

    pub fn doorbellStrideBytes(self: ControllerCapabilities) u32 {
        const dstrd: u5 = @intCast((self.raw >> CAP_DSTRD_SHIFT) & CAP_DSTRD_MASK);
        return DOORBELL_REGISTER_BYTES << dstrd;
    }

    pub fn supportsNvmCommandSet(self: ControllerCapabilities) bool {
        return ((self.raw >> CAP_CSS_NVM_SHIFT) & CAP_CQR_MASK) != 0;
    }

    pub fn minPageSizeBytes(self: ControllerCapabilities) u64 {
        const mpsmin: u6 = @intCast((self.raw >> CAP_MPSMIN_SHIFT) & CAP_MPS_MASK);
        return @as(u64, 1) << (NVME_BASE_PAGE_SHIFT + mpsmin);
    }

    pub fn maxPageSizeBytes(self: ControllerCapabilities) u64 {
        const mpsmax: u6 = @intCast((self.raw >> CAP_MPSMAX_SHIFT) & CAP_MPS_MASK);
        return @as(u64, 1) << (NVME_BASE_PAGE_SHIFT + mpsmax);
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

pub const CompletionEvidenceSource = enum(u8) {
    modeled_mmio,
    hardware_dma,
};

pub const HardwareCompletionEvidence = struct {
    source: CompletionEvidenceSource = .modeled_mmio,
    controller_completion_writes: u32 = 0,
    dma_read_bytes: u64 = 0,
    dma_write_bytes: u64 = 0,
    interrupt_count: u32 = 0,
    phase_tag_observations: u32 = 0,

    pub fn verified(self: HardwareCompletionEvidence, expected_commands: u32, bytes_per_direction: u64) bool {
        return self.source == .hardware_dma and
            expected_commands > 0 and
            bytes_per_direction > 0 and
            self.controller_completion_writes >= expected_commands and
            self.dma_read_bytes >= bytes_per_direction and
            self.dma_write_bytes >= bytes_per_direction and
            self.interrupt_count != 0 and
            self.phase_tag_observations >= expected_commands;
    }
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

pub const IoProof = struct {
    namespace_id: u32,
    namespace_sector_count: u64,
    start_lba: u64,
    final_lba: u64,
    sector_count: u16,
    write_read_cycles: u16,
    write_completions: u16,
    read_completions: u16,
    last_write_completion: IoCompletion,
    last_read_completion: IoCompletion,
    mmio: MmioIoProof,

    pub fn verified(self: IoProof) bool {
        const expected_commands = @as(u32, self.write_completions) + @as(u32, self.read_completions);
        return self.namespace_id != 0 and
            self.namespace_sector_count > 0 and
            self.sector_count > 0 and
            self.write_read_cycles > 0 and
            self.write_completions == self.write_read_cycles and
            self.read_completions == self.write_read_cycles and
            self.final_lba >= self.start_lba and
            self.last_write_completion.status == .success and
            self.last_read_completion.status == .success and
            self.last_write_completion.namespace_id == self.namespace_id and
            self.last_read_completion.namespace_id == self.namespace_id and
            self.last_write_completion.lba == self.final_lba and
            self.last_read_completion.lba == self.final_lba and
            self.last_write_completion.sector_count == self.sector_count and
            self.last_read_completion.sector_count == self.sector_count and
            self.last_write_completion.command_id != self.last_read_completion.command_id and
            self.mmio.verified(expected_commands);
    }

    pub fn productionHardwareVerified(self: IoProof) bool {
        const expected_commands = @as(u32, self.write_completions) + @as(u32, self.read_completions);
        const bytes_per_direction = self.bytesPerDirection() orelse return false;
        return self.verified() and self.mmio.hardwareVerified(expected_commands, bytes_per_direction);
    }

    fn bytesPerDirection(self: IoProof) ?u64 {
        const sectors = std.math.mul(u64, @as(u64, self.write_read_cycles), @as(u64, self.sector_count)) catch return null;
        return std.math.mul(u64, sectors, SECTOR_BYTES) catch null;
    }
};

pub const MmioIoProof = struct {
    doorbell_stride_bytes: u32,
    submission_queue_address: u64,
    completion_queue_address: u64,
    prp1_address: u64,
    dma_buffer_bytes: u64,
    page_size_bytes: u64,
    queue_depth: u16,
    submission_doorbell_writes: u32,
    completion_head_updates: u32,
    completed_commands: u32,
    hardware_completion: HardwareCompletionEvidence = .{},

    pub fn verified(self: MmioIoProof, expected_commands: u32) bool {
        return expected_commands > 0 and
            self.doorbell_stride_bytes >= DOORBELL_REGISTER_BYTES and
            self.page_size_bytes >= DEFAULT_PAGE_SIZE and
            aligned(self.submission_queue_address, self.page_size_bytes) and
            aligned(self.completion_queue_address, self.page_size_bytes) and
            aligned(self.prp1_address, self.page_size_bytes) and
            self.dma_buffer_bytes >= SECTOR_BYTES and
            self.queue_depth >= MIN_QUEUE_ENTRIES and
            self.submission_doorbell_writes >= expected_commands and
            self.completion_head_updates >= expected_commands and
            self.completed_commands == expected_commands;
    }

    pub fn hardwareVerified(self: MmioIoProof, expected_commands: u32, bytes_per_direction: u64) bool {
        return self.verified(expected_commands) and
            self.hardware_completion.verified(expected_commands, bytes_per_direction);
    }
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
    mmio: ?MmioState = null,

    pub fn init(capabilities: ControllerCapabilities, namespaces: []Namespace, queue_depth: u16) Error!Controller {
        try validateQueueEntries(capabilities, queue_depth);
        if (!capabilities.supportsNvmCommandSet()) return error.UnsupportedCommandSet;
        return .{
            .capabilities = capabilities,
            .namespaces = namespaces,
            .queue_depth = queue_depth,
        };
    }

    pub fn initWithMmio(
        capabilities: ControllerCapabilities,
        namespaces: []Namespace,
        queue_depth: u16,
        plan: AdminQueuePlan,
        prp1_address: u64,
        dma_buffer_bytes: u64,
    ) Error!Controller {
        try validateAdminQueuePlan(capabilities, plan);
        if (prp1_address == 0 or !aligned(prp1_address, plan.page_size_bytes)) return error.PrpAddressUnaligned;
        if (dma_buffer_bytes < SECTOR_BYTES) return error.MissingDmaBuffer;
        var controller = try Controller.init(capabilities, namespaces, queue_depth);
        controller.mmio = .{
            .plan = plan,
            .prp1_address = prp1_address,
            .dma_buffer_bytes = dma_buffer_bytes,
        };
        return controller;
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

    pub fn proveWriteReadCycles(self: *Controller, namespace_id: u32, start_lba: u64, cycles: u16) Error!IoProof {
        if (cycles == 0) return error.ProofCycleCountInvalid;
        const namespace_sector_count = (try self.namespace(namespace_id)).sector_count;
        const final_lba = std.math.add(u64, start_lba, @as(u64, cycles) - 1) catch return error.TransferOutOfRange;
        if (start_lba >= namespace_sector_count or final_lba >= namespace_sector_count) return error.TransferOutOfRange;

        var write_buffer: [SECTOR_BYTES]u8 = undefined;
        var read_buffer: [SECTOR_BYTES]u8 = undefined;
        var last_write_completion: IoCompletion = undefined;
        var last_read_completion: IoCompletion = undefined;
        const mmio_start = self.mmioCounters();
        var completed: u16 = 0;
        while (completed < cycles) : (completed += 1) {
            const lba = std.math.add(u64, start_lba, completed) catch return error.TransferOutOfRange;
            fillProofPattern(write_buffer[0..], namespace_id, lba, completed);
            last_write_completion = try self.write(namespace_id, lba, write_buffer[0..]);
            @memset(read_buffer[0..], 0);
            last_read_completion = try self.read(namespace_id, lba, read_buffer[0..]);
            if (!std.mem.eql(u8, write_buffer[0..], read_buffer[0..])) return error.ProofMismatch;
        }

        return .{
            .namespace_id = namespace_id,
            .namespace_sector_count = namespace_sector_count,
            .start_lba = start_lba,
            .final_lba = final_lba,
            .sector_count = 1,
            .write_read_cycles = completed,
            .write_completions = completed,
            .read_completions = completed,
            .last_write_completion = last_write_completion,
            .last_read_completion = last_read_completion,
            .mmio = self.mmioProofSince(mmio_start),
        };
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
        if (self.mmio) |*mmio| {
            mmio.submission_doorbell_writes += 1;
            mmio.completion_head_updates += 1;
            mmio.completed_commands += 1;
        }
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

    fn mmioProof(self: *const Controller) MmioIoProof {
        const mmio = self.mmio orelse return emptyMmioIoProof();
        return mmio.proof(self.capabilities, self.queue_depth);
    }

    fn mmioCounters(self: *const Controller) MmioCounters {
        const mmio = self.mmio orelse return .{};
        return .{
            .submission_doorbell_writes = mmio.submission_doorbell_writes,
            .completion_head_updates = mmio.completion_head_updates,
            .completed_commands = mmio.completed_commands,
        };
    }

    fn mmioProofSince(self: *const Controller, start: MmioCounters) MmioIoProof {
        var proof = self.mmioProof();
        proof.submission_doorbell_writes = saturatedDelta(proof.submission_doorbell_writes, start.submission_doorbell_writes);
        proof.completion_head_updates = saturatedDelta(proof.completion_head_updates, start.completion_head_updates);
        proof.completed_commands = saturatedDelta(proof.completed_commands, start.completed_commands);
        return proof;
    }
};

const MmioCounters = struct {
    submission_doorbell_writes: u32 = 0,
    completion_head_updates: u32 = 0,
    completed_commands: u32 = 0,
};

const MmioState = struct {
    plan: AdminQueuePlan,
    prp1_address: u64,
    dma_buffer_bytes: u64,
    submission_doorbell_writes: u32 = 0,
    completion_head_updates: u32 = 0,
    completed_commands: u32 = 0,

    fn proof(self: MmioState, capabilities: ControllerCapabilities, queue_depth: u16) MmioIoProof {
        return .{
            .doorbell_stride_bytes = capabilities.doorbellStrideBytes(),
            .submission_queue_address = self.plan.submission_queue_address,
            .completion_queue_address = self.plan.completion_queue_address,
            .prp1_address = self.prp1_address,
            .dma_buffer_bytes = self.dma_buffer_bytes,
            .page_size_bytes = self.plan.page_size_bytes,
            .queue_depth = queue_depth,
            .submission_doorbell_writes = self.submission_doorbell_writes,
            .completion_head_updates = self.completion_head_updates,
            .completed_commands = self.completed_commands,
        };
    }
};

pub fn defaultAdminQueuePlan() AdminQueuePlan {
    return .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = TEST_SUBMISSION_QUEUE_ADDRESS,
        .completion_queue_address = TEST_COMPLETION_QUEUE_ADDRESS,
    };
}

pub fn defaultProofPrp1Address() u64 {
    return TEST_PRP1_ADDRESS;
}

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

pub fn withHardwareCompletionEvidence(proof: IoProof, evidence: HardwareCompletionEvidence) IoProof {
    var upgraded = proof;
    upgraded.mmio.hardware_completion = evidence;
    return upgraded;
}

fn validateQueueEntries(capabilities: ControllerCapabilities, entries: u32) Error!void {
    if (entries < MIN_QUEUE_ENTRIES) return error.QueueTooSmall;
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

fn fillProofPattern(buffer: []u8, namespace_id: u32, lba: u64, cycle: u16) void {
    for (buffer, 0..) |*byte, index| {
        const mixed = @as(u64, @intCast(index)) *% 131 +%
            lba *% 17 +%
            @as(u64, namespace_id) *% 7 +%
            @as(u64, cycle) *% 31;
        byte.* = @intCast(mixed & 0xFF);
    }
    @memcpy(buffer[0..4], "NVMe");
}

fn aligned(address: u64, alignment: u64) bool {
    return alignment != 0 and (address % alignment) == 0;
}

fn emptyMmioIoProof() MmioIoProof {
    return .{
        .doorbell_stride_bytes = 0,
        .submission_queue_address = 0,
        .completion_queue_address = 0,
        .prp1_address = 0,
        .dma_buffer_bytes = 0,
        .page_size_bytes = 0,
        .queue_depth = 0,
        .submission_doorbell_writes = 0,
        .completion_head_updates = 0,
        .completed_commands = 0,
    };
}

fn saturatedDelta(after: u32, before: u32) u32 {
    return if (after >= before) after - before else 0;
}

fn makeCapabilities(
    mqes_zero_based: u16,
    dstrd: u4,
    nvm_command_set: bool,
    mpsmin: u4,
    mpsmax: u4,
) ControllerCapabilities {
    var raw: u64 = mqes_zero_based;
    raw |= @as(u64, 1) << CAP_CQR_SHIFT;
    raw |= @as(u64, 10) << CAP_TO_SHIFT;
    raw |= @as(u64, dstrd) << CAP_DSTRD_SHIFT;
    if (nvm_command_set) raw |= @as(u64, 1) << CAP_CSS_NVM_SHIFT;
    raw |= @as(u64, mpsmin) << CAP_MPSMIN_SHIFT;
    raw |= @as(u64, mpsmax) << CAP_MPSMAX_SHIFT;
    return .{ .raw = raw };
}

test "NVMe capabilities expose queue and doorbell geometry" {
    const cap = makeCapabilities(1023, 2, true, 0, 4);
    try std.testing.expectEqual(@as(u32, 1024), cap.maxQueueEntries());
    try std.testing.expect(cap.contiguousQueuesRequired());
    try std.testing.expectEqual(@as(u32, 5000), cap.timeoutMilliseconds());
    try std.testing.expectEqual(@as(u32, 16), cap.doorbellStrideBytes());
    try std.testing.expect(cap.supportsNvmCommandSet());
    try std.testing.expectEqual(DEFAULT_PAGE_SIZE, cap.minPageSizeBytes());
    try std.testing.expectEqual(@as(u64, 65536), cap.maxPageSizeBytes());
}

test "NVMe admin queue plan validates command set page and alignment" {
    const cap = makeCapabilities(63, 0, true, 0, 0);
    try validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = TEST_SUBMISSION_QUEUE_ADDRESS,
        .completion_queue_address = TEST_COMPLETION_QUEUE_ADDRESS,
    });

    try std.testing.expectError(error.QueueAddressUnaligned, validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = TEST_UNALIGNED_QUEUE_ADDRESS,
        .completion_queue_address = TEST_COMPLETION_QUEUE_ADDRESS,
    }));

    try std.testing.expectError(error.QueueTooLarge, validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 65,
        .completion_queue_entries = 32,
        .submission_queue_address = TEST_SUBMISSION_QUEUE_ADDRESS,
        .completion_queue_address = TEST_COMPLETION_QUEUE_ADDRESS,
    }));
}

test "NVMe admin queue plan rejects unsupported command sets" {
    const cap = makeCapabilities(63, 0, false, 0, 0);
    try std.testing.expectError(error.UnsupportedCommandSet, validateAdminQueuePlan(cap, .{
        .submission_queue_entries = 32,
        .completion_queue_entries = 32,
        .submission_queue_address = TEST_SUBMISSION_QUEUE_ADDRESS,
        .completion_queue_address = TEST_COMPLETION_QUEUE_ADDRESS,
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
    try std.testing.expectError(error.PrpAddressUnaligned, Controller.initWithMmio(
        cap,
        namespaces[0..],
        32,
        defaultAdminQueuePlan(),
        TEST_PRP1_ADDRESS + 1,
        SECTOR_BYTES,
    ));
    var controller = try Controller.initWithMmio(cap, namespaces[0..], 32, defaultAdminQueuePlan(), TEST_PRP1_ADDRESS, SECTOR_BYTES);
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

    const proof = try controller.proveWriteReadCycles(1, 4, 3);
    try std.testing.expect(proof.verified());
    try std.testing.expect(!proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u16, 3), proof.write_read_cycles);
    try std.testing.expectEqual(@as(u64, 6), proof.final_lba);
    try std.testing.expectEqual(@as(u16, 8), proof.last_read_completion.command_id);
    try std.testing.expectEqual(@as(u32, 6), proof.mmio.submission_doorbell_writes);
    try std.testing.expectEqual(@as(u32, 6), proof.mmio.completion_head_updates);
    try std.testing.expectEqual(@as(u32, 6), proof.mmio.completed_commands);

    var malformed = proof;
    malformed.mmio.completed_commands = 0;
    try std.testing.expect(!malformed.verified());

    const hardware_proof = withHardwareCompletionEvidence(proof, .{
        .source = .hardware_dma,
        .controller_completion_writes = 6,
        .dma_read_bytes = 3 * SECTOR_BYTES,
        .dma_write_bytes = 3 * SECTOR_BYTES,
        .interrupt_count = 1,
        .phase_tag_observations = 6,
    });
    try std.testing.expect(hardware_proof.productionHardwareVerified());

    var missing_dma = hardware_proof;
    missing_dma.mmio.hardware_completion.dma_write_bytes = 0;
    try std.testing.expect(!missing_dma.productionHardwareVerified());
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
    try std.testing.expectError(error.ProofCycleCountInvalid, controller.proveWriteReadCycles(7, 0, 0));
    try std.testing.expectError(error.TransferOutOfRange, controller.proveWriteReadCycles(7, 1, 2));
}
