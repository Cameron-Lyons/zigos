const std = @import("std");
const abi = @import("../../core/abi.zig");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const device_broker = @import("../../kernel_api/device_broker.zig");
const driver_service = @import("../../drivers/driver_service.zig");
const ids = @import("../../core/ids.zig");
const process_isolation = @import("../../task/process_isolation.zig");
const shared_memory_mod = @import("../../kernel_api/shared_memory.zig");
const syscall_surface = @import("../../kernel_api/syscall_surface.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const common = @import("service_path_proofs_common.zig");

const accountingQuery = common.accountingQuery;
const createBootedProbeTask = common.createBootedProbeTask;
const createResourceProbeTask = common.createResourceProbeTask;
const deviceDescribeResult = common.deviceDescribeResult;
const endpointCreateResult = common.endpointCreateResult;
const expectDeviceDescribe = common.expectDeviceDescribe;
const expectEndpointCreate = common.expectEndpointCreate;
const expectSharedMemoryCreate = common.expectSharedMemoryCreate;
const expectSharedMemoryMap = common.expectSharedMemoryMap;
const expectSharedMemoryMapDescriptor = common.expectSharedMemoryMapDescriptor;
const expectSharedMemoryRevoke = common.expectSharedMemoryRevoke;
const resourceQuery = common.resourceQuery;
const sharedMemoryCreateResult = common.sharedMemoryCreateResult;
const sharedMemoryMapResult = common.sharedMemoryMapResult;
const storageGrant = common.storageGrant;
const units = @import("../../core/units.zig");

const SHARED_MEMORY_PAGE_BYTES: usize = shared_memory_mod.PAGE_SIZE;
const DMA_PAGE_BYTES: u64 = shared_memory_mod.PAGE_SIZE;
const DMA_TAIL_PROBE_OFFSET_BYTES: u64 = units.kibibytes(1);

pub fn proveResourceAccountingSyscalls(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const probe = try createResourceProbeTask(kernel_port, session_task_id, session_authority_id);
    try std.testing.expect(abi.taskFlagsHas(probe.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(probe.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    runtime.allowHostPointerSyscallsForTask(probe.task_id);

    const resources = try resourceQuery(kernel_port, session_task_id, session_authority_id, probe.task_id, 82);
    try std.testing.expectEqual(@as(u64, 1_200), resources.cpu_time_ticks);
    try std.testing.expectEqual(@as(u64, units.kibibytes(64)), resources.memory_bytes);
    try std.testing.expectEqual(@as(u64, common.RESOURCE_PROBE_SHARED_MEMORY_BYTES), resources.shared_memory_bytes);
    try std.testing.expectEqual(@as(u16, 0), resources.endpoint_count);

    _ = try expectEndpointCreate(kernel_port, session_task_id, session_authority_id, probe.task_id, "resource.probe", 83);
    const endpoint_over_budget = endpointCreateResult(kernel_port, session_task_id, session_authority_id, probe.task_id, "resource.probe.extra", 84);
    try std.testing.expectEqual(abi.SyscallStatus.conflict, endpoint_over_budget.status);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, endpoint_over_budget.denial_reason);

    const shared_memory = try expectSharedMemoryCreate(kernel_port, session_task_id, session_authority_id, probe.task_id, common.RESOURCE_PROBE_SHARED_MEMORY_BYTES, 85);
    try expectSharedMemoryMap(kernel_port, probe.task_id, shared_memory.capability_id, probe.task_id, 86);
    const shared_over_budget = sharedMemoryCreateResult(kernel_port, session_task_id, session_authority_id, probe.task_id, 1, 87);
    try std.testing.expectEqual(abi.SyscallStatus.conflict, shared_over_budget.status);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, shared_over_budget.denial_reason);

    const accounting = try accountingQuery(kernel_port, session_task_id, session_authority_id, probe.task_id, 88);
    try std.testing.expectEqual(@as(u16, 1), accounting.endpoint_count);
    try std.testing.expectEqual(@as(u16, 1), accounting.shared_memory_mappings);

    var spoofed_resource_response = std.mem.zeroes(abi.ResourceDescriptor);
    const spoofed_resource_request = component_port.ResourceQueryRequest{
        .header = component_port.makeHeader(.resource_query, 89, probe.task_id),
        .authority_capability_id = session_authority_id,
        .task_id = probe.task_id,
    };
    const spoofed_result = syscall_surface.dispatch(
        kernel_port,
        probe.task_id,
        89,
        @intFromPtr(&spoofed_resource_request),
        @intFromPtr(&spoofed_resource_response),
        @sizeOf(abi.ResourceDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.not_found, spoofed_result.status);
    try std.testing.expectEqual(abi.DenialReason.capability_missing, spoofed_result.denial_reason);
}

pub fn proveBootedSharedMemoryMappingRevocation(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const owner = try createBootedProbeTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        8_010,
        8_010,
        "shared-owner",
        "app.service-path.shared-owner",
        units.kibibytes(8),
        130,
    );
    const peer = try createBootedProbeTask(
        kernel_port,
        session_task_id,
        session_authority_id,
        8_010,
        8_011,
        "shared-peer",
        "app.service-path.shared-peer",
        units.kibibytes(8),
        131,
    );
    runtime.allowHostPointerSyscallsForTask(owner.task_id);
    runtime.allowHostPointerSyscallsForTask(peer.task_id);

    const created = try expectSharedMemoryCreate(kernel_port, session_task_id, session_authority_id, owner.task_id, SHARED_MEMORY_PAGE_BYTES, 132);
    const object_id = ids.sharedMemory(created.object.object_id);
    const peer_capability = try capability_table.mintBootRoot(.{
        .holder = runtime.find(peer.task_id).?.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .shared_memory, .id = object_id.raw() },
        .rights = .{ .shared_memory = .{
            .shared_memory_map = true,
            .shared_memory_unmap = true,
        } },
        .scope = .{
            .task_id = peer.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 132,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(peer.task_id, peer_capability.id);

    const owner_map = try expectSharedMemoryMapDescriptor(kernel_port, owner.task_id, created.capability_id, owner.task_id, 133);
    try std.testing.expectEqual(@as(u16, 1), owner_map.mapped_task_count);
    const peer_map = try expectSharedMemoryMapDescriptor(kernel_port, peer.task_id, peer_capability.id, peer.task_id, 134);
    try std.testing.expectEqual(@as(u16, 2), peer_map.mapped_task_count);

    const owner_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(object_id, ids.task(owner.task_id));
    const peer_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(object_id, ids.task(peer.task_id));
    const owner_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(object_id, ids.task(owner.task_id));
    const peer_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(object_id, ids.task(peer.task_id));
    try std.testing.expectEqual(owner_mapping.page_base, peer_mapping.page_base);
    try std.testing.expectEqual(@as(usize, 1), owner_mapping.page_count);
    try std.testing.expectEqual(SHARED_MEMORY_PAGE_BYTES, peer_mapping.size_bytes);
    try std.testing.expect(!owner_mapping.zero_copy);
    try std.testing.expectEqual(owner_mapping.page_base, owner_mmu_mapping.physical_base);
    try std.testing.expectEqual(owner_mmu_mapping.physical_base, peer_mmu_mapping.physical_base);
    try std.testing.expect(owner_mmu_mapping.virtual_base != 0);
    try std.testing.expect(peer_mmu_mapping.virtual_base != 0);
    try std.testing.expect(owner_mmu_mapping.virtual_base != peer_mmu_mapping.virtual_base);
    try std.testing.expect(!owner_mmu_mapping.zero_copy);
    try kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(owner_mapping);
    try kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(peer_mapping);
    try kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(owner_mmu_mapping);
    try kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(peer_mmu_mapping);
    try std.testing.expectEqual(@as(usize, 2), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(object_id));

    const revoked = try expectSharedMemoryRevoke(kernel_port, owner.task_id, created.capability_id, 135);
    try std.testing.expectEqual(@as(u16, 0), revoked.mapped_task_count);
    try std.testing.expectEqual(@as(u32, owner_map.revocation_generation + 1), revoked.revocation_generation);
    try std.testing.expectEqual(@as(u16, 1), revoked.flags);
    try std.testing.expectEqual(@as(u16, 0), (try accountingQuery(kernel_port, session_task_id, session_authority_id, owner.task_id, 136)).shared_memory_mappings);
    try std.testing.expectEqual(@as(u16, 0), (try accountingQuery(kernel_port, session_task_id, session_authority_id, peer.task_id, 137)).shared_memory_mappings);

    const post_revoke_map = sharedMemoryMapResult(kernel_port, peer.task_id, peer_capability.id, peer.task_id, 138);
    try std.testing.expectEqual(abi.SyscallStatus.denied, post_revoke_map.status);
    try std.testing.expectEqual(abi.DenialReason.capability_revoked, post_revoke_map.denial_reason);
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.taskMappingDescriptor(object_id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(object_id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(owner_mapping));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(owner_mmu_mapping));
    try std.testing.expectEqual(@as(usize, 0), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(object_id));

    const accelerated = try kernel_port.kernel.shared_memory_table.createLabeledWithAccess(ids.task(owner.task_id), shared_memory_mod.PAGE_SIZE * 2, "booted-accelerator", .{
        .gpu = true,
        .media = true,
    });
    try kernel_port.kernel.shared_memory_table.map(accelerated.id, ids.task(owner.task_id));
    try kernel_port.kernel.shared_memory_table.attachAccelerator(accelerated.id, .gpu);
    const task_mapping = try kernel_port.kernel.shared_memory_table.taskMappingDescriptor(accelerated.id, ids.task(owner.task_id));
    const gpu_mapping = try kernel_port.kernel.shared_memory_table.acceleratorMappingDescriptor(accelerated.id, .gpu);
    const task_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(accelerated.id, ids.task(owner.task_id));
    const gpu_mmu_mapping = try kernel_port.kernel.shared_memory_table.freestandingAcceleratorMappingDescriptor(accelerated.id, .gpu);
    try std.testing.expect(gpu_mapping.zero_copy);
    try std.testing.expectEqual(task_mapping.page_base, gpu_mapping.page_base);
    try std.testing.expectEqual(task_mapping.page_count, gpu_mapping.page_count);
    try std.testing.expectEqual(task_mapping.page_base, task_mmu_mapping.physical_base);
    try std.testing.expectEqual(task_mmu_mapping.physical_base, gpu_mmu_mapping.physical_base);
    try std.testing.expect(task_mmu_mapping.virtual_base != gpu_mmu_mapping.virtual_base);
    try std.testing.expect(gpu_mmu_mapping.zero_copy);
    try std.testing.expectEqual(shared_memory_mod.ComputeTarget.gpu, gpu_mmu_mapping.target.?);
    try kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(task_mapping);
    try kernel_port.kernel.shared_memory_table.validateAcceleratorMappingDescriptor(gpu_mapping, .gpu);
    try kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(task_mmu_mapping);
    try kernel_port.kernel.shared_memory_table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_mapping, .gpu);
    try std.testing.expectEqual(@as(usize, 2), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(accelerated.id));
    try kernel_port.kernel.shared_memory_table.revoke(accelerated.id);
    try std.testing.expectEqual(@as(usize, 0), kernel_port.kernel.shared_memory_table.activeFreestandingMappings(accelerated.id));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.taskMappingDescriptor(accelerated.id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.acceleratorMappingDescriptor(accelerated.id, .gpu));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.freestandingTaskMappingDescriptor(accelerated.id, ids.task(owner.task_id)));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.freestandingAcceleratorMappingDescriptor(accelerated.id, .gpu));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateTaskMappingDescriptor(task_mapping));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateAcceleratorMappingDescriptor(gpu_mapping, .gpu));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateFreestandingTaskMappingDescriptor(task_mmu_mapping));
    try std.testing.expectError(error.Revoked, kernel_port.kernel.shared_memory_table.validateFreestandingAcceleratorMappingDescriptor(gpu_mmu_mapping, .gpu));
}

pub fn proveBootedDriverPermissions(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *const capability.CapabilityTable,
    driver_directory: *driver_service.Directory,
    storage_driver_task: *task_runtime.TaskRecord,
    network_service_task: *task_runtime.TaskRecord,
) !void {
    const storage_driver = driver_directory.findByClass(.storage_controller).?;
    const network_driver = driver_directory.findByClass(.network_adapter).?;
    try std.testing.expectEqual(storage_driver_task.id, storage_driver.owner_task_id);
    try std.testing.expect(runtime.hasCapability(storage_driver.owner_task_id, storage_driver.authority_capability_id));
    try std.testing.expect(!runtime.hasCapability(network_service_task.id, storage_driver.authority_capability_id));
    try std.testing.expect(!runtime.hasCapability(storage_driver.owner_task_id, network_driver.authority_capability_id));

    const storage_authority = capability_table.query(storage_driver.authority_capability_id).?;
    try std.testing.expect(storage_authority.rights.has(.object_read));
    try std.testing.expect(storage_authority.rights.has(.object_write));
    try std.testing.expect(!storage_authority.rights.has(.network_local));
    try std.testing.expect(storage_driver.allowsDma(storage_driver.dma_ranges[0].base, DMA_PAGE_BYTES));
    try std.testing.expect(!storage_driver.allowsDma(storage_driver.dma_ranges[0].base + storage_driver.dma_ranges[0].length - DMA_TAIL_PROBE_OFFSET_BYTES, DMA_PAGE_BYTES));

    device_broker.reset();
    defer device_broker.reset();
    try std.testing.expect(device_broker.publishAtaController(storage_driver.device_id, storageGrant()));

    runtime.allowHostPointerSyscallsForTask(storage_driver.owner_task_id);
    const descriptor = try expectDeviceDescribe(kernel_port, storage_driver.owner_task_id, storage_driver.authority_capability_id, 90);
    try std.testing.expectEqual(storage_driver.device_id, descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);

    runtime.allowHostPointerSyscallsForTask(network_service_task.id);
    const cross_task = deviceDescribeResult(kernel_port, network_service_task.id, storage_driver.authority_capability_id, 91);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, cross_task.status);
    try std.testing.expectEqual(abi.DenialReason.capability_missing, cross_task.denial_reason);
}

pub fn proveBootedProcessIsolationVisibleEntitlementGates(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    caller: *task_runtime.TaskRecord,
    data_target: *task_runtime.TaskRecord,
    window_target: *task_runtime.TaskRecord,
) !void {
    try std.testing.expect(caller.runsAsUserspaceProcess());
    try std.testing.expect(data_target.runsAsUserspaceProcess());
    try std.testing.expect(window_target.runsAsUserspaceProcess());
    try std.testing.expect(runtime.processSeparated(caller.id, data_target.id));
    try std.testing.expect(runtime.processSeparated(caller.id, window_target.id));

    var broker = process_isolation.Broker.init(runtime, capability_table);
    try std.testing.expectError(error.CapabilityNotFound, broker.authorize(.{
        .caller_task_id = caller.id,
        .target_task_id = data_target.id,
        .capability_id = 90_000,
        .operation = .inspect_memory,
        .user_visible = true,
        .now_ticks = 90,
    }));

    const non_visible = try mintProcessControlCapability(
        capability_table,
        caller,
        data_target.id,
        false,
        91,
    );
    try runtime.grantCapability(caller.id, non_visible.id);
    try std.testing.expectError(error.VisibleEntitlementRequired, broker.authorize(.{
        .caller_task_id = caller.id,
        .target_task_id = data_target.id,
        .capability_id = non_visible.id,
        .operation = .inject_code,
        .user_visible = true,
        .now_ticks = 92,
    }));

    const visible_data = try mintProcessControlCapability(
        capability_table,
        caller,
        data_target.id,
        true,
        93,
    );
    try runtime.grantCapability(caller.id, visible_data.id);
    inline for (.{ process_isolation.Operation.inspect_memory, process_isolation.Operation.inject_code }) |operation| {
        const decision = try broker.authorize(.{
            .caller_task_id = caller.id,
            .target_task_id = data_target.id,
            .capability_id = visible_data.id,
            .operation = operation,
            .user_visible = true,
            .now_ticks = 94 + @intFromEnum(operation),
        });
        try std.testing.expect(decision.allowed);
        try std.testing.expectEqual(data_target.id, decision.target_task_id);
    }

    const visible_window = try mintProcessControlCapability(
        capability_table,
        caller,
        window_target.id,
        true,
        101,
    );
    try runtime.grantCapability(caller.id, visible_window.id);
    const scrape_decision = try broker.authorize(.{
        .caller_task_id = caller.id,
        .target_task_id = window_target.id,
        .capability_id = visible_window.id,
        .operation = .scrape_window,
        .user_visible = true,
        .now_ticks = 102,
    });
    try std.testing.expect(scrape_decision.allowed);
    try std.testing.expectEqual(window_target.id, scrape_decision.target_task_id);

    const visible_self = try mintProcessControlCapability(
        capability_table,
        caller,
        caller.id,
        true,
        103,
    );
    try runtime.grantCapability(caller.id, visible_self.id);
    try std.testing.expectError(error.VisibleEntitlementRequired, broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = false,
        .now_ticks = 104,
    }));
    const clipboard_decision = try broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .watch_clipboard,
        .continuous = true,
        .user_visible = true,
        .now_ticks = 105,
    });
    try std.testing.expect(clipboard_decision.allowed);
    try std.testing.expectEqual(caller.id, clipboard_decision.target_task_id);
    try std.testing.expectError(error.HiddenGlobalHookDenied, broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .register_global_hook,
        .hidden = true,
        .user_visible = true,
        .now_ticks = 106,
    }));
    const hook_decision = try broker.authorize(.{
        .caller_task_id = caller.id,
        .capability_id = visible_self.id,
        .operation = .register_global_hook,
        .user_visible = true,
        .now_ticks = 107,
    });
    try std.testing.expect(hook_decision.allowed);

    const latest = caller.latestAuditEvent() orelse return error.MissingProcessIsolationAudit;
    try std.testing.expectEqual(task_runtime.AuditEventKind.policy_allowed, latest.kind);
    try std.testing.expectEqual(@as(u32, @intFromEnum(process_isolation.Operation.register_global_hook)), latest.detail);
}

fn mintProcessControlCapability(
    capability_table: *capability.CapabilityTable,
    caller: *const task_runtime.TaskRecord,
    target_task_id: u64,
    visible: bool,
    tick: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = caller.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .task, .id = target_task_id },
        .rights = .{ .task = .{ .process_control = true } },
        .scope = .{
            .task_id = caller.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = tick,
            .expires_at_ticks = 1_000,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = caller.id,
            .broker_service_id = 90,
            .user_visible_entitlement = visible,
        },
    });
}
