const std = @import("std");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const device_broker = @import("../kernel_api/device_broker.zig");
const driver_service = @import("../drivers/driver_service.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const session_manager = @import("session_manager.zig");
const signing = @import("../core/signing.zig");
const storage_driver_protocol = @import("../drivers/storage_driver_protocol.zig");
const sync_service = @import("../sync/sync_service.zig");
const syscall_surface = @import("../kernel_api/syscall_surface.zig");
const task_runtime = @import("../task/task_runtime.zig");
const compositor_session = @import("../platform/compositor_session.zig");

pub fn bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting() !void {
    session_manager.testing.resetState();
    defer session_manager.testing.resetState();

    session_manager.boot();

    const runtime = session_manager.testing.runtimePtr();
    const capability_table = session_manager.system().capabilityTablePtr();
    const supervisor = session_manager.testing.supervisorPtr();
    const driver_directory = session_manager.testing.driverDirectoryPtr();
    const storage = session_manager.testing.storageServicePtr();
    const kernel_port = session_manager.kernelPort() orelse return error.KernelPortUnavailable;

    const session_task = session_manager.testing.findTask("session-manager").?;
    const sync_task = session_manager.testing.findTask("sync-service").?;
    const storage_task = session_manager.testing.findTask("workspace-storage").?;
    const storage_driver_task = session_manager.testing.findTask("storage-driver").?;
    const network_service_task = session_manager.testing.findTask("network-service").?;
    const compositor_task = session_manager.testing.findTask("compositor-session").?;

    try std.testing.expect(sync_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_driver_task.runsAsUserspaceProcess());
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_task.id));
    try std.testing.expect(runtime.processSeparated(sync_task.id, storage_driver_task.id));
    try std.testing.expect(runtime.processSeparated(storage_driver_task.id, storage_task.id));

    const session_authority_id = findServiceAuthority(
        capability_table,
        session_task,
        .resource_query,
    ) orelse return error.MissingBootAuthority;

    allowHostStackSyscalls(runtime, session_task.id);
    try proveResourceAccountingSyscalls(kernel_port, runtime, session_task.id, session_authority_id);
    try proveBootedDriverPermissions(kernel_port, runtime, capability_table, driver_directory, storage_driver_task, network_service_task);
    try proveBootedSyncServicePath(
        runtime,
        capability_table,
        supervisor.findByClass(.sync_replication).?,
        sync_task,
        storage,
    );
    try proveBootedCompositorServicePath(
        kernel_port,
        runtime,
        capability_table,
        supervisor.findByClass(.compositor_ui_session).?,
        compositor_task,
        session_manager.testing.compositorSessionPtr(),
    );
}

fn proveResourceAccountingSyscalls(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    session_task_id: u64,
    session_authority_id: u64,
) !void {
    const probe = try createResourceProbeTask(kernel_port, session_task_id, session_authority_id);
    try std.testing.expect(abi.taskFlagsHas(probe.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(abi.taskFlagsHas(probe.flags, abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED));
    allowHostStackSyscalls(runtime, probe.task_id);

    const resources = try resourceQuery(kernel_port, session_task_id, session_authority_id, probe.task_id, 82);
    try std.testing.expectEqual(@as(u64, 1_200), resources.cpu_time_ticks);
    try std.testing.expectEqual(@as(u64, 64 * 1024), resources.memory_bytes);
    try std.testing.expectEqual(@as(u64, 1024), resources.shared_memory_bytes);
    try std.testing.expectEqual(@as(u16, 0), resources.endpoint_count);

    _ = try expectEndpointCreate(kernel_port, session_task_id, session_authority_id, probe.task_id, "resource.probe", 83);
    const endpoint_over_budget = endpointCreateResult(kernel_port, session_task_id, session_authority_id, probe.task_id, "resource.probe.extra", 84);
    try std.testing.expectEqual(abi.SyscallStatus.conflict, endpoint_over_budget.status);
    try std.testing.expectEqual(abi.DenialReason.budget_exhausted, endpoint_over_budget.denial_reason);

    const shared_memory = try expectSharedMemoryCreate(kernel_port, session_task_id, session_authority_id, probe.task_id, 1024, 85);
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

fn proveBootedDriverPermissions(
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
    try std.testing.expect(storage_driver.allowsDma(storage_driver.dma_ranges[0].base, 4096));
    try std.testing.expect(!storage_driver.allowsDma(storage_driver.dma_ranges[0].base + storage_driver.dma_ranges[0].length - 1024, 4096));

    device_broker.reset();
    defer device_broker.reset();
    try std.testing.expect(device_broker.publishAtaController(storage_driver.device_id, storageGrant()));

    allowHostStackSyscalls(runtime, storage_driver.owner_task_id);
    const descriptor = try expectDeviceDescribe(kernel_port, storage_driver.owner_task_id, storage_driver.authority_capability_id, 90);
    try std.testing.expectEqual(storage_driver.device_id, descriptor.device_id);
    try std.testing.expectEqual(@as(u16, 0x1F0), descriptor.base_port);

    allowHostStackSyscalls(runtime, network_service_task.id);
    const cross_task = deviceDescribeResult(kernel_port, network_service_task.id, storage_driver.authority_capability_id, 91);
    try std.testing.expectEqual(abi.SyscallStatus.not_found, cross_task.status);
    try std.testing.expectEqual(abi.DenialReason.capability_missing, cross_task.denial_reason);
}

fn proveBootedSyncServicePath(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    sync_record: *const @import("supervisor.zig").ServiceRecord,
    sync_task: *task_runtime.TaskRecord,
    storage: *@import("../storage/storage_service.zig").Service,
) !void {
    const sync_owner = sync_record.owner;
    const user = principal.PrincipalId{ .kind = .user, .serial = 7_001 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 7_002 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 7_003 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 7_004 };
    const storage_signer = signer("service-path-storage", 0x61);
    const user_signer = signer("service-path-user", 0x62);
    const laptop_signer = signer("service-path-laptop", 0x63);
    const tablet_signer = signer("service-path-tablet", 0x64);
    const contract_signer = signer("service-path-contract", 0x65);

    var sync_instance = try sync_service.Service.initWithStorage(
        sync_record.id,
        sync_task.id,
        sync_owner,
        storage,
        session_manager.system().syncResidentStatePtr(),
    );
    const authority = try capability_table.mintBootRoot(.{
        .holder = sync_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = sync_instance.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = sync_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 100,
            .expires_at_ticks = 1_000,
        },
    });
    try runtime.grantCapability(sync_task.id, authority.id);

    var sync_port = sync_service.SyncPort.init(&sync_instance, capability_table);
    const sync_authority = sync_service.AuthorityContext{
        .task_id = sync_task.id,
        .principal = sync_owner,
        .capability_id = authority.id,
        .now_ticks = 101,
    };

    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_000),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 101),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_000),
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v2", 102),
        .parent_version_id = notes_v1.version_id,
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_001),
        .object_type = .media_asset,
        .payload = "cover-bytes",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "cover-bytes", 103),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(71_002),
        .object_type = .secret,
        .payload = "enc:service-path-secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:service-path-secret", 104),
    });

    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "service-path-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v2.object_id, notes_v2.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    _ = try storage.commit(workspace_record.id, 105);
    const workspace_id = workspace_record.id.raw();

    _ = try sync_port.ensureUserRoot(sync_authority, user, "owner", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, laptop, "laptop", user_signer, laptop_signer, 106);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, tablet, "tablet", user_signer, tablet_signer, 107);
    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "local",
        .mode = .local_network,
    });
    const relay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.service-path.zigos",
    });
    const overlay_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.service-path.notes",
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_id,
        .owner = user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.service-path.zigos",
    });
    _ = try sync_port.configureOverlay(sync_authority, workspace_id, laptop, "overlay.service-path.notes", true);
    _ = try sync_port.publishPrivateService(sync_authority, workspace_id, "notes.remote");

    try sync_port.setReplicaVersion(sync_authority, workspace_id, tablet, "documents/notes.md", notes_v1.object_id, cover.version_id);
    const summary = try sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expectEqual(@as(usize, 2), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expectEqual(summary.transport_frame_count, summary.encrypted_transport_count);
    try std.testing.expect(sync_instance.findConflict(workspace_id, tablet, "documents/notes.md") != null);

    const relay_session = try sync_port.openOverlaySession(
        sync_authority,
        workspace_id,
        laptop,
        tablet,
        .private_service,
        .relay_assisted,
        "notes.remote",
        108,
    );
    try std.testing.expect(relay_session.encrypted);
    try std.testing.expect(relay_session.relay_encrypted);
    try std.testing.expectEqualStrings("notes.remote", relay_session.privateServiceSlice());
    try std.testing.expect(!(try sync_port.evaluateNetworkPolicy(sync_authority, relay_policy.id, .{ .domain = "other.service-path.zigos" })).allowed);

    try std.testing.expect(try sync_port.transferSecretObject(sync_authority, storage, workspace_id, secret.object_id, laptop, tablet, .device_to_device));
    const contract = try sync_port.registerDatabaseContract(sync_authority, workspace_id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expect(try sync_port.replicateDatabaseContract(sync_authority, contract.id, workspace_id, laptop, tablet, .relay_assisted));
    try std.testing.expectError(sync_service.Error.DeviceNotTrusted, sync_port.replicateWorkspace(sync_authority, storage, workspace_id, laptop, phone, .device_to_device));
}

fn proveBootedCompositorServicePath(
    kernel_port: *component_port.KernelPort,
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    compositor_record: *const @import("supervisor.zig").ServiceRecord,
    compositor_task: *task_runtime.TaskRecord,
    session: *compositor_session.Session,
) !void {
    session.reset();
    allowHostStackSyscalls(runtime, compositor_task.id);

    const authority = try capability_table.mintBootRoot(.{
        .holder = compositor_record.owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = compositor_record.id },
        .rights = .{ .service = .{
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
        } },
        .scope = .{
            .task_id = compositor_task.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 120,
            .expires_at_ticks = 1_200,
        },
    });
    try runtime.grantCapability(compositor_task.id, authority.id);

    const service_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        compositor_task.id,
        authority.id,
        compositor_task.id,
        "zigos.ui.compositor",
        .{ .local_only = true, .service_port = true },
        121,
    );
    const peer_endpoint = try expectEndpointCreateWithFlags(
        kernel_port,
        compositor_task.id,
        authority.id,
        compositor_task.id,
        "zigos.ui.client",
        .{ .local_only = true },
        122,
    );
    _ = try expectEndpointConnect(
        kernel_port,
        compositor_task.id,
        peer_endpoint.capability_id,
        service_endpoint.capability_id,
        service_endpoint.endpoint.endpoint_id,
        123,
    );

    var checkpoint_store = compositor_session.CheckpointStore{};
    var service = compositor_session.Service.initWithCheckpoint(
        compositor_record.id,
        compositor_task.id,
        runtime,
        session,
        &checkpoint_store,
    );

    var tick: u64 = 124;
    const open_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .open_view,
        .view_type = .document_view,
        .subject_task_id = compositor_task.id,
        .workspace_id = 88_001,
        .detail = "docs/plan",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, open_response.status);
    try std.testing.expectEqual(@as(u16, 1), open_response.visible_window_count);
    try std.testing.expectEqual(open_response.window_id, session.active_window_id);

    const missing_switch = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .switch_view,
        .window_id = 99_999,
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.not_found, missing_switch.status);

    const switch_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .switch_view,
        .window_id = open_response.window_id,
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, switch_response.status);
    try std.testing.expectEqual(open_response.window_id, switch_response.active_window_id);

    const review_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .review_permission,
        .subject_task_id = compositor_task.id,
        .reviewer_task_id = compositor_task.id,
        .permission_kind = .object_access,
        .local_only = true,
        .max_lease_ticks = 64,
        .bundle_id = "app.svc",
        .display_name = "Svc",
        .resource = "ws:svc",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, review_response.status);
    try std.testing.expectEqual(@as(u16, 1), review_response.review_item_count);

    const decision_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .record_decision,
        .window_id = review_response.window_id,
        .permission_kind = .object_access,
        .allow = true,
        .local_only = true,
        .has_lease = true,
        .lease_ticks = 64,
        .resource = "ws:svc",
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, decision_response.status);
    try std.testing.expectEqual(compositor_session.DecisionState.allow, decision_response.decision);

    session.reset();
    try std.testing.expectEqual(@as(usize, 0), session.window_count);
    const recover_response = try compositorRoundTrip(kernel_port, compositor_task.id, peer_endpoint.capability_id, service_endpoint.capability_id, &service, .{
        .operation = .recover_state,
    }, &tick);
    try std.testing.expectEqual(compositor_session.ServiceStatus.ok, recover_response.status);
    try std.testing.expect(recover_response.recovered);
    try std.testing.expectEqual(@as(usize, 2), session.window_count);
    try std.testing.expectEqual(@as(usize, 1), session.item_count);
    try std.testing.expectEqual(
        compositor_session.DecisionState.allow,
        session.findReviewItemConst(review_response.window_id, .object_access, "ws:svc").?.decision,
    );
}

fn compositorRoundTrip(
    kernel_port: *component_port.KernelPort,
    task_id: u64,
    peer_endpoint_capability_id: u64,
    service_endpoint_capability_id: u64,
    service: *compositor_session.Service,
    request: compositor_session.ServiceRequest,
    tick: *u64,
) !compositor_session.ServiceResponse {
    var request_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const request_payload = try compositor_session.encodeRequest(&request_buffer, request);
    try expectEndpointSend(kernel_port, task_id, peer_endpoint_capability_id, request_payload, tick.*);
    tick.* += 1;

    const received_request = try expectEndpointRecv(kernel_port, task_id, service_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received_request.present);

    var response_buffer: [abi.ENDPOINT_INLINE_BYTES]u8 = undefined;
    const response_payload = try service.dispatchPayload(
        received_request.payload[0..received_request.message.payload_len],
        &response_buffer,
    );
    try expectEndpointSend(kernel_port, task_id, service_endpoint_capability_id, response_payload, tick.*);
    tick.* += 1;

    const received_response = try expectEndpointRecv(kernel_port, task_id, peer_endpoint_capability_id, tick.*);
    tick.* += 1;
    try std.testing.expectEqual(@as(u8, 1), received_response.present);
    return compositor_session.decodeResponse(received_response.payload[0..received_response.message.payload_len]);
}

fn createResourceProbeTask(
    kernel_port: *component_port.KernelPort,
    session_task_id: u64,
    session_authority_id: u64,
) !abi.TaskDescriptor {
    const image = task_runtime.syntheticUserspaceImage("resource-proof", "app.resource-proof");
    var response = std.mem.zeroes(abi.TaskDescriptor);
    const request = component_port.TaskCreateRequest{
        .header = component_port.makeHeader(.task_create, 81, session_task_id),
        .authority_capability_id = session_authority_id,
        .request = .{
            .owner = .{ .kind = .app, .serial = 8_001 },
            .component_class = .app_component,
            .budget = .{
                .cpu_time_ticks = 1_200,
                .memory_bytes = 64 * 1024,
                .endpoint_slots = 1,
                .shared_memory_bytes = 1024,
            },
            .local_only = true,
            .launch = .{
                .boundary = .userspace_process,
                .image_id = 8_001,
                .component_abi_version = abi.ABI_VERSION,
                .signed = true,
                .bundle_id = "app.resource-proof",
            },
            .userspace_image = &image,
        },
    };
    const result = syscall_surface.dispatch(
        kernel_port,
        session_task_id,
        81,
        @intFromPtr(&request),
        @intFromPtr(&response),
        @sizeOf(abi.TaskDescriptor),
    );
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn resourceQuery(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.ResourceDescriptor {
    var response = std.mem.zeroes(abi.ResourceDescriptor);
    const request = component_port.ResourceQueryRequest{
        .header = component_port.makeHeader(.resource_query, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.ResourceDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn accountingQuery(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    task_id: u64,
    tick: u64,
) !abi.AccountingDescriptor {
    var response = std.mem.zeroes(abi.AccountingDescriptor);
    const request = component_port.AccountingQueryRequest{
        .header = component_port.makeHeader(.accounting_query, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.AccountingDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectEndpointCreate(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
) !abi.EndpointCreateResponse {
    return expectEndpointCreateWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, .{ .local_only = true }, tick);
}

fn expectEndpointCreateWithFlags(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    tick: u64,
) !abi.EndpointCreateResponse {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    const result = endpointCreateResultIntoWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, flags, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn endpointCreateResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.EndpointCreateResponse);
    return endpointCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, tick, &response);
}

fn endpointCreateResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    tick: u64,
    response: *abi.EndpointCreateResponse,
) syscall_surface.DispatchResult {
    return endpointCreateResultIntoWithFlags(kernel_port, caller_task_id, authority_capability_id, owner_task_id, label, .{ .local_only = true }, tick, response);
}

fn endpointCreateResultIntoWithFlags(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    label: []const u8,
    flags: endpoint.EndpointFlags,
    tick: u64,
    response: *abi.EndpointCreateResponse,
) syscall_surface.DispatchResult {
    const request = component_port.EndpointCreateRequest{
        .header = component_port.makeHeader(.endpoint_create, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = owner_task_id,
        .label = label,
        .flags = flags,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.EndpointCreateResponse));
}

fn expectEndpointConnect(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    peer_endpoint_capability_id: u64,
    peer_endpoint_id: u64,
    tick: u64,
) !abi.EndpointDescriptor {
    var response = std.mem.zeroes(abi.EndpointDescriptor);
    const request = component_port.EndpointConnectRequest{
        .header = component_port.makeHeader(.endpoint_connect, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .peer_endpoint_capability_id = peer_endpoint_capability_id,
        .peer_endpoint_id = peer_endpoint_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectEndpointSend(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    payload: []const u8,
    tick: u64,
) !void {
    const request = component_port.EndpointSendRequest{
        .header = component_port.makeHeader(.endpoint_send, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .payload = payload,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), 0, 0);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
}

fn expectEndpointRecv(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    endpoint_capability_id: u64,
    tick: u64,
) !abi.EndpointRecvResponse {
    var response = std.mem.zeroes(abi.EndpointRecvResponse);
    const request = component_port.EndpointRecvRequest{
        .header = component_port.makeHeader(.endpoint_recv, tick, caller_task_id),
        .endpoint_capability_id = endpoint_capability_id,
        .receiver_task_id = caller_task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.EndpointRecvResponse));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn expectSharedMemoryCreate(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
) !abi.SharedMemoryCreateResponse {
    var response = std.mem.zeroes(abi.SharedMemoryCreateResponse);
    const result = sharedMemoryCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, size_bytes, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn sharedMemoryCreateResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.SharedMemoryCreateResponse);
    return sharedMemoryCreateResultInto(kernel_port, caller_task_id, authority_capability_id, owner_task_id, size_bytes, tick, &response);
}

fn sharedMemoryCreateResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    authority_capability_id: u64,
    owner_task_id: u64,
    size_bytes: usize,
    tick: u64,
    response: *abi.SharedMemoryCreateResponse,
) syscall_surface.DispatchResult {
    const request = component_port.SharedMemoryCreateRequest{
        .header = component_port.makeHeader(.shared_memory_create, tick, caller_task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = owner_task_id,
        .size_bytes = size_bytes,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.SharedMemoryCreateResponse));
}

fn expectSharedMemoryMap(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    shared_memory_capability_id: u64,
    task_id: u64,
    tick: u64,
) !void {
    var response = std.mem.zeroes(abi.SharedMemoryDescriptor);
    const request = component_port.SharedMemoryMapRequest{
        .header = component_port.makeHeader(.shared_memory_map, tick, caller_task_id),
        .shared_memory_capability_id = shared_memory_capability_id,
        .task_id = task_id,
    };
    const result = syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(&response), @sizeOf(abi.SharedMemoryDescriptor));
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
}

fn expectDeviceDescribe(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
) !abi.DeviceDescriptor {
    var response = std.mem.zeroes(abi.DeviceDescriptor);
    const result = deviceDescribeResultInto(kernel_port, caller_task_id, device_capability_id, tick, &response);
    try std.testing.expectEqual(abi.SyscallStatus.success, result.status);
    return response;
}

fn deviceDescribeResult(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
) syscall_surface.DispatchResult {
    var response = std.mem.zeroes(abi.DeviceDescriptor);
    return deviceDescribeResultInto(kernel_port, caller_task_id, device_capability_id, tick, &response);
}

fn deviceDescribeResultInto(
    kernel_port: *component_port.KernelPort,
    caller_task_id: u64,
    device_capability_id: u64,
    tick: u64,
    response: *abi.DeviceDescriptor,
) syscall_surface.DispatchResult {
    const request = component_port.DeviceDescribeRequest{
        .header = component_port.makeHeader(.device_describe, tick, caller_task_id),
        .device_capability_id = device_capability_id,
    };
    return syscall_surface.dispatch(kernel_port, caller_task_id, tick, @intFromPtr(&request), @intFromPtr(response), @sizeOf(abi.DeviceDescriptor));
}

fn findServiceAuthority(
    capability_table: *const capability.CapabilityTable,
    task: *const task_runtime.TaskRecord,
    right: capability.CapabilityRight,
) ?u64 {
    for (task.capabilityIds()) |capability_id| {
        const record = capability_table.query(capability_id) orelse continue;
        if (record.target.kind == .service and record.rights.has(right)) return capability_id;
    }
    return null;
}

fn allowHostStackSyscalls(runtime: *task_runtime.Runtime, task_id: u64) void {
    const task = runtime.find(task_id).?;
    runtime.findAddressSpace(task.address_space_id).?.region_count = 0;
}

fn storageGrant() storage_driver_protocol.AtaBrokerGrant {
    return .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 4096,
    };
}

fn signer(label: []const u8, seed: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = [_]u8{seed} ** 32,
    };
}

test "booted userspace service paths prove sync driver isolation and resource accounting" {
    try bootedUserspaceServicePathsProveSyncDriverIsolationAndResourceAccounting();
}
