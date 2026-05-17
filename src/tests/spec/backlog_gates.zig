const std = @import("std");
const abi = @import("../../native/core/abi.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const device_broker = @import("../../native/kernel_api/device_broker.zig");
const driver_runtime = @import("../../native/drivers/driver_runtime.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const endpoint = @import("../../native/kernel_api/endpoint.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const ids = @import("../../native/core/ids.zig");
const kernel_ata = @import("../../kernel/drivers/ata.zig");
const kernel_data_plane_boundary = @import("../../kernel/boot/init/data_plane_boundary.zig");
const kernel_ethernet = @import("../../kernel/net/ethernet.zig");
const kernel_link_port = @import("../../kernel/net/link_port.zig");
const manifest = @import("../../native/policy/manifest.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const principal = @import("../../native/core/principal.zig");
const runtime_negative_proofs = @import("../../native/session/runtime_negative_proofs.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const spec_support = @import("support.zig");
const supervisor = @import("../../native/session/supervisor.zig");
const sync_adapters = @import("../../native/sync/sync_adapters.zig");
const sync_service_test = @import("../../native/sync/sync_service_test.zig");
const sync_transport = @import("../../native/sync/sync_transport_harness.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const typed_component_abi = @import("../../native/services/typed_component_abi.zig");

const indexed_arena_source = @embedFile("../../native/core/indexed_arena.zig");
const service_registry_source = @embedFile("../../native/services/service_registry.zig");
const component_abi_schema_source = @embedFile("../../native/services/component_abi_schema.zig");
const service_bootstrap_source = @embedFile("../../native/session/service_bootstrap.zig");
const service_catalog_source = @embedFile("../../native/session/service_catalog.zig");
const session_bootstrap_source = @embedFile("../../native/session/session_bootstrap.zig");
const session_manager_boot_flow_source = @embedFile("../../native/session/session_manager_boot_flow.zig");
const session_service_bootstrap_source = @embedFile("../../native/session/session_service_bootstrap.zig");
const userspace_scheduler_source = @embedFile("../../native/task/userspace_scheduler.zig");
const accelerator_scheduler_source = @embedFile("../../native/task/accelerator_scheduler.zig");
const indexing_service_source = @embedFile("../../native/services/indexing_service.zig");
const event_ledger_source = @embedFile("../../native/platform/event_ledger.zig");
const native_ux_source = @embedFile("../../native/platform/native_ux.zig");
const compositor_session_source = @embedFile("../../native/platform/compositor_session.zig");
const sync_service_impl_source = @embedFile("../../native/sync/sync_service_impl.zig");
const sync_adapters_source = @embedFile("../../native/sync/sync_adapters.zig");
const sync_state_store_source = @embedFile("../../native/sync/sync_state_store.zig");
const sync_service_test_source = @embedFile("../../native/sync/sync_service_test.zig");
const sync_transport_harness_source = @embedFile("../../native/sync/sync_transport_harness.zig");
const workspace_source = @embedFile("../../native/storage/workspace.zig");
const storage_volume_source = @embedFile("../../native/storage/storage_volume.zig");

pub fn isolationProofDepthGate() !void {
    try std.testing.expect(runtime_negative_proofs.processIsolationBlocksForeignSharedMemory());
    try std.testing.expect(runtime_negative_proofs.syscallSubjectSpoofingIsRejected());
    try std.testing.expect(runtime_negative_proofs.rawNetworkSendBypassIsDenied());
}

pub fn networkTransportHardeningGate() !void {
    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const owner = spec_support.service(701);
    const app = spec_support.app(702);
    const source = spec_support.device(703);
    const target = spec_support.device(704);
    const relay = try policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.backlog.example",
    });
    const relay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = spec_support.policyAuthority(705),
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 81, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 20 },
        .audit = .{},
    });

    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var harness = sync_transport.Harness.init();
    const session = try harness.openRelay(&broker, .{
        .task_id = 81,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.backlog.example" } },
        .now_ticks = 10,
    }, source, target, "relay.backlog.example");
    const packet = try harness.encryptPacket(&session, "backlog transport frame");
    try std.testing.expect(packet.encrypted);
    try std.testing.expect(!std.mem.eql(u8, packet.ciphertextSlice(), "backlog transport frame"));

    var relay_queue = sync_transport.Relay.init();
    _ = try harness.sendRelayPacket(&relay_queue, &session, "backlog op frame");
    var plaintext_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_queue.deliverNext(&session, plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("backlog op frame", delivered);

    var booted_relay = try sync_transport.BootedOverlayRelayService.init(812, 813, "relay.backlog.example");
    const signed_frame = try harness.encryptSignedFrame(&session, "booted relay frame", spec_support.signer("backlog.relay", 0x81));
    try std.testing.expectError(error.EgressDenied, booted_relay.submitSignedFrame(82, &session, signed_frame));
    try booted_relay.submitSignedFrame(81, &session, signed_frame);
    var booted_plaintext_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const booted_delivered = (try booted_relay.deliverNext(81, &session, booted_plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("booted relay frame", booted_delivered);
    try std.testing.expectEqual(@as(usize, 1), booted_relay.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay.delivered_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay.rejected_packets);

    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, .{
        .task_id = 81,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "unexpected.backlog.example" } },
        .now_ticks = 10,
    }, source, target, "relay.backlog.example"));
}

pub fn syncAdapterDepthGate() !void {
    const laptop = spec_support.device(711);
    const tablet = spec_support.device(712);
    var laptop_log = sync_adapters.DocumentOperationLog{};
    var tablet_log = sync_adapters.DocumentOperationLog{};
    try laptop_log.append(try sync_adapters.DocumentOperation.insert(5, " from laptop", laptop, 1));
    try tablet_log.append(try sync_adapters.DocumentOperation.insert(5, " and tablet", tablet, 1));

    var merged_log = sync_adapters.DocumentOperationLog{};
    var output: [96]u8 = undefined;
    const merged = try sync_adapters.mergeDocumentOperationLogs("hello", &laptop_log, &tablet_log, &merged_log, output[0..]);
    try std.testing.expectEqualStrings("hello and tablet from laptop", merged);
    try std.testing.expectEqual(@as(u64, 1), merged_log.clockFor(laptop));
    try std.testing.expectEqual(@as(u64, 1), merged_log.clockFor(tablet));

    try merged_log.mergeFrom(&tablet_log);
    var replay: [96]u8 = undefined;
    const replayed = try merged_log.apply("hello", replay[0..]);
    try std.testing.expectEqualStrings(merged, replayed);
}

pub fn syncPrivateOverlayEndToEndGate() !void {
    try expectContains(sync_transport_harness_source, "SignedEncryptedFrame");
    try expectContains(sync_transport_harness_source, "encryptSignedFrame");
    try expectContains(sync_transport_harness_source, "verifySignedFrame");
    try expectContains(sync_transport_harness_source, "caller_task_id != session.task_id");
    try expectContains(sync_service_test_source, "deterministicTwoDeviceOverlayReplication");
    try expectContains(sync_service_test_source, "openOverlaySession");
    try expectContains(sync_service_test_source, "replicateWorkspace");
    try expectContains(sync_service_test_source, "relay_queue.submit");
    try expectContains(sync_service_impl_source, "sendOverlayRelayFrameViaService");
    try sync_service_test.deterministicTwoDeviceOverlayReplication();
}

pub fn componentAbiDepthGate() !void {
    const iface = typed_component_abi.Interface(.service_registry);
    try std.testing.expectEqual(typed_component_abi.coverage_references.len, typed_component_abi.coverageReferenceCountForRequirement("REQ-COMPONENT-MODEL"));
    try std.testing.expectEqualStrings("zigos.object.workspace", typed_component_abi.interfaceForService(.storage_object).name);

    var header = typed_component_abi.WireHeader{
        .interface_major = 1,
        .interface_minor = 0,
        .operation = @intFromEnum(typed_component_abi.OperationId.service_connect),
        .request_len = @sizeOf(typed_component_abi.ServiceConnectionRequest),
        .response_len = @sizeOf(typed_component_abi.ServiceConnectionResponse),
        .correlation_id = 901,
        .subject_task_id = 77,
    };
    try typed_component_abi.validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(typed_component_abi.ServiceConnectionRequest),
        @sizeOf(typed_component_abi.ServiceConnectionResponse),
    );

    header.subject_task_id = 0;
    try std.testing.expectError(error.SubjectTaskRequired, typed_component_abi.validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(typed_component_abi.ServiceConnectionRequest),
        @sizeOf(typed_component_abi.ServiceConnectionResponse),
    ));
    header.subject_task_id = 77;
    header.response_len -= 1;
    try std.testing.expectError(error.MalformedMessage, typed_component_abi.validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(typed_component_abi.ServiceConnectionRequest),
        @sizeOf(typed_component_abi.ServiceConnectionResponse),
    ));
}

pub fn indexedHotPathTablesGate() !void {
    try expectContains(indexed_arena_source, "used_count");
    try expectContains(indexed_arena_source, "return self.used_count");

    try expectContains(service_registry_source, "BindingArena");
    try expectContains(service_registry_source, "bindings: BindingArena");
    try expectContains(component_abi_schema_source, "pub const InterfaceId");
    try expectContains(component_abi_schema_source, "interface_id: InterfaceId");
    try expectContains(component_abi_schema_source, "interfaceIdForService");
    try expectContains(service_registry_source, "interface_id: typed_component_abi.InterfaceId");
    try expectContains(service_registry_source, "interfaceIdForRequest");
    try expectContains(service_registry_source, "interfaceIdKey");
    try expectMissing(service_registry_source, "fixed_table");
    try expectMissing(service_registry_source, "firstFreeSlot");
    try expectMissing(service_registry_source, "hashInterface");
    try expectMissing(service_registry_source, "interfaceNameKey");
    try expectMissing(service_registry_source, "interface_hash");

    try expectContains(userspace_scheduler_source, "SchedulerSlotArena");
    try expectContains(userspace_scheduler_source, "slots: SchedulerSlotArena");
    try expectContains(userspace_scheduler_source, "ready_heads");
    try expectContains(userspace_scheduler_source, "selectReadyResourceClass");
    try expectContains(userspace_scheduler_source, "wakeTask");
    try expectContains(userspace_scheduler_source, "refillTaskBudget");
    try expectContains(userspace_scheduler_source, "deadline_tick");
    try expectContains(userspace_scheduler_source, "configureResourceState");
    try expectContains(userspace_scheduler_source, "accelerator_claim_heads");
    try expectContains(userspace_scheduler_source, "grantNextAcceleratorClaim");
    try expectMissing(userspace_scheduler_source, "fixed_table");
    try expectMissing(userspace_scheduler_source, "firstFreeSlot");
    try expectMissing(userspace_scheduler_source, "next_index");
    try expectMissing(userspace_scheduler_source, "while (attempts < self.slots.slots.len)");

    try expectContains(accelerator_scheduler_source, "ClaimArena");
    try expectContains(accelerator_scheduler_source, "claims: ClaimArena");
    try expectContains(accelerator_scheduler_source, "ClaimTaskIndex");
    try expectContains(accelerator_scheduler_source, "claim_task_index");
    try expectMissing(accelerator_scheduler_source, "claims: [MAX_ENGINE_CLAIMS]");
    try expectMissing(accelerator_scheduler_source, "for (&self.claims)");
    try expectMissing(accelerator_scheduler_source, "for (self.claims)");

    try expectContains(indexing_service_source, "DocumentArena");
    try expectContains(indexing_service_source, "documents: DocumentArena");
    try expectMissing(indexing_service_source, "fixed_table");
    try expectMissing(indexing_service_source, "firstFreeSlot");

    try expectContains(event_ledger_source, "EventArena");
    try expectContains(event_ledger_source, "kind_index");
    try expectContains(event_ledger_source, "subject_index");
    try expectContains(event_ledger_source, "task_index");
    try expectContains(event_ledger_source, "visitIndex");

    try expectContains(compositor_session_source, "WindowArena");
    try expectContains(compositor_session_source, "ReviewItemArena");
    try expectContains(compositor_session_source, "windows: WindowArena");
    try expectContains(compositor_session_source, "items: ReviewItemArena");
    try expectMissing(compositor_session_source, "windows: [MAX_WINDOWS]");
    try expectMissing(compositor_session_source, "items: [MAX_REVIEW_ITEMS]");

    try expectContains(native_ux_source, "FlowArena");
    try expectContains(native_ux_source, "flows: FlowArena");
    try expectContains(native_ux_source, "flowAtOrder");
    try expectMissing(native_ux_source, "flows: [MAX_FLOWS]");
    try expectMissing(native_ux_source, "for (&self.flows)");
    try expectMissing(native_ux_source, "for (self.flows)");

    try expectContains(sync_transport_harness_source, "RelayPacketArena");
    try expectContains(sync_transport_harness_source, "RelaySessionIndex");
    try expectMissing(sync_transport_harness_source, "for (&self.packets)");

    try expectContains(sync_service_impl_source, "OverlaySessionArena");
    try expectContains(sync_service_impl_source, "overlay_sessions: OverlaySessionArena");
    try expectContains(sync_service_impl_source, "closed_overlay_sessions");
    try expectContains(sync_service_impl_source, "active_overlay_session_count");
    try expectMissing(sync_service_impl_source, "overlay_sessions: [MAX_SERVICE_OVERLAY_SESSIONS]");
    try expectMissing(sync_service_impl_source, "for (&self.overlay_sessions)");
    try expectMissing(sync_service_impl_source, "for (self.overlay_sessions)");

    try expectContains(sync_adapters_source, "TransportFrameArena");
    try expectContains(sync_adapters_source, "TransportFrameTargetIndex");
    try expectContains(sync_adapters_source, "TransportFramePathIndex");
    try expectContains(sync_adapters_source, "frames: TransportFrameArena");
    try expectMissing(sync_adapters_source, "frames: [MAX_TRANSPORT_FRAMES]");
    try expectMissing(sync_adapters_source, "for (&self.frames)");
    try expectMissing(sync_adapters_source, "for (self.frames)");

    try expectContains(sync_state_store_source, "record_prefix = \"state/v4/\"");
    try expectContains(sync_state_store_source, "putRecord");
    try expectContains(sync_state_store_source, "deleteStaleRecords");
    try expectContains(sync_state_store_source, "storage.entries");
    try expectMissing(sync_state_store_source, "state_codec");
    try expectMissing(sync_state_store_source, "state_codec.serialize");
    try expectMissing(sync_state_store_source, "decodeStateIndex");
    try expectMissing(sync_state_store_source, "max_state_bytes");
    try expectMissing(sync_state_store_source, "chunk_dirty");

    try expectContains(workspace_source, "WorkspacePathIndex");
    try expectContains(workspace_source, "path_index: WorkspacePathIndex");
    try expectContains(workspace_source, "mutation_log: WorkspaceMutationLog");
    try expectContains(workspace_source, "share_table: WorkspaceShareTable");
    try expectContains(workspace_source, "staging: WorkspaceStagingState");
    try expectContains(workspace_source, "recoverable_deletes: RecoverableDeleteLog");
    try expectContains(workspace_source, "leaf_hashes");
    try expectContains(workspace_source, "root_address = workspace.path_index.root_address");
    try expectContains(workspace_source, "findIndexedEntryPath");
    try expectContains(workspace_source, "rebuildPathMerkle");
    try expectContains(storage_volume_source, "workspace-state/v4");
    try expectContains(storage_volume_source, "hashBytes(hash, &record.path_index.root_address)");
    try expectMissing(storage_volume_source, "workspace_state_buffer");
    try expectMissing(storage_volume_source, "max_workspace_state_bytes");

    try expectContains(service_catalog_source, "owner_key: BootstrapOwnerKey");
    try expectContains(service_catalog_source, "service_record_key: BootstrapServiceRecordKey");
    try expectContains(session_bootstrap_source, "ownerForServiceClass");
    try expectContains(session_bootstrap_source, "serviceRecordForClass");
    try expectContains(session_bootstrap_source, "for (service_catalog.catalog)");
    try expectContains(service_bootstrap_source, "pub const LaunchServiceRequest");
    try expectContains(session_service_bootstrap_source, "launchContractService(.{");
    try expectMissing(session_manager_boot_flow_source, "fn serviceOwner");
    try expectMissing(session_manager_boot_flow_source, "fn serviceRecord");
    try expectMissing(session_service_bootstrap_source, "fn serviceOwner");
    try expectMissing(session_service_bootstrap_source, "fn serviceId");
}

pub fn driverBoundaryAuditGate() !void {
    var capabilities = capability.CapabilityTable.init();
    var directory = driver_service.Directory.init();
    const holder = spec_support.service(811);
    const authority = try spec_support.driverAuthority(&capabilities, holder, 812, 0x8086_100E_0007, .network_adapter);

    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.backlog",
        .display_name = "Backlog Driver",
        .publisher = "zigos.spec",
        .signature = .{ .format = "ed25519", .signer = "zigos-spec-driver" },
    };
    const driver = try directory.register(.{
        .service_id = 811,
        .owner_task_id = 812,
        .device_id = 0x8086_100E_0007,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = holder,
        .now_ticks = 1,
        .bundle = bundle,
    });
    try std.testing.expect(driver.allowsDma(driver.dma_ranges[0].base, 64));
    try std.testing.expect(!driver.allowsDma(driver.dma_ranges[0].base - 64, 128));

    var rejected_directory = driver_service.Directory.init();
    try std.testing.expectError(error.InvalidBootstrapTransport, rejected_directory.register(.{
        .service_id = 812,
        .owner_task_id = 812,
        .device_id = 0x8086_100E_0007,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = holder,
        .now_ticks = 1,
        .bundle = bundle,
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));

    try deviceBrokerNegativeAuthorityGate();
}

fn deviceBrokerNegativeAuthorityGate() !void {
    const device_id: u64 = 0x0000_1F00_00C1;

    device_broker.reset();
    defer device_broker.reset();
    try std.testing.expect(device_broker.publishAtaController(device_id, .{
        .base_port = 0x1F0,
        .ctrl_port = 0x3F6,
        .is_master = true,
        .irq_line = 14,
        .sector_count = 4096,
    }));

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(
        spec_support.policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const driver_task = try runtime.createTask(.{
        .owner = spec_support.service(813),
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const untrusted_task = try runtime.createTask(.{
        .owner = spec_support.app(814),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const device_authority = try mintBrokeredDeviceAuthority(
        &capabilities,
        driver_task.owner,
        driver_task.id,
        device_id,
        10,
        100,
    );
    try runtime.grantCapability(driver_task.id, device_authority.id);

    try kernel.devicePortWrite(
        kernelContext(driver_task.id, .device_port_write, device_authority.id, .{ .device = device_id }),
        0x1F0 + 7,
        .u8,
        0x5A,
        12,
    );
    try std.testing.expectEqual(@as(u32, 0x5A), try kernel.devicePortRead(
        kernelContext(driver_task.id, .device_port_read, device_authority.id, .{ .device = device_id }),
        0x1F0 + 7,
        .u8,
        12,
    ));

    try std.testing.expectError(error.CapabilityNotFound, kernel.deviceDescribe(
        kernelContext(untrusted_task.id, .device_describe, device_authority.id, .{ .device = device_id }),
        12,
    ));
    try std.testing.expectError(error.InvalidPort, kernel.devicePortRead(
        kernelContext(driver_task.id, .device_port_read, device_authority.id, .{ .device = device_id }),
        0x2F8,
        .u8,
        12,
    ));

    const expired_authority = try mintBrokeredDeviceAuthority(
        &capabilities,
        driver_task.owner,
        driver_task.id,
        device_id,
        1,
        2,
    );
    try runtime.grantCapability(driver_task.id, expired_authority.id);
    try std.testing.expectError(error.CapabilityRevoked, kernel.deviceDescribe(
        kernelContext(driver_task.id, .device_describe, expired_authority.id, .{ .device = device_id }),
        3,
    ));

    const restart_generation_authority = try mintBrokeredDeviceAuthority(
        &capabilities,
        driver_task.owner,
        driver_task.id,
        device_id,
        20,
        100,
    );
    try capabilities.revokeTargetAuthority(restart_generation_authority.id);
    try std.testing.expectError(error.CapabilityRevoked, kernel.devicePortRead(
        kernelContext(driver_task.id, .device_port_read, device_authority.id, .{ .device = device_id }),
        0x1F0 + 7,
        .u8,
        20,
    ));

    const rebound_authority = try mintBrokeredDeviceAuthority(
        &capabilities,
        driver_task.owner,
        driver_task.id,
        device_id,
        20,
        100,
    );
    try runtime.grantCapability(driver_task.id, rebound_authority.id);
    const rebound_descriptor = try kernel.deviceDescribe(
        kernelContext(driver_task.id, .device_describe, rebound_authority.id, .{ .device = device_id }),
        20,
    );
    try std.testing.expectEqual(device_id, rebound_descriptor.device_id);
}

fn mintBrokeredDeviceAuthority(
    capabilities: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
) capability.Error!capability.Capability {
    return capabilities.mintBootRoot(.{
        .holder = holder,
        .issuer = spec_support.policyAuthority(1),
        .target = driver_service.authorityTarget(device_id),
        .rights = driver_service.allowedRightsFor(.storage_controller),
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = issued_at_ticks,
            .expires_at_ticks = expires_at_ticks,
            .renewable = true,
        },
        .audit = .{},
    });
}

pub fn kernelBootstrapShimBoundaryGate() !void {
    try std.testing.expectEqualStrings("bootstrap_network_shim", kernel_ethernet.kernel_boundary_role);
    try std.testing.expect(!kernel_ethernet.publishes_full_network_service);
    try std.testing.expect(kernel_ethernet.network_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, kernel_ethernet.rejectDataPlaneExport(.{
        .service_id = 811,
        .device_id = 0x8086_100E_0007,
        .frame_len = 64,
    }));

    try std.testing.expectEqualStrings("bootstrap_network_link_shim", kernel_link_port.kernel_boundary_role);
    try std.testing.expect(!kernel_link_port.publishes_full_network_service);
    try std.testing.expect(kernel_link_port.network_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, kernel_link_port.rejectKernelDataPlaneTransport(.{
        .device_id = 0x8086_100E_0007,
        .service_id = 811,
    }));

    try std.testing.expectEqualStrings("bootstrap_storage_inventory_shim", kernel_ata.kernel_boundary_role);
    try std.testing.expect(!kernel_ata.publishes_full_storage_service);
    try std.testing.expect(kernel_ata.ata_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelStorageDataPlaneDisabled, kernel_ata.rejectKernelDataPlaneTransfer(.{
        .device_id = 0x1F001,
        .lba = 7,
        .sector_count = 1,
    }));

    try std.testing.expectEqualStrings("bootstrap_device_inventory_shim", kernel_data_plane_boundary.kernel_boundary_role);
    try std.testing.expect(!kernel_data_plane_boundary.publishes_device_data_planes);
    try std.testing.expect(!kernel_data_plane_boundary.publishes_windowing_data_plane);
    try std.testing.expect(!kernel_data_plane_boundary.publishes_package_data_plane);
    try std.testing.expect(!kernel_data_plane_boundary.publishes_indexing_data_plane);
    try std.testing.expect(!kernel_data_plane_boundary.publishes_sync_data_plane);
    try std.testing.expectError(error.KernelDeviceDataPlaneDisabled, kernel_data_plane_boundary.rejectKernelDeviceDataPlane(.{
        .service_id = 811,
        .device_id = 0x1F001,
        .device_class = @intFromEnum(driver_service.DeviceClass.storage_controller),
    }));
    const excluded_subsystems = [_]kernel_data_plane_boundary.SubsystemPublicationRequest{
        .{ .kind = .windowing, .service_id = 831, .owner_task_id = 841, .endpoint_id = 851 },
        .{ .kind = .package_install, .service_id = 832, .owner_task_id = 842, .endpoint_id = 852 },
        .{ .kind = .indexing, .service_id = 833, .owner_task_id = 843, .endpoint_id = 853 },
        .{ .kind = .sync_replication, .service_id = 834, .owner_task_id = 844, .endpoint_id = 854 },
    };
    for (excluded_subsystems) |request| {
        try std.testing.expectError(
            error.KernelSubsystemDataPlaneDisabled,
            kernel_data_plane_boundary.rejectKernelSubsystemDataPlane(request),
        );
    }
    try std.testing.expectError(error.KernelDeviceDataPlaneDisabled, kernel_data_plane_boundary.rejectKernelSubsystemDataPlane(.{
        .kind = .device,
        .service_id = 835,
        .owner_task_id = 845,
        .endpoint_id = 855,
    }));

    try bootedDriverKernelBoundaryGate();
}

pub fn bootedDriverKernelBoundaryGate() !void {
    const BoundaryRuntime = struct {
        tasks: *task_runtime.Runtime,
        activations: driver_runtime.Runtime = driver_runtime.Runtime.init(),
        activation_count: usize = 0,
        deactivation_count: usize = 0,
        rehost_count: usize = 0,

        pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, tick: u64) !driver_runtime.ActivationRecord {
            const rehosted = try self.tasks.rehostTask(driver.owner_task_id, tick);
            const activation = try self.activations.activateAt(driver, tick);
            self.activation_count += 1;
            if (rehosted) self.rehost_count += 1;
            return activation;
        }

        pub fn deactivate(self: *@This(), service_id: u64) bool {
            const deactivated = self.activations.deactivate(service_id);
            if (deactivated) self.deactivation_count += 1;
            return deactivated;
        }
    };

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(
        spec_support.policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );

    const bootstrap_task = try runtime.createTask(.{
        .owner = spec_support.service(821),
        .component_class = .session_manager,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const bootstrap_authority = try capabilities.mintBootRoot(.{
        .holder = bootstrap_task.owner,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .service, .id = 821 },
        .rights = .{ .service = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .shared_memory_create = true,
            .shared_memory_map = true,
            .shared_memory_unmap = true,
            .shared_memory_revoke = true,
            .resource_query = true,
            .accounting_query = true,
            .time_query = true,
            .capability_query = true,
            .ipc_peer = true,
        } },
        .scope = .{ .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 1_000, .renewable = true },
    });
    try runtime.grantCapability(bootstrap_task.id, bootstrap_authority.id);

    var session_supervisor = supervisor.Supervisor.init();
    const storage_service = try session_supervisor.register(.storage_object, spec_support.service(822));
    try std.testing.expect(session_supervisor.markHealthy(storage_service.id, 2));

    const control_image = task_runtime.syntheticUserspaceImage("driver-boundary-control", "zigos.boundary.control");
    const control_task = try kernel.taskCreate(kernelContext(bootstrap_task.id, .task_create, bootstrap_authority.id, .{ .task = 0 }), .{
        .owner = spec_support.service(823),
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "driver-boundary-control",
            .entry = "zigos.boundary.control",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 821,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.boundary.control",
        },
        .userspace_image = &control_image,
    }, 3);

    const storage_driver_image = task_runtime.syntheticUserspaceImage("storage-driver-boundary", "zigos.system.storage-driver");
    const driver_task = try kernel.taskCreate(kernelContext(bootstrap_task.id, .task_create, bootstrap_authority.id, .{ .task = 0 }), .{
        .owner = storage_service.owner,
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "storage-driver-boundary",
            .entry = "zigos.system.storage-driver",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 822,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.storage-driver",
        },
        .userspace_image = &storage_driver_image,
    }, 4);

    const untrusted_image = task_runtime.syntheticUserspaceImage("untrusted-driver-peer", "app.untrusted.driver-peer");
    const untrusted_task = try kernel.taskCreate(kernelContext(bootstrap_task.id, .task_create, bootstrap_authority.id, .{ .task = 0 }), .{
        .owner = spec_support.app(824),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "untrusted-driver-peer",
            .entry = "app.untrusted.driver-peer",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 823,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.untrusted.driver-peer",
        },
        .userspace_image = &untrusted_image,
    }, 5);

    const driver_task_record = runtime.find(driver_task.task_id).?;
    try std.testing.expect(driver_task_record.runsAsUserspaceProcess());
    try std.testing.expect(driver_task_record.hasLoadedExecutable());
    try std.testing.expect(runtime.processSeparated(driver_task.task_id, control_task.task_id));
    try std.testing.expect(runtime.processSeparated(driver_task.task_id, untrusted_task.task_id));

    const device_id: u64 = 0x0000_1F00_00B0;
    const device_authority = try spec_support.driverAuthority(
        &capabilities,
        storage_service.owner,
        driver_task.task_id,
        device_id,
        .storage_controller,
    );
    try runtime.grantCapability(driver_task.task_id, device_authority.id);

    var directory = driver_service.Directory.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.storage-boundary",
        .display_name = "Storage Boundary Driver",
        .publisher = "zigos.spec",
        .signature = .{ .format = "ed25519", .signer = "zigos-spec-driver" },
    };
    const registered_driver = try directory.register(.{
        .service_id = storage_service.id,
        .owner_task_id = driver_task.task_id,
        .device_id = device_id,
        .device_class = .storage_controller,
        .authority_capability_id = device_authority.id,
        .capability_table = &capabilities,
        .requester = storage_service.owner,
        .now_ticks = 6,
        .bundle = bundle,
    });
    try std.testing.expect(session_supervisor.noteDriverAttached(storage_service.id, .storage_controller, device_authority.id, 6));
    try std.testing.expect(runtime.hasCapability(driver_task.task_id, device_authority.id));
    try std.testing.expect(!runtime.hasCapability(control_task.task_id, device_authority.id));
    try std.testing.expect(!runtime.hasCapability(untrusted_task.task_id, device_authority.id));

    const driver_endpoint = try kernel.endpointCreate(
        kernelContext(bootstrap_task.id, .endpoint_create, bootstrap_authority.id, .{ .task = driver_task.task_id }),
        driver_task.task_id,
        "storage-driver.io",
        .{ .local_only = true, .service_port = true },
        7,
    );
    const control_endpoint = try kernel.endpointCreate(
        kernelContext(bootstrap_task.id, .endpoint_create, bootstrap_authority.id, .{ .task = control_task.task_id }),
        control_task.task_id,
        "storage-driver.control",
        .{ .local_only = true },
        8,
    );
    _ = try kernel.endpointConnect(
        kernelContext(control_task.task_id, .endpoint_connect, control_endpoint.capability_id, .{ .endpoint = control_endpoint.endpoint.endpoint_id }),
        driver_endpoint.capability_id,
        driver_endpoint.endpoint.endpoint_id,
        9,
    );

    const request_ring = try kernel.sharedMemoryCreate(
        kernelContext(bootstrap_task.id, .shared_memory_create, bootstrap_authority.id, .{ .task = control_task.task_id }),
        control_task.task_id,
        4096,
        10,
    );
    const completion_ring = try kernel.sharedMemoryCreate(
        kernelContext(bootstrap_task.id, .shared_memory_create, bootstrap_authority.id, .{ .task = control_task.task_id }),
        control_task.task_id,
        4096,
        11,
    );
    _ = try kernel.sharedMemoryMap(
        kernelContext(control_task.task_id, .shared_memory_map, request_ring.capability_id, .{ .shared_memory = request_ring.object.object_id }),
        control_task.task_id,
        12,
    );
    _ = try kernel.sharedMemoryMap(
        kernelContext(control_task.task_id, .shared_memory_map, completion_ring.capability_id, .{ .shared_memory = completion_ring.object.object_id }),
        control_task.task_id,
        12,
    );

    try kernel.endpointSend(
        kernelContext(control_task.task_id, .endpoint_send, control_endpoint.capability_id, .{ .endpoint = control_endpoint.endpoint.endpoint_id }),
        100,
        "ring=request",
        request_ring.capability_id,
        false,
        13,
    );
    const request_setup = (try kernel.endpointRecv(
        kernelContext(driver_task.task_id, .endpoint_recv, driver_endpoint.capability_id, .{ .endpoint = driver_endpoint.endpoint.endpoint_id }),
        driver_task.task_id,
        14,
    )).?;
    try std.testing.expectEqualStrings("ring=request", request_setup.payload[0..request_setup.payload_len]);
    const driver_request_ring_capability = request_setup.attached_capability.?.capability_id;
    _ = try kernel.sharedMemoryMap(
        kernelContext(driver_task.task_id, .shared_memory_map, driver_request_ring_capability, .{ .shared_memory = request_ring.object.object_id }),
        driver_task.task_id,
        14,
    );

    try kernel.endpointSend(
        kernelContext(control_task.task_id, .endpoint_send, control_endpoint.capability_id, .{ .endpoint = control_endpoint.endpoint.endpoint_id }),
        101,
        "ring=completion",
        completion_ring.capability_id,
        false,
        15,
    );
    const completion_setup = (try kernel.endpointRecv(
        kernelContext(driver_task.task_id, .endpoint_recv, driver_endpoint.capability_id, .{ .endpoint = driver_endpoint.endpoint.endpoint_id }),
        driver_task.task_id,
        16,
    )).?;
    try std.testing.expectEqualStrings("ring=completion", completion_setup.payload[0..completion_setup.payload_len]);
    const driver_completion_ring_capability = completion_setup.attached_capability.?.capability_id;
    _ = try kernel.sharedMemoryMap(
        kernelContext(driver_task.task_id, .shared_memory_map, driver_completion_ring_capability, .{ .shared_memory = completion_ring.object.object_id }),
        driver_task.task_id,
        16,
    );

    try kernel.endpointSend(
        kernelContext(control_task.task_id, .endpoint_send, control_endpoint.capability_id, .{ .endpoint = control_endpoint.endpoint.endpoint_id }),
        102,
        "io:read lba=7 sectors=1",
        null,
        false,
        17,
    );
    const io_request = (try kernel.endpointRecv(
        kernelContext(driver_task.task_id, .endpoint_recv, driver_endpoint.capability_id, .{ .endpoint = driver_endpoint.endpoint.endpoint_id }),
        driver_task.task_id,
        18,
    )).?;
    try std.testing.expectEqualStrings("io:read lba=7 sectors=1", io_request.payload[0..io_request.payload_len]);

    try kernel.endpointSend(
        kernelContext(driver_task.task_id, .endpoint_send, driver_endpoint.capability_id, .{ .endpoint = driver_endpoint.endpoint.endpoint_id }),
        103,
        "io:complete status=ok",
        null,
        false,
        19,
    );
    const io_completion = (try kernel.endpointRecv(
        kernelContext(control_task.task_id, .endpoint_recv, control_endpoint.capability_id, .{ .endpoint = control_endpoint.endpoint.endpoint_id }),
        control_task.task_id,
        20,
    )).?;
    try std.testing.expectEqualStrings("io:complete status=ok", io_completion.payload[0..io_completion.payload_len]);

    try std.testing.expectEqual(@as(u16, 2), shared.mappingsForTask(ids.task(control_task.task_id)));
    try std.testing.expectEqual(@as(u16, 2), shared.mappingsForTask(ids.task(driver_task.task_id)));
    try std.testing.expectEqual(@as(u16, 0), shared.mappingsForTask(ids.task(untrusted_task.task_id)));

    const passed_request_ring = capabilities.query(driver_request_ring_capability).?;
    try std.testing.expect(passed_request_ring.holder.eql(storage_service.owner));
    try std.testing.expectEqual(driver_task.task_id, passed_request_ring.scope.task_id.?);
    try std.testing.expect(runtime.hasCapability(driver_task.task_id, driver_request_ring_capability));
    try std.testing.expect(!runtime.hasCapability(untrusted_task.task_id, driver_request_ring_capability));

    var device_capabilities: [2]capability.Capability = undefined;
    const matching_device_capabilities = capabilities.queryByTarget(driver_service.authorityTarget(device_id), &device_capabilities);
    try std.testing.expectEqual(@as(usize, 1), matching_device_capabilities.len);
    try std.testing.expectEqual(driver_task.task_id, matching_device_capabilities[0].scope.task_id.?);

    var rejected_directory = driver_service.Directory.init();
    try std.testing.expectError(error.AuthorityScopeViolation, rejected_directory.register(.{
        .service_id = storage_service.id + 100,
        .owner_task_id = untrusted_task.task_id,
        .device_id = device_id,
        .device_class = .storage_controller,
        .authority_capability_id = device_authority.id,
        .capability_table = &capabilities,
        .requester = storage_service.owner,
        .now_ticks = 21,
        .bundle = bundle,
    }));
    try std.testing.expectError(error.CapabilityNotFound, kernel.sharedMemoryMap(
        kernelContext(untrusted_task.task_id, .shared_memory_map, request_ring.capability_id, .{ .shared_memory = request_ring.object.object_id }),
        untrusted_task.task_id,
        21,
    ));
    try std.testing.expectError(error.CapabilityNotFound, kernel.endpointRecv(
        kernelContext(untrusted_task.task_id, .endpoint_recv, driver_endpoint.capability_id, .{ .endpoint = driver_endpoint.endpoint.endpoint_id }),
        untrusted_task.task_id,
        21,
    ));
    try std.testing.expectError(error.CapabilityNotFound, kernel.deviceDescribe(
        kernelContext(untrusted_task.task_id, .device_describe, device_authority.id, .{ .device = device_id }),
        21,
    ));

    var boundary_runtime = BoundaryRuntime{ .tasks = &runtime };
    _ = try boundary_runtime.activations.activateAt(registered_driver, 21);
    const original_address_space_id = runtime.find(driver_task.task_id).?.address_space_id;
    var ledger = event_ledger.Ledger.init();
    const recovery = try session_supervisor.recoverDriverCrash(
        storage_service.id,
        &directory,
        &boundary_runtime,
        null,
        &ledger,
        22,
        0xD11E,
        "storage driver boundary crash",
    );
    try std.testing.expect(!recovery.visible_impact);
    try std.testing.expectEqual(@as(?u64, null), recovery.notification_id);
    try std.testing.expectEqual(supervisor.ServiceState.healthy, storage_service.state);
    try std.testing.expectEqual(@as(u16, 1), storage_service.restart_count);
    try std.testing.expectEqual(@as(u32, 2), directory.findByService(storage_service.id).?.restart_generation);
    try std.testing.expectEqual(@as(usize, 1), boundary_runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 1), boundary_runtime.activation_count);
    try std.testing.expectEqual(@as(usize, 1), boundary_runtime.rehost_count);
    try std.testing.expect(session_supervisor.hasDiagnostic(storage_service.id, .crash));
    try std.testing.expect(session_supervisor.hasDiagnostic(storage_service.id, .restart_completed));
    const restart_event = ledger.latestKind(.driver_restart).?;
    try std.testing.expect(restart_event.subject.eql(storage_service.owner));
    try std.testing.expectEqual(device_authority.id, restart_event.related_id);

    const restarted_driver_task = runtime.find(driver_task.task_id).?;
    try std.testing.expectEqual(@as(u32, 2), restarted_driver_task.process_generation);
    try std.testing.expect(restarted_driver_task.address_space_id != original_address_space_id);
    try std.testing.expect(runtime.findAddressSpaceConst(original_address_space_id) == null);
    try std.testing.expect(restarted_driver_task.runsAsUserspaceProcess());
    try std.testing.expect(restarted_driver_task.hasLoadedExecutable());
    try std.testing.expect(runtime.hasCapability(driver_task.task_id, device_authority.id));
    try std.testing.expect(runtime.hasCapability(driver_task.task_id, driver_completion_ring_capability));
    try std.testing.expect(!runtime.hasCapability(untrusted_task.task_id, device_authority.id));

    try kernel.endpointSend(
        kernelContext(control_task.task_id, .endpoint_send, control_endpoint.capability_id, .{ .endpoint = control_endpoint.endpoint.endpoint_id }),
        104,
        "io:read after restart",
        null,
        false,
        25,
    );
    const restarted_io_request = (try kernel.endpointRecv(
        kernelContext(driver_task.task_id, .endpoint_recv, driver_endpoint.capability_id, .{ .endpoint = driver_endpoint.endpoint.endpoint_id }),
        driver_task.task_id,
        26,
    )).?;
    try std.testing.expectEqualStrings("io:read after restart", restarted_io_request.payload[0..restarted_io_request.payload_len]);
}

pub fn uxRenderingGate() !void {
    var runtime = task_runtime.Runtime.init();
    const app_task = try runtime.createTask(.{
        .owner = spec_support.app(901),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .ui_surface_id = 55,
    });
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.backlog",
        .display_name = "Backlog App",
        .publisher = "zigos.spec",
        .signature = .{ .format = "ed25519", .signer = "zigos-spec-app" },
    };
    const request = manifest.PermissionRequest{
        .kind = .clipboard,
        .resource = "clipboard://primary",
        .rights = .{ .service = .{} },
        .local_only = true,
        .max_lease_ticks = 30,
    };

    var compositor = compositor_session.Session.init();
    const window = try compositor.beginPermissionReview(1, app_task, bundle);
    const item = try compositor.ensureReviewItem(window.id, bundle, request);
    const decision = try compositor.recordDecision(window.id, request, false, false, null);

    var render_buffer: [1024]u8 = undefined;
    const rendered_window = try compositor_session.renderWindowToBuffer(&render_buffer, window);
    try std.testing.expect(std.mem.indexOf(u8, rendered_window, "type=app_panel") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered_window, "bundle=app.backlog") != null);
    const rendered_item = try compositor_session.renderReviewItemToBuffer(&render_buffer, window.id, item);
    try std.testing.expect(std.mem.indexOf(u8, rendered_item, "resource=clipboard://primary") != null);
    const rendered_decision = try compositor_session.renderDecisionToBuffer(&render_buffer, window.id, decision);
    try std.testing.expect(std.mem.indexOf(u8, rendered_decision, "decision=deny") != null);

    var ledger = event_ledger.Ledger.init();
    try ledger.recordPermissionDecision(spec_support.user(902), app_task.id, .clipboard, false, .policy_denied, 17, "clipboard denied", true);
    var events: [1]event_ledger.Event = undefined;
    const redacted = ledger.queryEvents(.{ .kind = .permission_decision, .task_id = app_task.id }, &events);
    try std.testing.expectEqual(@as(usize, 1), redacted.len);
    try std.testing.expectEqualStrings("redacted", redacted[0].detailSlice());
}

test "backlog gates enforce isolation proof depth" {
    try isolationProofDepthGate();
}

test "backlog gates enforce network transport hardening" {
    try networkTransportHardeningGate();
}

test "backlog gates enforce sync adapter depth" {
    try syncAdapterDepthGate();
}

test "backlog gates enforce component ABI depth" {
    try componentAbiDepthGate();
}

test "backlog gates enforce indexed hot-path tables" {
    try indexedHotPathTablesGate();
}

test "backlog gates enforce driver boundary audit" {
    try driverBoundaryAuditGate();
}

test "backlog gates enforce kernel bootstrap shim boundary" {
    try kernelBootstrapShimBoundaryGate();
}

test "backlog gates enforce UX rendering" {
    try uxRenderingGate();
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

fn expectMissing(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) == null);
}

fn kernelContext(
    caller_task_id: u64,
    operation: abi.NativeOperation,
    capability_id: u64,
    target: native_kernel.KernelTarget,
) native_kernel.KernelCallContext {
    return .{
        .caller_task_id = caller_task_id,
        .presented_capability_id = capability_id,
        .operation = operation,
        .target = target,
    };
}
