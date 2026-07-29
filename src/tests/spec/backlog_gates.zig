const std = @import("std");
const abi = @import("../../native/core/abi.zig");
const architecture_gates = @import("../../native/architecture_gates.zig");
const base_boot_selector = @import("../../native/platform/base_boot_selector.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const component_port = @import("../../native/kernel_api/component_port.zig");
const driver_runtime = @import("../../native/drivers/driver_runtime.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const endpoint = @import("../../native/kernel_api/endpoint.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const hardware_target = @import("../../native/platform/hardware_target.zig");
const ids = @import("../../native/core/ids.zig");
const intel_i225 = @import("../../kernel/drivers/intel_i225.zig");
const immutable_base = @import("../../native/platform/immutable_base.zig");
const kernel_crash_record = @import("../../kernel/platform/crash_record.zig");
const kernel_acpi = @import("../../kernel/platform/acpi.zig");
const kernel_apic = @import("../../kernel/platform/apic.zig");
const kernel_dmar = @import("../../kernel/platform/dmar.zig");
const kernel_data_plane_boundary = @import("../../kernel/boot/init/data_plane_boundary.zig");
const kernel_fadt = @import("../../kernel/platform/fadt.zig");
const kernel_framebuffer = @import("../../kernel/platform/framebuffer.zig");
const kernel_handoff = @import("../../kernel/boot/handoff.zig");
const kernel_hardware_proof = @import("../../kernel/platform/hardware_proof.zig");
const kernel_ethernet = @import("../../kernel/net/ethernet.zig");
const kernel_link_port = @import("../../kernel/net/link_port.zig");
const kernel_nvme = @import("../../kernel/drivers/nvme.zig");
const kernel_pci = @import("../../kernel/drivers/pci.zig");
const kernel_smbios = @import("../../kernel/platform/smbios.zig");
const manifest = @import("../../native/policy/manifest.zig");
const native_app_sdk = @import("../../native/sdk/native_app_sdk.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const network_driver_task = @import("../../native/drivers/network_driver_task.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const kernel_xhci = @import("../../kernel/drivers/xhci.zig");
const principal = @import("../../native/core/principal.zig");
const runtime_negative_proofs = @import("../../native/session/runtime_negative_proofs.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const spec_support = @import("support.zig");
const supervisor = @import("../../native/session/supervisor.zig");
const sync_adapters = @import("../../native/sync/sync_adapters.zig");
const sync_service_test = @import("../../native/sync/sync_service_test.zig");
const sync_transport = @import("../../native/sync/sync_transport.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const typed_component_abi = @import("../../native/services/typed_component_abi.zig");

const COMPOSITOR_RENDER_BUFFER_BYTES: usize = 1024;
const SYNC_ADAPTER_REPLAY_BUFFER_BYTES: usize = 96;
const XHCI_CAPABILITY_MMAP_BYTES: usize = 24;
const DRIVER_RING_BYTES: usize = shared_memory.PAGE_SIZE;

pub fn isolationProofDepthGate() !void {
    try std.testing.expect(runtime_negative_proofs.processIsolationBlocksForeignSharedMemory());
    try std.testing.expect(runtime_negative_proofs.syscallSubjectSpoofingIsRejected());
    try std.testing.expect(runtime_negative_proofs.rawNetworkSendBypassIsDenied());
}

pub fn networkTransportHardeningGate() !void {
    const Driver = struct {
        var send_count: usize = 0;
        var last_frame_len: usize = 0;
        var expected_network_policy_id: u64 = 0;
        var expected_egress_capability_id: u64 = 0;
        var last_frame: [network_driver_task.MAX_NATIVE_FRAME_BYTES]u8 = [_]u8{0} ** network_driver_task.MAX_NATIVE_FRAME_BYTES;

        fn send(frame: []const u8) void {
            send_count += 1;
            last_frame_len = frame.len;
            @memcpy(last_frame[0..frame.len], frame);
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0x70, 0x71, 0x72, 0x73, 0x74 };
        }

        fn broker(request: network_driver_task.EgressRequest) network_driver_task.EgressDecision {
            return .{
                .allowed = request.network_policy_id == expected_network_policy_id,
                .capability_backed = request.egress_capability_id == expected_egress_capability_id,
            };
        }
    };

    Driver.send_count = 0;
    Driver.last_frame_len = 0;
    Driver.expected_network_policy_id = 0;
    Driver.expected_egress_capability_id = 0;
    network_driver_task.reset();
    defer network_driver_task.reset();

    const device = network_driver_task.NetworkDevice{
        .send = Driver.send,
        .getMacAddress = Driver.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&device, 709));
    network_driver_task.setEgressBroker(Driver.broker);

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
    Driver.expected_network_policy_id = relay.id;
    Driver.expected_egress_capability_id = relay_capability.id;
    network_driver_task.bindEgressCapability(relay_capability.id, relay.id);

    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var native_transport = sync_transport.NativeTransportService.init();
    var connection = try native_transport.openRelay(&broker, .{
        .task_id = 81,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.backlog.example" } },
        .now_ticks = 10,
    }, 81, 82, source, target, "relay.backlog.example");
    const signed_delivery = try native_transport.sendSigned(&connection, "backlog transport frame", spec_support.signer("backlog.native", 0x80));
    try std.testing.expect(signed_delivery.endpoint_delivered);
    try std.testing.expect(signed_delivery.network_delivered);
    try std.testing.expectEqual(@as(usize, 1), Driver.send_count);
    const captured = try native_transport.assertLastCapturedFrame(.{
        .session_id = connection.session.id,
        .sequence = signed_delivery.sequence,
        .source_task_id = connection.source_task_id,
        .target_task_id = connection.target_task_id,
        .transport = .relay_assisted,
        .source_device = source,
        .target_device = target,
        .policy_id = relay.id,
        .capability_id = relay_capability.id,
        .forbidden_plaintext = "backlog transport frame",
    });
    try std.testing.expectEqual(sync_transport.NativeTransportAbi.version, captured.abi_version);
    try std.testing.expectEqualSlices(u8, native_transport.capture.last().?.slice(), Driver.last_frame[0..Driver.last_frame_len]);
    try std.testing.expectEqualStrings("backlog transport frame", (try native_transport.receive(&connection)).payload());

    var booted_relay = try sync_transport.BootedOverlayRelayService.init(812, 81, "relay.backlog.example");
    native_transport.disconnect(&connection);
    const fallback = try native_transport.sendWithRelayFallback(&connection, &booted_relay, "booted relay frame", spec_support.signer("backlog.relay", 0x81));
    try std.testing.expect(fallback.relay_fallback);
    try std.testing.expect(!fallback.endpoint_delivered);
    try std.testing.expect(!fallback.network_delivered);
    var booted_plaintext_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const booted_delivered = (try booted_relay.deliverNext(81, &connection.session, booted_plaintext_buffer[0..])).?;
    try std.testing.expectEqualStrings("booted relay frame", booted_delivered);
    try std.testing.expectEqual(@as(usize, 1), booted_relay.accepted_packets);
    try std.testing.expectEqual(@as(usize, 1), booted_relay.delivered_packets);
    try std.testing.expectEqual(@as(usize, 0), booted_relay.rejected_packets);

    try std.testing.expectError(error.EgressDenied, native_transport.openRelay(&broker, .{
        .task_id = 81,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "unexpected.backlog.example" } },
        .now_ticks = 10,
    }, 81, 82, source, target, "relay.backlog.example"));
}

pub fn syncAdapterDepthGate() !void {
    const laptop = spec_support.device(711);
    const tablet = spec_support.device(712);
    var laptop_log = sync_adapters.DocumentOperationLog{};
    var tablet_log = sync_adapters.DocumentOperationLog{};
    try laptop_log.append(try sync_adapters.DocumentOperation.insert(5, " from laptop", laptop, 1));
    try tablet_log.append(try sync_adapters.DocumentOperation.insert(5, " and tablet", tablet, 1));

    var merged_log = sync_adapters.DocumentOperationLog{};
    var output: [SYNC_ADAPTER_REPLAY_BUFFER_BYTES]u8 = undefined;
    const merged = try sync_adapters.mergeDocumentOperationLogs("hello", &laptop_log, &tablet_log, &merged_log, output[0..]);
    try std.testing.expectEqualStrings("hello and tablet from laptop", merged);
    try std.testing.expectEqual(@as(u64, 1), merged_log.clockFor(laptop));
    try std.testing.expectEqual(@as(u64, 1), merged_log.clockFor(tablet));

    try merged_log.mergeFrom(&tablet_log);
    var replay: [SYNC_ADAPTER_REPLAY_BUFFER_BYTES]u8 = undefined;
    const replayed = try merged_log.apply("hello", replay[0..]);
    try std.testing.expectEqualStrings(merged, replayed);
}

pub fn syncPrivateOverlayEndToEndGate() !void {
    try expectAllMetadataTrue(architecture_gates.sync_private_overlay);
    try sync_service_test.deterministicTwoDeviceOverlayReplication();
}

pub fn componentAbiDepthGate() !void {
    const iface = typed_component_abi.Interface(.service_registry);
    try std.testing.expectEqual(typed_component_abi.coverage_references.len, typed_component_abi.coverageReferenceCountForRequirement("REQ-COMPONENT-MODEL"));
    try std.testing.expectEqualStrings("zigos.object.workspace", typed_component_abi.interfaceForService(.storage_object).name);
    try std.testing.expectEqualStrings("zigos.package.install", typed_component_abi.interfaceForService(.package_install_update).name);

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

    const package_iface = typed_component_abi.Interface(.package_install);
    const rollback_header = typed_component_abi.WireHeader{
        .interface_major = package_iface.version_major,
        .interface_minor = package_iface.version_minor,
        .operation = @intFromEnum(typed_component_abi.OperationId.package_rollback),
        .request_len = @sizeOf(typed_component_abi.PackageRollbackRequest),
        .response_len = @sizeOf(typed_component_abi.PackageRollbackResponse),
        .correlation_id = 902,
        .subject_task_id = 78,
    };
    try typed_component_abi.validateMessage(
        package_iface,
        .package_rollback,
        rollback_header,
        @sizeOf(typed_component_abi.PackageRollbackRequest),
        @sizeOf(typed_component_abi.PackageRollbackResponse),
    );

    var sim = native_app_sdk.simulator.Simulator.init();
    const suite = native_app_sdk.example_apps.firstPartySuite();
    for (suite) |package| {
        const compiled = try native_app_sdk.app_platform.compile(package);
        try std.testing.expect(compiled.operationCount() >= 4);
        const generated = try sim.parseAndGenerate(package.idl_source);
        try std.testing.expect(std.mem.indexOf(u8, generated.slice(), "OperationDescriptor") != null);
        const review = try sim.reviewPermissions(.{
            .bundle = package.bundle,
            .signer = package.signer,
        }, &.{});
        try std.testing.expect(review.grant_count >= manifest.requiredPermissionCount(package.bundle));
        _ = try sim.install(.{
            .bundle = package.bundle,
            .signer = package.signer,
            .data_schema_version = package.data_schema_version,
        });
        const launched = try sim.launchNativeApp(package.bundle.bundle_id);
        try std.testing.expect(launched.signed_provenance);
        try std.testing.expect(launched.component_count >= 3);
        try std.testing.expect(launched.background_allowed);
        try std.testing.expectEqual(task_runtime.TaskState.active, launched.state);
        try std.testing.expect(try sim.suspendNativeApp(launched.task_id));
        try std.testing.expect(try sim.resumeNativeApp(launched.task_id));
    }

    var updated_writer = suite[0].bundle;
    updated_writer.version_minor += 1;
    _ = try sim.install(.{
        .bundle = updated_writer,
        .signer = suite[0].signer,
        .data_schema_version = suite[0].data_schema_version,
    });
    _ = try sim.rollback(suite[0].bundle.bundle_id);

    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.package_installed));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_updated));
    try std.testing.expectEqual(@as(usize, 1), sim.debug.countKind(.package_rolled_back));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.permission_review_rendered));
    try std.testing.expectEqual(@as(usize, suite.len), sim.debug.countKind(.native_app_launched));
}

pub fn indexedHotPathTablesGate() !void {
    try expectAllMetadataTrue(architecture_gates.indexed_hot_path_tables);
}

pub fn firstHardwareTargetGate() !void {
    const target = &hardware_target.first_supported_target;
    try std.testing.expectEqualStrings("intel-nuc11tnki5", target.id);
    try std.testing.expectEqualStrings("NUC11TNKi5", target.sku);
    try std.testing.expectEqualStrings("Intel Ethernet Controller I225-LM", target.network);
    try std.testing.expect(hardware_target.coversRequiredSubsystems(target));
    try std.testing.expect(target.required_subsystems.len >= target.required_markers.len);
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_proof_metadata_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":EVIDENCE_SOURCE:REAL_HARDWARE",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_proof_metadata_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":PROOF_MANIFEST:RECORDED",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_proof_metadata_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":ARTIFACT_DIGESTS:RECORDED",
    ));
    try std.testing.expectEqual(@as(usize, 16), hardware_target.nuc11tnki5_hardware_fact_markers.len);
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_hardware_fact_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":SMBIOS_SKU:OBSERVED",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_hardware_fact_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_DMAR:OBSERVED",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_hardware_fact_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":VT_D_SEGMENT_ZERO:OBSERVED",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_hardware_fact_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":NVME_WRITE_READ_COMPLETION:OBSERVED",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_hardware_fact_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":I225_LM_FRAME_INTERRUPT:OBSERVED",
    ));
    try std.testing.expect(containsString(
        hardware_target.nuc11tnki5_hardware_fact_markers[0..],
        hardware_target.nuc11tnki5_marker_prefix ++ ":ATTESTATION_ROOT_LIFECYCLE:OBSERVED",
    ));
    try std.testing.expectEqual(@as(usize, 8), hardware_target.nuc11tnki5_counter_markers.len);
    for (hardware_target.nuc11tnki5_counter_markers) |counter_marker| {
        try std.testing.expect(std.mem.startsWith(u8, counter_marker.marker_prefix, hardware_target.nuc11tnki5_marker_prefix));
        try std.testing.expect(counter_marker.minimum > 0);
    }
    try std.testing.expect(kernel_acpi.signatureMatches("RSD PTR "));
    try std.testing.expectEqual(kernel_apic.EntryType.io_apic, kernel_apic.EntryType.fromByte(1));
    try std.testing.expect(kernel_pci.isIntelI225Lm(.{
        .bus = 0,
        .device = 31,
        .function = 6,
        .vendor_id = kernel_pci.PCI_VENDOR_INTEL,
        .device_id = kernel_pci.PCI_DEVICE_INTEL_I225_LM,
        .class_code = kernel_pci.PCI_CLASS_NETWORK_ADAPTER,
        .subclass = 0,
        .prog_if = 0,
        .bar0 = 0,
        .bar1 = 0,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
    }));
    try std.testing.expect(kernel_pci.isXhciController(.{
        .bus = 0,
        .device = 20,
        .function = 0,
        .vendor_id = kernel_pci.PCI_VENDOR_INTEL,
        .device_id = 0xA0ED,
        .class_code = kernel_pci.PCI_CLASS_SERIAL_BUS_CONTROLLER,
        .subclass = kernel_pci.PCI_SUBCLASS_USB,
        .prog_if = kernel_pci.PCI_PROG_IF_XHCI,
        .bar0 = 0,
        .bar1 = 0,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
    }));
    var mmap = [_]u8{0} ** XHCI_CAPABILITY_MMAP_BYTES;
    mmap[2] = 0x10;
    mmap[10] = 0x20;
    mmap[16] = 1;
    const memory_map = try kernel_handoff.summarizeMemoryMap(
        kernel_handoff.multiboot2MemoryMap(mmap[0..], @intCast(XHCI_CAPABILITY_MMAP_BYTES)),
    );
    try std.testing.expect(memory_map.hasUsableMemory());
    const nuc_smbios_table = [_]u8{
        1,   8,   1,   0,   1,   2,   0,   0,
        'I', 'n', 't', 'e', 'l', 0,   'N', 'U',
        'C', '1', '1', 'T', 'N', 'K', 'i', '5',
        0,   0,
    };
    try std.testing.expect(kernel_smbios.tableContainsTargetSku(nuc_smbios_table[0..], 1, kernel_smbios.NUC11TNKI5_SKU));
    try std.testing.expectEqual(@as(u32, 64), (kernel_nvme.ControllerCapabilities{ .raw = (@as(u64, 63) | (@as(u64, 1) << 37)) }).maxQueueEntries());
    try intel_i225.validateRingPlan(.{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    });
    try kernel_xhci.validateRingPlan(.{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });
    var hardware_xhci = try kernel_xhci.HidController.initWithMmio(kernel_xhci.defaultCapabilityRegisters(), .{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });
    const hardware_keyboard_descriptor = kernel_xhci.bootKeyboardConfigurationDescriptor(kernel_xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const hardware_keyboard = try hardware_xhci.attachBootKeyboard(kernel_xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, hardware_keyboard_descriptor[0..]);
    const hardware_keyboard_report = try kernel_xhci.bootKeyboardReport(hardware_keyboard.device_id, hardware_keyboard.endpoint_id, 0, &.{0x04});
    try hardware_xhci.submitKeyboardInterruptEvent(hardware_keyboard.slot_id, hardware_keyboard.endpoint_id, hardware_keyboard_report.reportSlice());
    const modeled_xhci_input_proof = hardware_xhci.inputProof().?;
    const hardware_xhci_input_proof = kernel_xhci.withHardwareInputEvidence(modeled_xhci_input_proof, .{
        .source = .hardware_event_ring,
        .controller_event_trbs = 1,
        .event_ring_dma_writes = 1,
        .device_context_reads_by_controller = 1,
        .endpoint_context_reads_by_controller = 1,
        .interrupt_assertions = 1,
        .port_status_change_events = 1,
        .input_report_dma_bytes = kernel_xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
    });
    try std.testing.expect(hardware_xhci_input_proof.verified());
    try std.testing.expect(!modeled_xhci_input_proof.productionHardwareVerified());
    try std.testing.expect(hardware_xhci_input_proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u32, 2), hardware_xhci_input_proof.mmio.device_context_writes);
    try std.testing.expectEqual(@as(u32, 1), hardware_xhci_input_proof.mmio.endpoint_context_writes);
    try std.testing.expectEqual(@as(u32, 1), hardware_xhci_input_proof.mmio.event_ring_segment_table_writes);
    try std.testing.expectEqual(@as(u32, 1), hardware_xhci_input_proof.mmio.event_ring_segment_table_entries);
    var hardware_xhci_missing_context = hardware_xhci_input_proof;
    hardware_xhci_missing_context.mmio.endpoint_context_writes = 0;
    try std.testing.expect(!hardware_xhci_missing_context.verified());
    var hardware_nvme_image = [_]u8{0} ** (kernel_nvme.SECTOR_BYTES * 4);
    var hardware_nvme_namespaces = [_]kernel_nvme.Namespace{.{
        .id = 1,
        .sector_count = 4,
        .image = hardware_nvme_image[0..],
    }};
    var hardware_nvme = try kernel_nvme.Controller.initWithMmio(
        kernel_nvme.ControllerCapabilities{ .raw = (@as(u64, 63) | (@as(u64, 1) << 37)) },
        hardware_nvme_namespaces[0..],
        16,
        kernel_nvme.defaultAdminQueuePlan(),
        kernel_nvme.defaultProofPrp1Address(),
        kernel_nvme.SECTOR_BYTES,
    );
    const modeled_nvme_proof = try hardware_nvme.proveWriteReadCycles(1, 0, 2);
    const hardware_nvme_proof = kernel_nvme.withHardwareCompletionEvidence(modeled_nvme_proof, .{
        .source = .hardware_dma,
        .controller_completion_writes = 4,
        .dma_read_bytes = 2 * kernel_nvme.SECTOR_BYTES,
        .dma_write_bytes = 2 * kernel_nvme.SECTOR_BYTES,
        .interrupt_count = 1,
        .phase_tag_observations = 4,
    });
    try std.testing.expect(hardware_nvme_proof.verified());
    try std.testing.expect(!modeled_nvme_proof.productionHardwareVerified());
    try std.testing.expect(hardware_nvme_proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u32, 4), hardware_nvme_proof.mmio.submission_doorbell_writes);
    try std.testing.expectEqual(@as(u32, 4), hardware_nvme_proof.mmio.completion_head_updates);
    try std.testing.expectEqual(@as(u32, 4), hardware_nvme_proof.mmio.completed_commands);
    try std.testing.expectEqual(@as(u64, kernel_nvme.defaultProofPrp1Address()), hardware_nvme_proof.mmio.prp1_address);
    var hardware_nvme_missing_completion = hardware_nvme_proof;
    hardware_nvme_missing_completion.mmio.completed_commands = 0;
    try std.testing.expect(!hardware_nvme_missing_completion.verified());
    var hardware_i225 = try intel_i225.SoftwareAdapter.initWithMmio(.{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 5 }, intel_i225.defaultPhyLinkState(), intel_i225.defaultPacketBufferPlan());
    const modeled_i225_proof = try hardware_i225.proveFrameCycles(2);
    const hardware_i225_proof = intel_i225.withHardwarePacketEvidence(modeled_i225_proof, .{
        .source = .hardware_descriptor_ring,
        .tx_descriptors_owned_by_device = 2,
        .rx_descriptors_owned_by_device = 2,
        .tx_dma_bytes = 2 * intel_i225.MIN_ETHERNET_FRAME_BYTES,
        .rx_dma_bytes = 2 * intel_i225.MIN_ETHERNET_FRAME_BYTES,
        .asserted_interrupts = 2,
        .phy_packet_observations = 2,
    });
    try std.testing.expect(hardware_i225_proof.verified());
    try std.testing.expect(!modeled_i225_proof.productionHardwareVerified());
    try std.testing.expect(hardware_i225_proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u32, 2), hardware_i225_proof.mmio.tx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, 2), hardware_i225_proof.mmio.rx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, 4), hardware_i225_proof.mmio.interrupt_cause_reads);
    try std.testing.expectEqual(@as(u32, 1), hardware_i225_proof.mmio.phy_status_reads);
    try std.testing.expectEqual(@as(u32, 2500), hardware_i225_proof.mmio.link_speed_mbps);
    var hardware_i225_missing_interrupt = hardware_i225_proof;
    hardware_i225_missing_interrupt.mmio.interrupt_cause_reads = 0;
    try std.testing.expect(!hardware_i225_missing_interrupt.verified());
    const framebuffer_info = try kernel_framebuffer.validate(.{
        .physical_address = 0x8000_0000,
        .width = 64,
        .height = 16,
        .pixels_per_scan_line = 64,
        .format = .bgrx8888,
        .buffer_bytes = 64 * 16 * 4,
    });
    const framebuffer_expected_pixel: u32 = 0x00FF_00FF;
    var framebuffer_scanline = [_]u8{0} ** (64 * 4);
    std.mem.writeInt(u32, framebuffer_scanline[0..4], framebuffer_expected_pixel, .little);
    const modeled_framebuffer_scanout_proof = try kernel_framebuffer.proveScanout(
        framebuffer_info,
        framebuffer_scanline[0..],
        framebuffer_expected_pixel,
    );
    const hardware_framebuffer_scanout_proof = kernel_framebuffer.withHardwareScanoutEvidence(modeled_framebuffer_scanout_proof, .{
        .source = .hardware_gop_scanout,
        .gop_mode_info_reads = 1,
        .framebuffer_base_observations = 1,
        .framebuffer_stride_observations = 1,
        .framebuffer_memory_read_bytes = framebuffer_scanline.len,
        .display_scanout_observations = 1,
        .expected_pixel_observations = 1,
        .captured_scanline_bytes = framebuffer_scanline.len,
        .sink_signal_observations = 1,
    });
    try std.testing.expect(modeled_framebuffer_scanout_proof.verified());
    try std.testing.expect(!modeled_framebuffer_scanout_proof.productionHardwareVerified());
    try std.testing.expect(hardware_framebuffer_scanout_proof.productionHardwareVerified());
    var framebuffer_missing_pixel = hardware_framebuffer_scanout_proof;
    framebuffer_missing_pixel.expected_pixel_count = 0;
    try std.testing.expect(!framebuffer_missing_pixel.verified());
    const apic_summary = kernel_apic.Summary{
        .local_apic_address = 0xFEE0_0000,
        .pc_at_compatible = true,
        .processor_count = 1,
        .enabled_processor_count = 1,
        .io_apic_count = 1,
        .interrupt_source_override_count = 1,
    };
    const modeled_apic_timer_proof = try kernel_apic.proveTimerInterrupt(apic_summary, .{
        .local_apic_address = apic_summary.local_apic_address,
        .vector = 0x40,
        .initial_count = 10_000,
        .current_count_before = 8_000,
        .current_count_after = 6_000,
        .divide_value = 16,
        .mode = .periodic,
        .delivered_interrupts = 2,
        .eoi_count_before = 9,
        .eoi_count_after = 11,
    });
    const hardware_apic_timer_proof = kernel_apic.withHardwareTimerEvidence(modeled_apic_timer_proof, .{
        .source = .hardware_lapic_timer,
        .initial_count_register_writes = 1,
        .divide_register_writes = 1,
        .lvt_timer_register_writes = 1,
        .current_count_register_reads = 2,
        .isr_vector_observations = 2,
        .interrupt_handler_entries = 2,
        .eoi_register_writes = 2,
        .tsc_delta_ticks = 100,
    });
    try std.testing.expect(modeled_apic_timer_proof.verified());
    try std.testing.expect(!modeled_apic_timer_proof.productionHardwareVerified());
    try std.testing.expect(hardware_apic_timer_proof.productionHardwareVerified());
    var apic_missing_eoi = hardware_apic_timer_proof;
    apic_missing_eoi.eoi_count = 0;
    try std.testing.expect(!apic_missing_eoi.verified());
    const suspend_firmware = kernel_fadt.FixedAcpiDescription{
        .revision = 6,
        .dsdt_address = 0x00AB_C000,
        .sci_interrupt = 9,
        .pm1a_event_block = 0x1800,
        .pm1b_event_block = 0,
        .pm1a_control_block = 0x1804,
        .pm1b_control_block = 0,
        .pm_timer_block = 0x1808,
        .pm1_event_length = 4,
        .pm1_control_length = 2,
        .pm_timer_length = 4,
        .reset_register = null,
        .reset_value = 0,
    };
    const suspend_cycles = target.proof_minimums.suspend_resume_cycles;
    const modeled_suspend_resume_proof = try kernel_fadt.proveSuspendResume(
        suspend_firmware,
        suspend_cycles,
        100,
        100 + @as(u32, suspend_cycles) * 10,
        suspend_cycles,
        .{
            .timer = true,
            .framebuffer = true,
            .xhci_input = true,
            .nvme_block = true,
            .i225_network = true,
        },
    );
    const hardware_suspend_resume_proof = kernel_fadt.withHardwareSuspendResumeEvidence(modeled_suspend_resume_proof, .{
        .source = .hardware_power_transition,
        .pm1_control_sleep_writes = @as(u32, suspend_cycles),
        .s_state_entry_observations = @as(u32, suspend_cycles),
        .s0_resume_observations = @as(u32, suspend_cycles),
        .pm_timer_resume_reads = @as(u32, suspend_cycles) * 2,
        .sci_wake_interrupts = @as(u32, suspend_cycles),
        .resumed_timer_probes = @as(u32, suspend_cycles),
        .resumed_framebuffer_probes = @as(u32, suspend_cycles),
        .resumed_xhci_probes = @as(u32, suspend_cycles),
        .resumed_nvme_probes = @as(u32, suspend_cycles),
        .resumed_i225_probes = @as(u32, suspend_cycles),
    });
    try std.testing.expect(modeled_suspend_resume_proof.verified());
    try std.testing.expect(!modeled_suspend_resume_proof.productionHardwareVerified());
    try std.testing.expect(hardware_suspend_resume_proof.productionHardwareVerified());
    var suspend_missing_sci = hardware_suspend_resume_proof;
    suspend_missing_sci.hardware_resume.sci_wake_interrupts = 0;
    try std.testing.expect(!suspend_missing_sci.productionHardwareVerified());
    const crash_cycles = target.proof_minimums.crash_record_persistence_cycles;
    const crash = try kernel_crash_record.init(.watchdog, 77, 88, 0x1234, 0x5678, "target proof crash");
    var crash_report_buffer: [kernel_crash_record.REDACTED_REPORT_BUFFER_BYTES]u8 = undefined;
    const modeled_crash_persistence_proof = try kernel_crash_record.provePersistence(
        crash,
        crash,
        crash.boot_id + 1,
        crash_cycles,
        crash_report_buffer[0..],
    );
    const crash_record_bytes = @as(u64, crash_cycles) * @as(u64, @sizeOf(kernel_crash_record.Record));
    const hardware_crash_persistence_proof = kernel_crash_record.withHardwarePersistenceEvidence(modeled_crash_persistence_proof, .{
        .source = .hardware_reboot_persistence,
        .crash_handler_entries = @as(u32, crash_cycles),
        .persistent_record_writes = @as(u32, crash_cycles),
        .persistent_record_flushes = @as(u32, crash_cycles),
        .reboot_observations = @as(u32, crash_cycles),
        .recovery_boot_reads = @as(u32, crash_cycles),
        .recovered_record_validations = @as(u32, crash_cycles),
        .redacted_report_emissions = @as(u32, crash_cycles),
        .persistent_bytes_written = crash_record_bytes,
        .persistent_bytes_read = crash_record_bytes,
    });
    try std.testing.expect(modeled_crash_persistence_proof.verified());
    try std.testing.expect(!modeled_crash_persistence_proof.productionHardwareVerified());
    try std.testing.expect(hardware_crash_persistence_proof.productionHardwareVerified());
    var crash_missing_flush = hardware_crash_persistence_proof;
    crash_missing_flush.hardware_persistence.persistent_record_flushes = 0;
    try std.testing.expect(!crash_missing_flush.productionHardwareVerified());
    const update_cycles = target.proof_minimums.update_rollback_cycles;
    const modeled_update_rollback_proof = hardware_target.UpdateRollbackProof{
        .cycles = update_cycles,
        .stable_slot = 0,
        .candidate_slot = 1,
        .recovered_slot = 0,
        .activation_generation_before = 10,
        .activation_generation_after = 11,
        .rollback_generation_before = 3,
        .rollback_generation_after = 4,
        .failure_detected = true,
        .rollback_decision = true,
        .service_use_started = false,
        .selector_record_persisted = true,
        .post_power_cycle_verified = true,
        .active_slot_verified = true,
        .persisted_state_preserved = true,
    };
    const hardware_update_rollback_proof = hardware_target.withHardwareUpdateRollbackEvidence(modeled_update_rollback_proof, .{
        .source = .hardware_power_cycle,
        .candidate_activation_writes = @as(u32, update_cycles),
        .selector_record_flushes = @as(u32, update_cycles),
        .power_cycle_observations = @as(u32, update_cycles),
        .failure_detector_observations = @as(u32, update_cycles),
        .rollback_decision_records = @as(u32, update_cycles),
        .stable_slot_boot_observations = @as(u32, update_cycles),
        .recovered_slot_reads = @as(u32, update_cycles),
        .persisted_state_verifications = @as(u32, update_cycles),
        .service_start_suppression_observations = @as(u32, update_cycles),
    });
    try std.testing.expect(modeled_update_rollback_proof.verified());
    try std.testing.expect(!modeled_update_rollback_proof.productionHardwareVerified());
    try std.testing.expect(hardware_update_rollback_proof.productionHardwareVerified());
    var update_missing_power_cycle = hardware_update_rollback_proof;
    update_missing_power_cycle.hardware_rollback.power_cycle_observations = 0;
    try std.testing.expect(!update_missing_power_cycle.productionHardwareVerified());

    const qemu_only = hardware_target.EvidenceSummary{
        .target_id = target.id,
        .source = .qemu,
        .qemu_boots = 100,
        .serial_log_captured = true,
        .required_markers_captured = true,
        .firmware_settings_captured = true,
        .power_cycle_notes_captured = true,
        .artifact_digests_captured = true,
    };
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, qemu_only));

    const markerless_real_hardware = hardware_target.EvidenceSummary{
        .target_id = target.id,
        .source = .real_hardware,
        .hardware_cold_boots = target.proof_minimums.cold_boots,
        .hardware_warm_reboots = target.proof_minimums.warm_reboots,
        .storage_write_read_cycles = target.proof_minimums.storage_write_read_cycles,
        .network_frame_cycles = target.proof_minimums.network_frame_cycles,
        .suspend_resume_cycles = target.proof_minimums.suspend_resume_cycles,
        .crash_recovery_cycles = target.proof_minimums.crash_recovery_cycles,
        .crash_record_persistence_cycles = target.proof_minimums.crash_record_persistence_cycles,
        .update_rollback_cycles = target.proof_minimums.update_rollback_cycles,
        .proof_manifest_captured = true,
        .serial_log_captured = true,
        .firmware_settings_captured = true,
        .power_cycle_notes_captured = true,
        .artifact_digests_captured = true,
    };
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, markerless_real_hardware));

    const complete_hardware_evidence = hardware_target.EvidenceSummary{
        .target_id = target.id,
        .source = .real_hardware,
        .hardware_cold_boots = target.proof_minimums.cold_boots,
        .hardware_warm_reboots = target.proof_minimums.warm_reboots,
        .storage_write_read_cycles = target.proof_minimums.storage_write_read_cycles,
        .network_frame_cycles = target.proof_minimums.network_frame_cycles,
        .suspend_resume_cycles = target.proof_minimums.suspend_resume_cycles,
        .crash_recovery_cycles = target.proof_minimums.crash_recovery_cycles,
        .crash_record_persistence_cycles = target.proof_minimums.crash_record_persistence_cycles,
        .update_rollback_cycles = target.proof_minimums.update_rollback_cycles,
        .proof_manifest_captured = true,
        .serial_log_captured = true,
        .required_markers_captured = true,
        .firmware_settings_captured = true,
        .power_cycle_notes_captured = true,
        .artifact_digests_captured = true,
    };
    try std.testing.expect(hardware_target.hardwareProofSatisfied(target, complete_hardware_evidence));

    var production_dmar = kernel_dmar.Summary{
        .host_address_width = kernel_dmar.MIN_PRODUCTION_HOST_ADDRESS_WIDTH,
        .interrupt_remapping = true,
        .x2apic_opt_out = false,
        .dma_control_platform_opt_in = true,
        .dma_remapping_opt_out = false,
    };
    production_dmar.remapping_units[0] = .{
        .register_base_address = 0xFED9_1000,
        .register_page_count = 1,
        .segment = 0,
        .include_pci_all = true,
    };
    production_dmar.remapping_unit_count = 1;

    const composed_partial = kernel_hardware_proof.ProbeFacts{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .framebuffer_gop = true,
        .acpi_xsdt = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .acpi_mcfg = true,
        .acpi_dmar = true,
        .apic_timer = true,
        .xhci_controller = true,
        .nvme_controller = true,
        .i225_lm_controller = true,
    };
    try std.testing.expect(composed_partial.uefiBootReady());
    try std.testing.expect(composed_partial.acpiTablesReady());
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_partial));
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, kernel_hardware_proof.evaluateEvidence(composed_partial)));

    const composed_complete = kernel_hardware_proof.ProbeFacts{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .framebuffer_gop = hardware_framebuffer_scanout_proof.productionHardwareVerified(),
        .acpi_xsdt = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .acpi_mcfg = true,
        .acpi_dmar = true,
        .dmar_summary = production_dmar,
        .apic_timer = hardware_apic_timer_proof.productionHardwareVerified(),
        .xhci_controller = true,
        .xhci_keyboard_input = hardware_xhci_input_proof.productionHardwareVerified(),
        .nvme_controller = true,
        .nvme_write_read_io = hardware_nvme_proof.productionHardwareVerified(),
        .i225_lm_controller = true,
        .i225_frame_io = hardware_i225_proof.productionHardwareVerified(),
        .cold_boots = target.proof_minimums.cold_boots,
        .warm_reboots = target.proof_minimums.warm_reboots,
        .storage_write_read_cycles = target.proof_minimums.storage_write_read_cycles,
        .network_frame_cycles = target.proof_minimums.network_frame_cycles,
        .suspend_resume_power = hardware_suspend_resume_proof.productionHardwareVerified(),
        .suspend_resume_cycles = hardware_suspend_resume_proof.cycles,
        .crash_recovery_record = hardware_crash_persistence_proof.productionHardwareVerified(),
        .crash_recovery_cycles = hardware_crash_persistence_proof.cycles,
        .crash_record_persisted = hardware_crash_persistence_proof.productionHardwareVerified(),
        .crash_record_persistence_cycles = hardware_crash_persistence_proof.cycles,
        .update_rollback_power_cycle = hardware_update_rollback_proof.productionHardwareVerified(),
        .update_rollback_cycles = hardware_update_rollback_proof.cycles,
    };
    try std.testing.expect(kernel_hardware_proof.allSubsystemMarkersReady(composed_complete));
    var composed_missing_framebuffer_scanout = composed_complete;
    composed_missing_framebuffer_scanout.framebuffer_gop = framebuffer_missing_pixel.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_framebuffer_scanout));
    var composed_missing_framebuffer_hardware_scanout = composed_complete;
    composed_missing_framebuffer_hardware_scanout.framebuffer_gop = modeled_framebuffer_scanout_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_framebuffer_hardware_scanout));
    var composed_missing_apic_interrupt = composed_complete;
    composed_missing_apic_interrupt.apic_timer = apic_missing_eoi.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_apic_interrupt));
    var composed_missing_apic_lapic_evidence = composed_complete;
    composed_missing_apic_lapic_evidence.apic_timer = modeled_apic_timer_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_apic_lapic_evidence));
    var composed_missing_xhci_context = composed_complete;
    composed_missing_xhci_context.xhci_keyboard_input = hardware_xhci_missing_context.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_xhci_context));
    var composed_missing_xhci_event_ring = composed_complete;
    composed_missing_xhci_event_ring.xhci_keyboard_input = modeled_xhci_input_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_xhci_event_ring));
    var composed_missing_nvme_mmio = composed_complete;
    composed_missing_nvme_mmio.nvme_write_read_io = hardware_nvme_missing_completion.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_nvme_mmio));
    var composed_missing_nvme_dma = composed_complete;
    composed_missing_nvme_dma.nvme_write_read_io = modeled_nvme_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_nvme_dma));
    var composed_missing_i225_mmio = composed_complete;
    composed_missing_i225_mmio.i225_frame_io = hardware_i225_missing_interrupt.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_i225_mmio));
    var composed_missing_i225_descriptor_ownership = composed_complete;
    composed_missing_i225_descriptor_ownership.i225_frame_io = modeled_i225_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_i225_descriptor_ownership));
    var composed_missing_suspend_wake = composed_complete;
    composed_missing_suspend_wake.suspend_resume_power = suspend_missing_sci.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_suspend_wake));
    var composed_missing_suspend_hardware = composed_complete;
    composed_missing_suspend_hardware.suspend_resume_power = modeled_suspend_resume_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_suspend_hardware));
    var composed_missing_crash_flush = composed_complete;
    composed_missing_crash_flush.crash_recovery_record = crash_missing_flush.productionHardwareVerified();
    composed_missing_crash_flush.crash_record_persisted = crash_missing_flush.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_crash_flush));
    var composed_missing_crash_hardware = composed_complete;
    composed_missing_crash_hardware.crash_recovery_record = modeled_crash_persistence_proof.productionHardwareVerified();
    composed_missing_crash_hardware.crash_record_persisted = modeled_crash_persistence_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_crash_hardware));
    var composed_missing_update_power_cycle = composed_complete;
    composed_missing_update_power_cycle.update_rollback_power_cycle = update_missing_power_cycle.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_update_power_cycle));
    var composed_missing_update_hardware = composed_complete;
    composed_missing_update_hardware.update_rollback_power_cycle = modeled_update_rollback_proof.productionHardwareVerified();
    try std.testing.expect(!kernel_hardware_proof.allSubsystemMarkersReady(composed_missing_update_hardware));
    const runtime_evidence = kernel_hardware_proof.evaluateEvidence(composed_complete);
    try std.testing.expect(runtime_evidence.required_markers_captured);
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, runtime_evidence));

    var archived_evidence = runtime_evidence;
    archived_evidence.proof_manifest_captured = true;
    archived_evidence.serial_log_captured = true;
    archived_evidence.firmware_settings_captured = true;
    archived_evidence.power_cycle_notes_captured = true;
    archived_evidence.artifact_digests_captured = true;
    try std.testing.expect(hardware_target.hardwareProofSatisfied(target, archived_evidence));
}

pub fn driverBoundaryAuditGate() !void {
    var capabilities = capability.CapabilityTable.init();
    var directory = driver_service.Directory.init();
    const holder = spec_support.service(811);
    const authority = try spec_support.driverAuthority(&capabilities, holder, 812, 0x8086_15F2_0007, .network_adapter);

    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.backlog",
        .display_name = "Backlog Driver",
        .publisher = "zigos.spec",
        .signature = .{ .format = manifest.SIGNATURE_FORMAT_ED25519, .signer = "zigos-spec-driver" },
    };
    const driver = try directory.register(.{
        .service_id = 811,
        .owner_task_id = 812,
        .device_id = 0x8086_15F2_0007,
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
        .device_id = 0x8086_15F2_0007,
        .device_class = .network_adapter,
        .authority_capability_id = authority.id,
        .capability_table = &capabilities,
        .requester = holder,
        .now_ticks = 1,
        .bundle = bundle,
        .bootstrap_transport = .kernel_bootstrap_broker,
    }));

    try networkDriverBrokerRevocationGate();
}

fn networkDriverBrokerRevocationGate() !void {
    const Harness = struct {
        var send_count: usize = 0;

        fn send(_: []const u8) void {
            send_count += 1;
        }

        fn mac() [6]u8 {
            return [_]u8{ 0x02, 0x81, 0x10, 0x0E, 0x00, 0x07 };
        }
    };

    Harness.send_count = 0;
    network_driver_task.reset();
    defer network_driver_task.reset();

    const service_owner = spec_support.service(880);
    const source_device = spec_support.device(881);
    const target_device = spec_support.device(882);
    const network_device = network_driver_task.NetworkDevice{
        .send = Harness.send,
        .getMacAddress = Harness.mac,
    };
    try std.testing.expect(network_driver_task.activateDevice(&network_device, 880));

    var policies = network_policy.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const policy = try policies.create(.{
        .owner = service_owner,
        .label = "driver-egress",
        .mode = .named_service_identity,
        .target = "storage-sync.driver.zigos",
    });
    const egress_capability = try capabilities.mintBootRoot(.{
        .holder = service_owner,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .network_policy, .id = policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 880, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const revocation_trigger = try capabilities.mintBootRoot(.{
        .holder = service_owner,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .network_policy, .id = policy.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 880, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100 },
        .audit = .{},
    });

    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    var stack = network_driver_task.NativeNetworkStack.init();
    const connection = try stack.openServiceIdentity(&broker, .{
        .task_id = 880,
        .principal_id = service_owner,
        .capability_id = egress_capability.id,
        .policy_id = policy.id,
        .evidence = .{ .destination = .{ .service_identity = "storage-sync.driver.zigos" } },
        .now_ticks = 10,
    }, source_device, target_device);

    const first_frame = try stack.sendServiceIdentityFrameBrokered(&broker, &connection, "brokered network payload", 11);
    try std.testing.expect(first_frame.egress_allowed);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);

    try capabilities.revokeTargetAuthority(revocation_trigger.id);
    try std.testing.expectError(
        error.EgressDenied,
        stack.sendServiceIdentityFrameBrokered(&broker, &connection, "revoked network payload", 12),
    );
    try std.testing.expectEqual(network_policy.EgressDecisionReason.capability_revoked, stack.last_denial_reason);
    try std.testing.expectEqual(@as(usize, 1), Harness.send_count);
}

pub fn kernelBootstrapShimBoundaryGate() !void {
    try std.testing.expectEqualStrings("bootstrap_network_shim", kernel_ethernet.kernel_boundary_role);
    try std.testing.expect(!kernel_ethernet.publishes_full_network_service);
    try std.testing.expect(kernel_ethernet.network_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, kernel_ethernet.rejectDataPlaneExport(.{
        .service_id = 811,
        .device_id = 0x8086_15F2_0007,
        .frame_len = 64,
    }));

    try std.testing.expectEqualStrings("bootstrap_network_link_shim", kernel_link_port.kernel_boundary_role);
    try std.testing.expect(!kernel_link_port.publishes_full_network_service);
    try std.testing.expect(kernel_link_port.network_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, kernel_link_port.rejectKernelDataPlaneTransport(.{
        .device_id = 0x8086_15F2_0007,
        .service_id = 811,
    }));

    try std.testing.expectEqualStrings("bootstrap_i225_lm_inventory_shim", intel_i225.kernel_boundary_role);
    try std.testing.expect(!intel_i225.publishes_full_network_service);
    try std.testing.expect(intel_i225.network_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelNetworkDataPlaneDisabled, intel_i225.rejectKernelTransmit(.{
        .device_id = 0x8086_15F2_0000,
        .frame_len = 64,
    }));
    var i225_adapter = try intel_i225.SoftwareAdapter.initWithMmio(.{
        .rx_descriptors = 256,
        .tx_descriptors = 256,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 7 }, intel_i225.defaultPhyLinkState(), intel_i225.defaultPacketBufferPlan());
    var tx_frame = [_]u8{0xC1} ** intel_i225.MIN_ETHERNET_FRAME_BYTES;
    @memcpy(tx_frame[6..12], &i225_adapter.mac_address);
    const tx_completion = try i225_adapter.transmit(tx_frame[0..]);
    try std.testing.expect(tx_completion.descriptor_done);
    try std.testing.expectEqual(@as(u32, 1), i225_adapter.tx_tail);
    try std.testing.expect(std.mem.eql(u8, tx_frame[0..], i225_adapter.lastTransmitSlice()));
    const i225_proof = try i225_adapter.proveFrameCycles(2);
    try std.testing.expect(i225_proof.verified());
    try std.testing.expect(!i225_proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u16, 2), i225_proof.tx_rx_cycles);
    try std.testing.expectEqual(@as(u32, 2), i225_proof.last_tx_completion.descriptor_index);
    try std.testing.expectEqual(@as(u32, 1), i225_proof.last_rx_completion.descriptor_index);
    try std.testing.expectEqual(@as(u32, 2), i225_proof.mmio.tx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, 2), i225_proof.mmio.rx_tail_register_writes);
    try std.testing.expectEqual(@as(u32, 4), i225_proof.mmio.interrupt_cause_reads);
    try std.testing.expectEqual(@as(u32, 1), i225_proof.mmio.phy_status_reads);
    var i225_missing_interrupt = i225_proof;
    i225_missing_interrupt.mmio.interrupt_cause_reads = 0;
    try std.testing.expect(!i225_missing_interrupt.verified());
    const i225_hardware_proof = intel_i225.withHardwarePacketEvidence(i225_proof, .{
        .source = .hardware_descriptor_ring,
        .tx_descriptors_owned_by_device = 2,
        .rx_descriptors_owned_by_device = 2,
        .tx_dma_bytes = 2 * intel_i225.MIN_ETHERNET_FRAME_BYTES,
        .rx_dma_bytes = 2 * intel_i225.MIN_ETHERNET_FRAME_BYTES,
        .asserted_interrupts = 2,
        .phy_packet_observations = 2,
    });
    try std.testing.expect(i225_hardware_proof.productionHardwareVerified());

    try std.testing.expectEqualStrings("bootstrap_xhci_input_inventory_shim", kernel_xhci.kernel_boundary_role);
    try std.testing.expect(!kernel_xhci.publishes_full_input_service);
    try std.testing.expect(kernel_xhci.usb_input_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelUsbInputDataPlaneDisabled, kernel_xhci.rejectKernelInputReport(.{
        .device_id = 0x8086_A0ED_0000,
        .report_len = 8,
    }));
    var hid_controller = try kernel_xhci.HidController.initWithMmio(kernel_xhci.defaultCapabilityRegisters(), .{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });
    const keyboard_descriptor = kernel_xhci.bootKeyboardConfigurationDescriptor(kernel_xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    _ = try hid_controller.attachBootKeyboard(kernel_xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, keyboard_descriptor[0..]);
    const boot_report = try kernel_xhci.bootKeyboardReport(kernel_xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, kernel_xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, 0x02, &.{0x04});
    const keyboard = hid_controller.configuredBootKeyboard().?;
    try hid_controller.submitKeyboardInterruptEvent(keyboard.slot_id, kernel_xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID, boot_report.reportSlice());
    const xhci_input_proof = hid_controller.inputProof().?;
    try std.testing.expect(xhci_input_proof.verified());
    try std.testing.expect(!xhci_input_proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(usize, 1), xhci_input_proof.event_count);
    try std.testing.expectEqual(@as(u32, 1), xhci_input_proof.mmio.transfer_doorbells);
    try std.testing.expectEqual(@as(u32, 2), xhci_input_proof.mmio.device_context_writes);
    try std.testing.expectEqual(@as(u32, 1), xhci_input_proof.mmio.endpoint_context_writes);
    try std.testing.expectEqual(@as(u32, 1), xhci_input_proof.mmio.event_ring_segment_table_writes);
    try std.testing.expectEqual(@as(u32, 1), xhci_input_proof.mmio.interrupt_events);
    var xhci_missing_context = xhci_input_proof;
    xhci_missing_context.mmio.endpoint_context_writes = 0;
    try std.testing.expect(!xhci_missing_context.verified());
    const xhci_hardware_proof = kernel_xhci.withHardwareInputEvidence(xhci_input_proof, .{
        .source = .hardware_event_ring,
        .controller_event_trbs = 1,
        .event_ring_dma_writes = 1,
        .device_context_reads_by_controller = 1,
        .endpoint_context_reads_by_controller = 1,
        .interrupt_assertions = 1,
        .port_status_change_events = 1,
        .input_report_dma_bytes = kernel_xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
    });
    try std.testing.expect(xhci_hardware_proof.productionHardwareVerified());
    const input_report = try hid_controller.pollHidReport();
    try std.testing.expectEqual(@as(u8, 0x02), input_report.modifiers());
    try std.testing.expectEqual(@as(u8, 0x04), input_report.keySlots()[0]);
    try std.testing.expectError(error.BadSignature, kernel_fadt.parseFadt(&[_]u8{0} ** kernel_fadt.MIN_FADT_PM_LENGTH));
    const suspend_firmware = kernel_fadt.FixedAcpiDescription{
        .revision = 6,
        .dsdt_address = 0x00AB_C000,
        .sci_interrupt = 9,
        .pm1a_event_block = 0x1800,
        .pm1b_event_block = 0,
        .pm1a_control_block = 0x1804,
        .pm1b_control_block = 0,
        .pm_timer_block = 0x1808,
        .pm1_event_length = 4,
        .pm1_control_length = 2,
        .pm_timer_length = 4,
        .reset_register = null,
        .reset_value = 0,
    };
    const suspend_proof = try kernel_fadt.proveSuspendResume(suspend_firmware, 2, 500, 650, 2, .{
        .timer = true,
        .framebuffer = true,
        .xhci_input = true,
        .nvme_block = true,
        .i225_network = true,
    });
    try std.testing.expect(suspend_proof.verified());
    const recovered_selection = immutable_base.BootSelection{
        .slot_index = 0,
        .object_id = 0xA11CE,
        .version_id = 0xB00B,
        .activation_generation = 12,
        .rollback_generation = 4,
        .measurement = [_]u8{0x5A} ** 32,
        .signer_len = 0,
        .signer = [_]u8{0} ** immutable_base.MAX_LABEL_BYTES,
    };
    const staged_rollback = base_boot_selector.Decision{
        .active_slot = 0,
        .candidate_slot = 1,
        .failure = .none,
        .activation_generation = 11,
        .rollback_generation = 3,
    };
    const rollback_decision = base_boot_selector.Decision{
        .active_slot = 0,
        .failure = .network,
        .rolled_back = true,
        .activation_generation = 12,
        .rollback_generation = 4,
    };
    const recovered_selector = base_boot_selector.Selector{
        .state = .stable,
        .active = recovered_selection,
        .pending = null,
        .last_good_slot = 0,
        .activation_generation = 12,
        .rollback_generation = 4,
    };
    const rollback_proof = base_boot_selector.powerCycleRollbackProof(staged_rollback, rollback_decision, &recovered_selector, 2, true);
    try std.testing.expect(rollback_proof.verified());
    const crash = try kernel_crash_record.init(.panic, 1, 2, 3, 4, "target proof crash");
    try kernel_crash_record.validate(crash);

    try std.testing.expectEqualStrings("bootstrap_nvme_inventory_shim", kernel_nvme.kernel_boundary_role);
    try std.testing.expect(!kernel_nvme.publishes_full_storage_service);
    try std.testing.expect(kernel_nvme.nvme_data_plane_exports_fail_closed);
    try std.testing.expectError(error.KernelStorageDataPlaneDisabled, kernel_nvme.rejectKernelDataPlaneTransfer(.{
        .device_id = 0x8086_15F2_0000,
        .namespace_id = 1,
        .lba = 7,
        .sector_count = 1,
    }));
    const nvme_capabilities = kernel_nvme.ControllerCapabilities{ .raw = (@as(u64, 63) | (@as(u64, 1) << 37)) };
    var nvme_image = [_]u8{0} ** (kernel_nvme.SECTOR_BYTES * 4);
    var namespaces = [_]kernel_nvme.Namespace{.{
        .id = 1,
        .sector_count = 4,
        .image = nvme_image[0..],
    }};
    var nvme_controller = try kernel_nvme.Controller.initWithMmio(
        nvme_capabilities,
        namespaces[0..],
        32,
        kernel_nvme.defaultAdminQueuePlan(),
        kernel_nvme.defaultProofPrp1Address(),
        kernel_nvme.SECTOR_BYTES,
    );
    var nvme_write = [_]u8{0x91} ** kernel_nvme.SECTOR_BYTES;
    @memcpy(nvme_write[0..4], "NVMe");
    _ = try nvme_controller.write(1, 2, nvme_write[0..]);
    var nvme_read = [_]u8{0} ** kernel_nvme.SECTOR_BYTES;
    const nvme_completion = try nvme_controller.read(1, 2, nvme_read[0..]);
    try std.testing.expectEqual(@as(u16, 2), nvme_completion.command_id);
    try std.testing.expect(std.mem.eql(u8, nvme_write[0..], nvme_read[0..]));
    const nvme_proof = try nvme_controller.proveWriteReadCycles(1, 0, 2);
    try std.testing.expect(nvme_proof.verified());
    try std.testing.expect(!nvme_proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u16, 2), nvme_proof.write_read_cycles);
    try std.testing.expectEqual(@as(u16, 6), nvme_proof.last_read_completion.command_id);
    try std.testing.expectEqual(@as(u32, 4), nvme_proof.mmio.submission_doorbell_writes);
    try std.testing.expectEqual(@as(u32, 4), nvme_proof.mmio.completion_head_updates);
    try std.testing.expectEqual(@as(u64, kernel_nvme.defaultProofPrp1Address()), nvme_proof.mmio.prp1_address);
    var nvme_missing_completion = nvme_proof;
    nvme_missing_completion.mmio.completed_commands = 0;
    try std.testing.expect(!nvme_missing_completion.verified());
    const nvme_hardware_proof = kernel_nvme.withHardwareCompletionEvidence(nvme_proof, .{
        .source = .hardware_dma,
        .controller_completion_writes = 4,
        .dma_read_bytes = 2 * kernel_nvme.SECTOR_BYTES,
        .dma_write_bytes = 2 * kernel_nvme.SECTOR_BYTES,
        .interrupt_count = 1,
        .phase_tag_observations = 4,
    });
    try std.testing.expect(nvme_hardware_proof.productionHardwareVerified());

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
    const generated_image_fixtures = @import("../../native/task/generated_image_fixtures.zig");

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

        pub fn deactivateDriver(self: *@This(), service_id: u64, device_class: driver_service.DeviceClass) bool {
            const deactivated = self.activations.deactivateDriver(service_id, device_class);
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

    const control_image = try generated_image_fixtures.serviceClientImage();
    const control_task = try kernel.taskCreate(kernelContext(bootstrap_task.id, .task_create, bootstrap_authority.id, .{ .task = 0 }), .{
        .owner = spec_support.service(823),
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "service-client",
            .entry = "app.service.client",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 821,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "zigos.system.service-client",
        },
        .userspace_image = &control_image,
    }, 3);

    const storage_driver_image = try generated_image_fixtures.storageDriverImage();
    const driver_task = try kernel.taskCreate(kernelContext(bootstrap_task.id, .task_create, bootstrap_authority.id, .{ .task = 0 }), .{
        .owner = storage_service.owner,
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "storage-driver",
            .entry = "zigos.driver.storage",
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

    const untrusted_image = try generated_image_fixtures.appImage();
    const untrusted_task = try kernel.taskCreate(kernelContext(bootstrap_task.id, .task_create, bootstrap_authority.id, .{ .task = 0 }), .{
        .owner = spec_support.app(824),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "viewer",
            .entry = "app.viewer",
        },
        .launch = .{
            .boundary = .userspace_process,
            .image_id = 823,
            .component_abi_version = 1,
            .signed = true,
            .bundle_id = "app.viewer",
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
        .signature = .{ .format = manifest.SIGNATURE_FORMAT_ED25519, .signer = "zigos-spec-driver" },
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
        DRIVER_RING_BYTES,
        10,
    );
    const completion_ring = try kernel.sharedMemoryCreate(
        kernelContext(bootstrap_task.id, .shared_memory_create, bootstrap_authority.id, .{ .task = control_task.task_id }),
        control_task.task_id,
        DRIVER_RING_BYTES,
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
        .signature = .{ .format = manifest.SIGNATURE_FORMAT_ED25519, .signer = "zigos-spec-app" },
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

    var render_buffer: [COMPOSITOR_RENDER_BUFFER_BYTES]u8 = undefined;
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

fn expectAllMetadataTrue(metadata: anytype) !void {
    inline for (std.meta.fields(@TypeOf(metadata))) |field| {
        const value = @field(metadata, field.name);
        switch (@typeInfo(@TypeOf(value))) {
            .bool => try std.testing.expect(value),
            .@"struct" => try expectAllMetadataTrue(value),
            else => @compileError("architecture gate metadata must contain only booleans or nested structs"),
        }
    }
}

fn containsString(values: []const []const u8, needle: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, needle)) return true;
    }
    return false;
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
