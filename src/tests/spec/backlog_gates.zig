const std = @import("std");
const capability = @import("../../native/kernel_api/capability.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const event_ledger = @import("../../native/platform/event_ledger.zig");
const manifest = @import("../../native/policy/manifest.zig");
const network_policy = @import("../../native/sync/network_policy.zig");
const principal = @import("../../native/core/principal.zig");
const runtime_negative_proofs = @import("../../native/session/runtime_negative_proofs.zig");
const spec_support = @import("support.zig");
const sync_transport = @import("../../native/sync/sync_transport_harness.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const typed_component_abi = @import("../../native/services/typed_component_abi.zig");

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

    try std.testing.expectError(error.EgressDenied, harness.openRelay(&broker, .{
        .task_id = 81,
        .principal_id = app,
        .capability_id = relay_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "unexpected.backlog.example" } },
        .now_ticks = 10,
    }, source, target, "relay.backlog.example"));
}

pub fn componentAbiDepthGate() !void {
    const iface = manifest.InterfaceDecl{ .name = "zigos.service.registry", .version_major = 1, .version_minor = 0 };
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
        .bootstrap_transport = .kernel_published_data_plane,
    }));
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

test "backlog gates enforce component ABI depth" {
    try componentAbiDepthGate();
}

test "backlog gates enforce driver boundary audit" {
    try driverBoundaryAuditGate();
}

test "backlog gates enforce UX rendering" {
    try uxRenderingGate();
}
