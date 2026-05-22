const std = @import("std");
const capability = @import("../../kernel_api/capability.zig");
const native_util = @import("../../core/util.zig");
const state_support = @import("../sync_state_support.zig");
const sync_transport = @import("../sync_transport_harness.zig");
const overlay_model = @import("overlay.zig");

pub const Error = state_support.Error;
pub const OverlayRelayFrameRequest = overlay_model.OverlayRelayFrameRequest;
pub const OverlayRelayFrameResult = overlay_model.OverlayRelayFrameResult;
pub const OverlaySession = overlay_model.OverlaySession;

pub fn sendOverlayRelayFrame(
    service: anytype,
    network_capabilities: *const capability.CapabilityTable,
    relay: *sync_transport.Relay,
    request: OverlayRelayFrameRequest,
) (Error || sync_transport.Error)!OverlayRelayFrameResult {
    const policy = service.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
    const relay_policy_id = policy.relay_policy_id orelse return error.TransportDenied;

    var broker = service.egressBroker(network_capabilities);
    var transport = sync_transport.Harness.init();
    const transport_session = try transport.openRelay(&broker, .{
        .task_id = service.task_id,
        .principal_id = service.owner,
        .capability_id = request.relay_capability_id,
        .policy_id = relay_policy_id,
        .evidence = .{ .destination = .{ .domain = policy.relayDomainSlice() } },
        .now_ticks = request.tick,
    }, request.from_device, request.to_device, policy.relayDomainSlice());
    const overlay_session = try service.openOverlaySession(
        request.workspace_id,
        request.from_device,
        request.to_device,
        request.usage,
        .relay_assisted,
        request.private_service_label,
        request.tick,
    );

    const signed_frame = try transport.encryptSignedFrame(&transport_session, request.payload, request.signer);
    try relay.submit(signed_frame.packet);
    var delivered_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay.deliverNext(&transport_session, delivered_buffer[0..])) orelse return error.RelayDeliveryMissing;
    if (!std.mem.eql(u8, delivered, request.payload)) return error.PacketAuthenticationFailed;

    return overlayRelayFrameResult(overlay_session, transport_session, signed_frame, delivered.len);
}

pub fn sendOverlayRelayFrameViaService(
    service: anytype,
    network_capabilities: *const capability.CapabilityTable,
    relay_service: *sync_transport.BootedOverlayRelayService,
    request: OverlayRelayFrameRequest,
) (Error || sync_transport.Error)!OverlayRelayFrameResult {
    const policy = service.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
    const relay_policy_id = policy.relay_policy_id orelse return error.TransportDenied;

    var broker = service.egressBroker(network_capabilities);
    var transport = sync_transport.Harness.init();
    const transport_session = try transport.openRelay(&broker, .{
        .task_id = service.task_id,
        .principal_id = service.owner,
        .capability_id = request.relay_capability_id,
        .policy_id = relay_policy_id,
        .evidence = .{ .destination = .{ .domain = policy.relayDomainSlice() } },
        .now_ticks = request.tick,
    }, request.from_device, request.to_device, policy.relayDomainSlice());
    const overlay_session = try service.openOverlaySession(
        request.workspace_id,
        request.from_device,
        request.to_device,
        request.usage,
        .relay_assisted,
        request.private_service_label,
        request.tick,
    );

    const signed_frame = try transport.encryptSignedFrame(&transport_session, request.payload, request.signer);
    try relay_service.submitSignedFrame(service.task_id, &transport_session, signed_frame);
    var delivered_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const delivered = (try relay_service.deliverNext(service.task_id, &transport_session, delivered_buffer[0..])) orelse return error.RelayDeliveryMissing;
    if (!std.mem.eql(u8, delivered, request.payload)) return error.PacketAuthenticationFailed;

    return overlayRelayFrameResult(overlay_session, transport_session, signed_frame, delivered.len);
}

fn overlayRelayFrameResult(
    overlay_session: OverlaySession,
    transport_session: sync_transport.TransportSession,
    signed_frame: sync_transport.SignedEncryptedFrame,
    delivered_len: usize,
) Error!OverlayRelayFrameResult {
    var result = OverlayRelayFrameResult{
        .overlay_session_id = overlay_session.session_id,
        .transport_session_id = transport_session.id,
        .usage = overlay_session.usage,
        .encrypted = overlay_session.encrypted and signed_frame.packet.encrypted,
        .relay_encrypted = overlay_session.relay_encrypted,
        .remote_access = overlay_session.remote_access,
        .egress_allowed = signed_frame.packet.egress_allowed,
        .delivered = true,
        .delivered_len = delivered_len,
        .packet_digest = signed_frame.packet_digest,
    };
    result.service_identity_len = native_util.copyTextExact(&result.service_identity, overlay_session.serviceIdentitySlice()) catch return error.ServiceIdentityTooLong;
    result.relay_domain_len = native_util.copyTextExact(&result.relay_domain, overlay_session.relayDomainSlice()) catch return error.NetworkTargetTooLong;
    if (overlay_session.private_service_len != 0) {
        result.private_service_len = native_util.copyTextExact(&result.private_service, overlay_session.privateServiceSlice()) catch return error.ServiceIdentityTooLong;
    }
    return result;
}
