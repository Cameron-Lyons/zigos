const std = @import("std");
const capability = @import("../../kernel_api/capability.zig");
const native_util = @import("../../core/util.zig");
const state_support = @import("../sync_state_support.zig");
const sync_transport = @import("../sync_transport.zig");
const overlay_model = @import("overlay.zig");

pub const Error = state_support.Error;
pub const OverlayRelayFrameRequest = overlay_model.OverlayRelayFrameRequest;
pub const OverlayRelayFrameResult = overlay_model.OverlayRelayFrameResult;
pub const OverlaySession = overlay_model.OverlaySession;

pub fn sendOverlayRelayFrameViaService(
    service: anytype,
    network_capabilities: *const capability.CapabilityTable,
    relay_service: *sync_transport.BootedOverlayRelayService,
    request: OverlayRelayFrameRequest,
) (Error || sync_transport.Error)!OverlayRelayFrameResult {
    const policy = service.findWorkspacePolicy(request.workspace_id) orelse return error.WorkspacePolicyNotFound;
    const relay_policy_id = policy.relay_policy_id orelse return error.TransportDenied;

    var broker = service.egressBroker(network_capabilities);
    var transport = sync_transport.NativeTransportService.init();
    defer transport.deinit();
    var connection = try transport.openRelay(&broker, .{
        .task_id = service.task_id,
        .principal_id = service.owner,
        .capability_id = request.relay_capability_id,
        .policy_id = relay_policy_id,
        .evidence = .{ .destination = .{ .domain = policy.relayDomainSlice() } },
        .now_ticks = request.tick,
    }, service.task_id, relay_service.task_id, request.from_device, request.to_device, policy.relayDomainSlice());
    const overlay_session = try service.openOverlaySession(
        request.workspace_id,
        request.from_device,
        request.to_device,
        request.usage,
        .relay_assisted,
        request.private_service_label,
        request.tick,
    );

    const delivery = try transport.sendWithRelayFallback(&connection, relay_service, request.payload, request.signer);
    var delivered_buffer: [sync_transport.MAX_PACKET_BYTES]u8 = undefined;
    const delivered = if (delivery.relay_fallback)
        (try relay_service.deliverNext(service.task_id, &connection.session, delivered_buffer[0..])) orelse return error.RelayDeliveryMissing
    else
        (try transport.receive(&connection)).payload();
    if (!std.mem.eql(u8, delivered, request.payload)) return error.PacketAuthenticationFailed;

    return overlayRelayFrameResult(overlay_session, connection.session, delivery.signed_frame, delivered.len);
}

fn overlayRelayFrameResult(
    overlay_session: *const OverlaySession,
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
    result.service_identity_len = @intCast(native_util.copyTextExact(&result.service_identity, overlay_session.serviceIdentitySlice()) catch return error.ServiceIdentityTooLong);
    result.relay_domain_len = @intCast(native_util.copyTextExact(&result.relay_domain, overlay_session.relayDomainSlice()) catch return error.NetworkTargetTooLong);
    if (overlay_session.private_service_len != 0) {
        result.private_service_len = @intCast(native_util.copyTextExact(&result.private_service, overlay_session.privateServiceSlice()) catch return error.ServiceIdentityTooLong);
    }
    return result;
}
