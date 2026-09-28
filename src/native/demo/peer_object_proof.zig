//! Verification-only object write across independent guests and disks. Only
//! the source generates the payload; the target learns it from Noise packets.
const std = @import("std");
const channel_mod = @import("../sync/peer_channel.zig");
const admission = @import("../sync/peer_admission.zig");
const timer = @import("../../kernel/timer/timer.zig");
const transfer = @import("../sync/object_transfer.zig");
const sync = @import("../sync/sync_service.zig");
const storage = @import("../storage/storage_service.zig");
const objects = @import("../storage/object_store.zig");
const connections = @import("../sync/peer_connections.zig");
const support = @import("scenario_support.zig");
const markers = @import("../../kernel/boot/markers.zig");
const clock = @import("../../kernel/timer/tsc_clock.zig");
const path = "received.bin";
const payload_length = 1024;

pub fn run(context: *support.Context, service: *sync.Service, channel: *channel_mod.Channel, peer_mac: [6]u8, initiator: bool) bool {
    execute(context, service, channel, peer_mac, initiator) catch |err| {
        support.common.printBootMarker("ZIGOS:SYNC:PEER_OBJECT:FAILED");
        support.common.printBootMarker(@errorName(err));
        return false;
    };
    support.common.printBootMarker(markers.sync_peer_object_durable);
    return true;
}

fn execute(context: *support.Context, service: *sync.Service, channel: *channel_mod.Channel, peer_mac: [6]u8, initiator: bool) !void {
    const store = context.storage_service_instance;
    var payload: [payload_length]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &payload);
    if (initiator) try @import("../../kernel/platform/secure_random.zig").fill(&payload);
    const initial: []const u8 = if (initiator) &payload else "waiting for remote bytes";
    const created = try store.putVersion(.{ .object_type = .blob, .payload = initial, .metadata = try objects.signMetadata(support.storage_signer, "peer object", "application/octet-stream", .blob, initial, 310) });
    const ws = try store.createWorkspace(.{ .owner = context.session_user, .label = "peer object transfer" });
    const workspace_id = ws.id.raw();
    try store.beginTransaction(workspace_id);
    try store.stagePut(workspace_id, path, created.object_id, created.version_id, .blob);
    _ = try store.commit(workspace_id, 310);
    _ = try store.checkpointDurable();
    @memset(&payload, 0);

    const policy = try service.createNetworkPolicy(.{ .owner = service.owner, .label = "peer object local network", .mode = .local_network });
    _ = try service.configureWorkspacePolicy(.{ .workspace_id = workspace_id, .owner = context.session_user, .require_shared_access = true, .device_to_device_policy_id = policy.id, .selective_prefixes = &.{path} });
    const owner_cap = try context.capability_table.mintBootRoot(.{
        .holder = context.session_user,
        .issuer = context.policy_authority,
        .target = .{ .kind = .workspace, .id = workspace_id },
        .rights = .{ .workspace = .{ .object_read = true, .object_write = true, .capability_derive = true } },
        .scope = .{ .workspace_id = workspace_id, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 1_000 },
        .audit = .{},
    });
    var port = storage.StoragePort.init(store, context.capability_table);
    const grant = try port.grantObjectShare(context.capability_table, .{ .task_id = context.sync_task_id, .principal = context.session_user, .capability_id = owner_cap.id, .now_ticks = 310 }, workspace_id, created.object_id, .{
        .principal_id = .{ .kind = .device, .serial = channel.remote },
        .can_write = !initiator,
        .network_scope = .trusted_overlay,
        .expires_at_ticks = 1_000,
    });
    const binding = transfer.Binding{ .workspace_id = workspace_id, .object_id = created.object_id.raw(), .local_device = channel.local, .peer_device = channel.remote, .peer_capability_id = grant.capability.id };
    var key_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const request = connections.Request{
        .store = store,
        .service = service,
        .capabilities = context.capability_table,
        .authority = support.mintSyncAuthority(context, 311),
        .binding = binding,
        .root_pin = channel.root_pin,
        .device_key = channel.signer,
        .peer_mac = peer_mac,
        .expires_at = 311 + admission.MAX_LIFETIME_TICKS,
        .direction = if (initiator) .send else .{ .receive = .{ .signer = try key_fixture.init(context.session_user, store.owner, store.task_id, support.storage_signer), .limit = payload_length } },
    };
    // The preceding channel is the isolated tamper/replay proof. This transfer
    // opens its own service-owned channel and promotes it without a stack-owned
    // channel, handshake, sender, receiver or receive staging allocation.
    channel.close();
    const manager = @import("../session/session_manager.zig").system();
    const retired_handle = try manager.openPeerConnection(request);
    defer manager.releasePeerConnection(retired_handle) catch {};
    if (!try context.runtime.suspendTask(store.task_id, 311)) return error.PeerTaskNotSuspended;
    _ = manager.servicePeerWork(311);
    const retired = manager.peerConnectionStatus(retired_handle) == null and !manager.peer_handshakes.hasSessions() and !manager.peers.hasSessions();
    if (!try context.runtime.resumeTask(store.task_id, 311) or !retired) return error.PeerTaskNotRetired;
    const handle = try manager.openPeerConnection(request);
    defer manager.releasePeerConnection(handle) catch {};
    if (handle == retired_handle or manager.peerConnectionStatus(retired_handle) != null) return error.StalePeerConnection;
    support.common.printBootMarker(markers.sync_peer_connection_owner_retired);
    timer.synchronize();
    const start_tick = timer.getTicks();
    support.common.printBootMarker(if (initiator) markers.sync_peer_object_sender_admitted else markers.sync_peer_object_admitted);
    var reopened = false;
    var promoted = false;
    var grace = clock.afterMilliseconds(30_000);
    const deadline = clock.afterMilliseconds(30_000);
    while (!deadline.expired()) {
        timer.synchronize();
        const now = 311 + (timer.getTicks() - start_tick);
        const state = manager.peerConnectionStatus(handle) orelse return error.PeerAdmissionRetired;
        if ((initiator and state.phase == .complete) or (!initiator and reopened and grace.expired())) {
            if (initiator) support.common.printBootMarker(markers.sync_peer_object_acknowledged);
            if (!try context.runtime.suspendTask(service.task_id, now)) return error.PeerTaskNotSuspended;
            defer _ = context.runtime.resumeTask(service.task_id, now) catch false;
            _ = manager.servicePeerWork(now);
            if (manager.peerConnectionStatus(handle) != null or manager.peers.hasSessions() or manager.peer_handshakes.hasSessions()) return error.PeerTaskNotRetired;
            support.common.printBootMarker(if (initiator) markers.sync_peer_object_sender_retired else markers.sync_peer_object_retired);
            return;
        }
        _ = manager.servicePendingNetworkWork(now);
        _ = manager.servicePeerWork(now);
        const current = manager.peerConnectionStatus(handle) orelse return error.PeerAdmissionRetired;
        if (!promoted and current.phase != .handshaking) {
            promoted = true;
            support.common.printBootMarker(markers.sync_peer_connection_promoted);
        }
        if (initiator) continue;
        const progress = current.progress orelse continue;
        if (progress.durable() and !reopened) {
            const expected = current.digest;
            store.* = storage.Service.reloadFromAttachedVolume(context.storage_service_id, context.storage_task_id, context.storage_service_principal, context.storage_checkpoint_store);
            store.bindCapabilityTable(context.capability_table);
            store.checkpoint_enabled = false;
            if (!store.loaded_from_volume) return error.ObjectReloadFailed;
            const entry = try store.resolve(workspace_id, path);
            const version = store.version(entry.version_id) orelse return error.VersionNotFound;
            if (entry.version_id.raw() != progress.version_id or !std.mem.eql(u8, &expected, &(try transfer.versionDigest(store, version)))) return error.ObjectReloadMismatch;
            reopened = true;
            grace = clock.afterMilliseconds(500);
            support.common.printBootMarker(markers.sync_peer_object_reopened);
        }
        // The dispatcher sends this sealed receipt on its next visit. Reopen
        // first so the gate still proves durable bytes before acknowledgment.
    }
    return error.ObjectTransferTimeout;
}
