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
const network = @import("../drivers/network_driver_task.zig");
const support = @import("scenario_support.zig");
const markers = @import("../../kernel/boot/markers.zig");
const clock = @import("../../kernel/timer/tsc_clock.zig");
const cursor = @import("binary_cursor");
const Reader = cursor.Reader(error{MalformedOffer}, error.MalformedOffer);
const Writer = cursor.Writer(error{MalformedOffer}, error.MalformedOffer);
const path = "received.bin";
const payload_length = 1024;

pub fn run(context: *support.Context, service: *sync.Service, channel: *channel_mod.Channel, peer_mac: [6]u8, initiator: bool, confirmation: []const u8) bool {
    execute(context, service, channel, peer_mac, initiator, confirmation) catch |err| {
        support.common.printBootMarker("ZIGOS:SYNC:PEER_OBJECT:FAILED");
        support.common.printBootMarker(@errorName(err));
        return false;
    };
    support.common.printBootMarker(markers.sync_peer_object_durable);
    return true;
}

fn execute(context: *support.Context, service: *sync.Service, channel: *channel_mod.Channel, peer_mac: [6]u8, initiator: bool, confirmation: []const u8) !void {
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
    if (initiator) {
        @memset(&payload, 0);
        const bytes = try store.versionPayloadInto(store.version(created.version_id).?, &payload);
        if (bytes.len != payload_length) return error.SourceLengthMismatch;
        return sendObject(channel, peer_mac, &payload, confirmation);
    }

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
        .can_write = true,
        .network_scope = .trusted_overlay,
        .expires_at_ticks = 1_000,
    });
    var receiver = transfer.Receiver{ .store = store, .sync = service, .capabilities = context.capability_table, .binding = .{ .workspace_id = workspace_id, .object_id = created.object_id.raw(), .local_device = channel.local, .peer_device = channel.remote, .peer_capability_id = grant.capability.id }, .scratch = &payload };
    defer receiver.reset();
    var key_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const storage_key = try key_fixture.init(context.session_user, store.owner, store.task_id, support.storage_signer);
    const authority = support.mintSyncAuthority(context, 311);
    var offer: [29]u8 = undefined;
    var writer = Writer{ .buffer = &offer };
    try writer.writeByte(5);
    try writer.writeU64(workspace_id);
    try writer.writeU64(created.object_id.raw());
    try writer.writeU64(created.version_id.raw());
    try writer.writeU32(payload_length);
    var admitted = try admission.Session.init(channel, &receiver, storage_key, authority, peer_mac, 311 + admission.MAX_LIFETIME_TICKS);
    const manager = @import("../session/session_manager.zig").system();
    try manager.attachPeerReceiver(&admitted, 311);
    defer manager.detachPeerReceiver(&admitted);
    timer.synchronize();
    const start_tick = timer.getTicks();
    support.common.printBootMarker(markers.sync_peer_object_admitted);
    var started = false;
    var reopened = false;
    var grace = clock.afterMilliseconds(30_000);
    const deadline = clock.afterMilliseconds(30_000);
    var resend = clock.afterMilliseconds(1);
    while (!deadline.expired()) {
        timer.synchronize();
        const now = 311 + (timer.getTicks() - start_tick);
        if (reopened and grace.expired()) {
            if (!try context.runtime.suspendTask(service.task_id, now)) return error.PeerTaskNotSuspended;
            defer _ = context.runtime.resumeTask(service.task_id, now) catch false;
            _ = manager.servicePeerWork(now);
            if (admitted.active or channel.established() or manager.peers.hasSessions()) return error.PeerTaskNotRetired;
            support.common.printBootMarker(markers.sync_peer_object_retired);
            return;
        }
        if (!started and resend.expired()) {
            try send(channel, peer_mac, &offer);
            resend = clock.afterMilliseconds(20);
        }
        _ = manager.servicePendingNetworkWork(now);
        _ = manager.servicePeerWork(now);
        if (!admitted.active) return error.PeerAdmissionRetired;
        const progress = admitted.last_progress orelse continue;
        started = true;
        if (progress.durable() and !reopened) {
            const expected = receiver.transfer.?.request.digest;
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

fn sendObject(channel: *channel_mod.Channel, peer_mac: [6]u8, payload: []const u8, confirmation: []const u8) !void {
    var outgoing: [channel_mod.MAX_PAYLOAD]u8 = undefined;
    var outgoing_len: usize = 0;
    var incoming: [1500]u8 = undefined;
    var plaintext: [channel_mod.MAX_PAYLOAD]u8 = undefined;
    defer std.crypto.secureZero(u8, &outgoing);
    defer std.crypto.secureZero(u8, &plaintext);
    var acknowledged: u32 = 0;
    const deadline = clock.afterMilliseconds(30_000);
    var resend = clock.afterMilliseconds(1);
    while (!deadline.expired()) {
        if (resend.expired()) {
            if (outgoing_len == 0) {
                // Help the responder finish the channel confirmation if its
                // first copy was lost. This repeats cached ciphertext only.
                try channel.validate(311);
                _ = network.sendActiveFrame(peer_mac, confirmation);
            } else try send(channel, peer_mac, outgoing[0..outgoing_len]);
            resend = clock.afterMilliseconds(20);
        }
        const frame = try receive(&incoming) orelse continue;
        const message = channel.open(&plaintext, frame, 311) catch |err| {
            if (err == error.ReplayRejected) continue;
            return err;
        };
        if (message.len > 0 and message[0] == 5) {
            if (outgoing_len != 0) continue;
            var reader = Reader{ .buffer = message };
            _ = try reader.readByte();
            const workspace_id = try reader.readU64();
            const object_id = try reader.readU64();
            const version_id = try reader.readU64();
            const limit = try reader.readU32();
            if (!reader.eof() or workspace_id == 0 or object_id == 0 or version_id == 0 or payload.len > limit) return error.MalformedOffer;
            outgoing_len = (try transfer.encodeBegin(&outgoing, .{ .id = 7, .workspace_id = workspace_id, .object_id = object_id, .expected_version = version_id, .length = @intCast(payload.len), .digest = transfer.digest(payload) })).len;
        } else {
            const progress = try transfer.decodeProgress(message);
            if (outgoing_len == 0 or progress.id != 7 or progress.received > payload.len) return error.InvalidReceipt;
            if (progress.received < acknowledged) continue;
            acknowledged = progress.received;
            if (progress.durable()) {
                if (acknowledged != payload.len) return error.InvalidReceipt;
                support.common.printBootMarker(markers.sync_peer_object_acknowledged);
                return;
            }
            outgoing_len = if (acknowledged == payload.len)
                (try transfer.encodeCommit(&outgoing, 7)).len
            else
                (try transfer.encodeChunk(&outgoing, 7, acknowledged, payload[acknowledged..@min(payload.len, acknowledged + transfer.MAX_CHUNK)])).len;
        }
        try send(channel, peer_mac, outgoing[0..outgoing_len]);
        resend = clock.afterMilliseconds(20);
    }
    return error.ObjectTransferTimeout;
}

fn send(channel: *channel_mod.Channel, peer_mac: [6]u8, message: []const u8) !void {
    var wire: [channel_mod.MAX_FRAME]u8 = undefined;
    // Application retries use fresh transport nonces. The receiver deduplicates
    // transfer IDs and offsets after authenticating each packet.
    // A full transmit ring drops this attempt; the timed application retry
    // (or its peer's repeated request) will try again before the deadline.
    _ = network.sendActiveFrame(peer_mac, try channel.seal(&wire, message, 311));
}

fn receive(buffer: []u8) !?[]const u8 {
    const result = network.receiveActiveFrame(buffer);
    if (result.status == .failed) return error.NetworkReceiveFailed;
    if (result.status != .frame) {
        std.atomic.spinLoopHint();
        return null;
    }
    const frame = buffer[0..result.length];
    if (frame.len < channel_mod.HEADER or frame.len > channel_mod.MAX_FRAME or !std.mem.startsWith(u8, frame, channel_mod.MAGIC) or frame[5] != 4) return null;
    return frame;
}
