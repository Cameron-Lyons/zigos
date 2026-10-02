//! Separate-guest verification with fixture enrollment keys. Establishment,
//! confirmation retries and transfer lifetime all use the managed connection.
const sync_service = @import("../sync/sync_service.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const support = @import("scenario_support.zig");
const markers = @import("../../kernel/boot/markers.zig");

pub fn run(context: *support.Context, service: *sync_service.Service, local_mac: [6]u8, peer_mac: [6]u8, laptop: principal.PrincipalId, tablet: principal.PrincipalId) bool {
    if (@import("builtin").target.os.tag != .freestanding) return false;
    const x86 = @import("../../arch/x86.zig");
    const was_enabled = x86.interruptsEnabled();
    x86.sti();
    defer if (!was_enabled) x86.cli();
    const initiator = local_mac[5] == 1;
    const signer = if (initiator)
        signing.SignerIdentity{ .label = "local-device", .seed = signing.seedFromByte(0x92) }
    else
        signing.SignerIdentity{ .label = "tablet-device-v2", .seed = signing.seedFromByte(0x94) };
    var key_fixture = @import("../../tests/fixtures/document_signer.zig").Fixture{};
    const device_key = key_fixture.init(context.session_user, service.owner, service.task_id, signer) catch return false;
    if (!@import("peer_object_proof.zig").run(context, service, .{
        .local = if (initiator) laptop else tablet,
        .remote = if (initiator) tablet else laptop,
        .root_pin = signing.publicKey(support.user_root_signer) catch return false,
        .device_key = device_key.key,
    }, peer_mac, initiator)) return false;
    if (@import("../../kernel/drivers/virtio_net_hw.zig").interruptCount() == 0) return false;
    support.common.printBootMarker(markers.sync_peer_authenticated);
    support.common.printBootMarker(markers.sync_peer_ciphertext_rejected);
    support.common.printBootMarker(markers.sync_peer_replay_rejected);
    support.common.printBootMarker(markers.sync_native_driver_peer_frame_received);
    return true;
}
