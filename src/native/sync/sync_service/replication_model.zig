const std = @import("std");
const capability = @import("../../kernel_api/capability.zig");
const object_store = @import("../../storage/object_store.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const state_support = @import("../sync_state_support.zig");
const sync_transport = @import("../sync_transport.zig");
const storage_service = @import("../../storage/storage_service.zig");

pub const TransportMode = state_support.TransportMode;
pub const ReplicationSummary = state_support.ReplicationSummary;
pub const COMPACT_PEER_REPLICATION_RESULT_METADATA = true;
pub const PEER_REPLICATION_RESULT_SIZE_CEILING_BYTES: usize = 32;
pub const MAX_PEER_RELAY_DELIVERIES: usize = state_support.MAX_TRANSPORT_FRAMES *
    ((object_store.MAX_PAYLOAD_BYTES + sync_transport.MAX_NATIVE_PAYLOAD_BYTES - 1) / sync_transport.MAX_NATIVE_PAYLOAD_BYTES);
pub const MAX_PEER_REPLICATION_PAYLOAD_BYTES: usize = state_support.MAX_TRANSPORT_FRAMES * object_store.MAX_PAYLOAD_BYTES;

comptime {
    if (state_support.MAX_TRANSPORT_FRAMES > std.math.maxInt(u8) or
        MAX_PEER_RELAY_DELIVERIES > std.math.maxInt(u32) or
        MAX_PEER_REPLICATION_PAYLOAD_BYTES > std.math.maxInt(u32))
    {
        @compileError("peer replication result no longer fits compact counters");
    }
}

pub const PeerReplicationRequest = struct {
    source_storage: *const storage_service.Service,
    target_storage: *storage_service.Service,
    workspace_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
    transport: TransportMode,
    network_capabilities: ?*const capability.CapabilityTable = null,
    relay_service: ?*sync_transport.BootedOverlayRelayService = null,
    relay_capability_id: u64 = 0,
    payload_buffer: ?[]u8 = null,
    signer: signing.SignerIdentity,
    tick: u64,
};

pub const PeerReplicationResult = struct {
    summary: ReplicationSummary,
    accepted_frame_count: u8 = 0,
    persisted_object_count: u8 = 0,
    relay_delivery_count: u32 = 0,
    payload_bytes: u32 = 0,
    used_booted_relay_service: bool = false,

    comptime {
        if (@sizeOf(@This()) > PEER_REPLICATION_RESULT_SIZE_CEILING_BYTES) {
            @compileError("peer replication result exceeds its compact size ceiling");
        }
    }
};
