const capability = @import("../../kernel_api/capability.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const state_support = @import("../sync_state_support.zig");
const sync_transport = @import("../sync_transport_harness.zig");
const storage_service = @import("../../storage/storage_service.zig");

pub const TransportMode = state_support.TransportMode;
pub const ReplicationSummary = state_support.ReplicationSummary;

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
    signer: signing.SignerIdentity,
    tick: u64,
};

pub const PeerReplicationResult = struct {
    summary: ReplicationSummary,
    accepted_frame_count: usize = 0,
    persisted_object_count: usize = 0,
    relay_delivery_count: usize = 0,
    payload_bytes: usize = 0,
    used_booted_relay_service: bool = false,
};
