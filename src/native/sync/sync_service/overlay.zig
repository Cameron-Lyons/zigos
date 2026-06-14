const crypto_hash = @import("../../core/crypto_hash.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const state_support = @import("../sync_state_support.zig");

pub const MAX_OVERLAY_SESSIONS: usize = 8;
pub const TransportMode = state_support.TransportMode;
pub const MAX_LABEL_BYTES = state_support.MAX_LABEL_BYTES;

pub const ServiceConfig = struct {
    max_overlay_sessions: usize = MAX_OVERLAY_SESSIONS,

    pub fn validate(comptime config: ServiceConfig) void {
        if (config.max_overlay_sessions == 0) @compileError("sync service requires at least one overlay session slot");
    }
};

pub const OverlaySessionUse = enum(u8) {
    sync_replication,
    remote_access,
    private_service,
};

pub const OverlaySessionState = enum(u8) {
    establishing,
    established,
    closed,
};

pub const OverlaySession = struct {
    session_id: u64 = 0,
    overlay_id: u64,
    workspace_id: u64,
    source_device: principal.PrincipalId,
    target_device: principal.PrincipalId,
    usage: OverlaySessionUse,
    transport: TransportMode,
    state: OverlaySessionState = .establishing,
    encrypted: bool,
    relay_encrypted: bool,
    remote_access: bool,
    open_tick: u64 = 0,
    last_activity_tick: u64 = 0,
    keepalive_count: u16 = 0,
    service_identity_len: usize = 0,
    service_identity: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    relay_domain_len: usize = 0,
    relay_domain: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    private_service_len: usize = 0,
    private_service: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn serviceIdentitySlice(self: *const OverlaySession) []const u8 {
        return self.service_identity[0..self.service_identity_len];
    }

    pub fn relayDomainSlice(self: *const OverlaySession) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }

    pub fn privateServiceSlice(self: *const OverlaySession) []const u8 {
        return self.private_service[0..self.private_service_len];
    }

    pub fn isActive(self: *const OverlaySession) bool {
        return self.state == .established;
    }
};

pub const OverlayRelayFrameRequest = struct {
    workspace_id: u64,
    from_device: principal.PrincipalId,
    to_device: principal.PrincipalId,
    usage: OverlaySessionUse,
    private_service_label: ?[]const u8 = null,
    relay_capability_id: u64,
    payload: []const u8,
    signer: signing.SignerIdentity,
    tick: u64,
};

pub const OverlayRelayFrameResult = struct {
    overlay_session_id: u64,
    transport_session_id: u64,
    usage: OverlaySessionUse,
    encrypted: bool,
    relay_encrypted: bool,
    remote_access: bool,
    egress_allowed: bool,
    delivered: bool,
    delivered_len: usize,
    packet_digest: crypto_hash.Digest,
    service_identity_len: usize = 0,
    service_identity: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    relay_domain_len: usize = 0,
    relay_domain: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    private_service_len: usize = 0,
    private_service: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn serviceIdentitySlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.service_identity[0..self.service_identity_len];
    }

    pub fn relayDomainSlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.relay_domain[0..self.relay_domain_len];
    }

    pub fn privateServiceSlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.private_service[0..self.private_service_len];
    }
};

pub const OverlaySessionSlot = struct {
    in_use: bool = false,
    session: OverlaySession = .{
        .overlay_id = 0,
        .workspace_id = 0,
        .source_device = .{ .kind = .device, .serial = 0 },
        .target_device = .{ .kind = .device, .serial = 0 },
        .usage = .sync_replication,
        .transport = .device_to_device,
        .state = .closed,
        .encrypted = true,
        .relay_encrypted = false,
        .remote_access = false,
    },
};

pub const closed_session_key: u64 = 1;

pub fn sessionSlotId(slot: *const OverlaySessionSlot) u64 {
    return slot.session.session_id;
}
