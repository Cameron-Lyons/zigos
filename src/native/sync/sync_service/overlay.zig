const std = @import("std");
const crypto_hash = @import("../../core/crypto_hash.zig");
const principal = @import("../../core/principal.zig");
const signing = @import("../../core/signing.zig");
const state_support = @import("../sync_state_support.zig");

pub const MAX_OVERLAY_SESSIONS: usize = 8;
pub const TransportMode = state_support.TransportMode;
pub const MAX_LABEL_BYTES = state_support.MAX_LABEL_BYTES;
pub const COMPACT_OVERLAY_SESSION_METADATA = true;
pub const OVERWRITES_REUSED_SESSION_SLOTS = true;
pub const GENERATIONAL_OVERLAY_SESSION_IDS = true;
pub const OVERLAY_SESSION_SIZE_CEILING_BYTES: usize = 232;
pub const OVERLAY_RELAY_FRAME_RESULT_SIZE_CEILING_BYTES: usize = 216;
pub const OVERLAY_SESSION_SLOT_SIZE_CEILING_BYTES: usize = 240;

comptime {
    if (MAX_LABEL_BYTES > std.math.maxInt(u8)) {
        @compileError("overlay session metadata no longer fits compact lengths");
    }
}

pub const ServiceConfig = struct {
    max_overlay_sessions: usize = MAX_OVERLAY_SESSIONS,

    pub fn validate(comptime config: ServiceConfig) void {
        if (config.max_overlay_sessions == 0) @compileError("sync service requires at least one overlay session slot");
        if (config.max_overlay_sessions > std.math.maxInt(u8)) @compileError("sync service overlay session count no longer fits compact metadata");
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
    service_identity_len: u8 = 0,
    service_identity: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    relay_domain_len: u8 = 0,
    relay_domain: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    private_service_len: u8 = 0,
    private_service: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn serviceIdentitySlice(self: *const OverlaySession) []const u8 {
        return self.service_identity[0..@as(usize, self.service_identity_len)];
    }

    pub fn relayDomainSlice(self: *const OverlaySession) []const u8 {
        return self.relay_domain[0..@as(usize, self.relay_domain_len)];
    }

    pub fn privateServiceSlice(self: *const OverlaySession) []const u8 {
        return self.private_service[0..@as(usize, self.private_service_len)];
    }

    pub fn isActive(self: *const OverlaySession) bool {
        return self.state == .established;
    }

    comptime {
        if (@sizeOf(@This()) > OVERLAY_SESSION_SIZE_CEILING_BYTES) {
            @compileError("overlay session exceeds its compact size ceiling");
        }
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
    service_identity_len: u8 = 0,
    service_identity: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    relay_domain_len: u8 = 0,
    relay_domain: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,
    private_service_len: u8 = 0,
    private_service: [MAX_LABEL_BYTES]u8 = [_]u8{0} ** MAX_LABEL_BYTES,

    pub fn serviceIdentitySlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.service_identity[0..@as(usize, self.service_identity_len)];
    }

    pub fn relayDomainSlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.relay_domain[0..@as(usize, self.relay_domain_len)];
    }

    pub fn privateServiceSlice(self: *const OverlayRelayFrameResult) []const u8 {
        return self.private_service[0..@as(usize, self.private_service_len)];
    }

    comptime {
        if (@sizeOf(@This()) > OVERLAY_RELAY_FRAME_RESULT_SIZE_CEILING_BYTES) {
            @compileError("overlay relay result exceeds its compact size ceiling");
        }
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

    comptime {
        if (@sizeOf(@This()) > OVERLAY_SESSION_SLOT_SIZE_CEILING_BYTES) {
            @compileError("overlay session slot exceeds its compact size ceiling");
        }
    }
};

pub const closed_session_key: u64 = 1;

test "compact overlay session metadata preserves exact label capacities" {
    const full_label = [_]u8{'o'} ** MAX_LABEL_BYTES;
    var session = std.mem.zeroes(OverlaySession);
    session.service_identity_len = @intCast(full_label.len);
    session.relay_domain_len = @intCast(full_label.len);
    session.private_service_len = @intCast(full_label.len);
    @memcpy(&session.service_identity, &full_label);
    @memcpy(&session.relay_domain, &full_label);
    @memcpy(&session.private_service, &full_label);

    try std.testing.expectEqualSlices(u8, &full_label, session.serviceIdentitySlice());
    try std.testing.expectEqualSlices(u8, &full_label, session.relayDomainSlice());
    try std.testing.expectEqualSlices(u8, &full_label, session.privateServiceSlice());

    var result = std.mem.zeroes(OverlayRelayFrameResult);
    result.service_identity_len = @intCast(full_label.len);
    result.relay_domain_len = @intCast(full_label.len);
    result.private_service_len = @intCast(full_label.len);
    @memcpy(&result.service_identity, &full_label);
    @memcpy(&result.relay_domain, &full_label);
    @memcpy(&result.private_service, &full_label);

    try std.testing.expectEqualSlices(u8, &full_label, result.serviceIdentitySlice());
    try std.testing.expectEqualSlices(u8, &full_label, result.relayDomainSlice());
    try std.testing.expectEqualSlices(u8, &full_label, result.privateServiceSlice());
}
