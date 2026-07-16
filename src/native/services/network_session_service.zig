const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const network_policy = @import("../sync/network_policy.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SESSIONS: usize = 32;
pub const MAX_DESTINATION_BYTES: usize = 96;
const SESSION_INDEX_CAPACITY: usize = MAX_SESSIONS * 2;

pub const SessionState = enum(u8) {
    active,
    completed,
    revoked,
};

pub const SessionRecord = struct {
    id: u64,
    subject: principal.PrincipalId,
    task_id: u64,
    policy_id: u64,
    capability_id: u64,
    matched_mode: network_policy.PolicyMode,
    sensitivity: manifest.DataSensitivity,
    destination_len: usize,
    destination: [MAX_DESTINATION_BYTES]u8,
    byte_limit: usize,
    bytes_used: usize = 0,
    opened_at_ticks: u64,
    expires_at_ticks: u64,
    attested: bool = false,
    identity_pinned: bool = false,
    state: SessionState = .active,

    pub fn destinationSlice(self: *const SessionRecord) []const u8 {
        return self.destination[0..self.destination_len];
    }

    pub fn remainingBytes(self: *const SessionRecord) usize {
        if (self.bytes_used >= self.byte_limit) return 0;
        return self.byte_limit - self.bytes_used;
    }
};

pub const OpenRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    policy_id: u64,
    capability_id: u64,
    evidence: network_policy.ConnectionEvidence,
    sensitivity: manifest.DataSensitivity = .internal_data,
    remote_bytes: usize = 0,
    max_session_bytes: usize = 0,
    expires_at_ticks: u64,
    now_ticks: u64,
    detail: []const u8,
};

pub const TransferRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    session_id: u64,
    expected_policy_id: u64,
    expected_capability_id: u64,
    bytes: usize,
    now_ticks: u64,
    detail: []const u8,
};

pub const RevokeRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    session_id: u64,
    expected_policy_id: u64,
    expected_capability_id: u64,
    now_ticks: u64,
    detail: []const u8,
};

pub const Error = network_policy.Error || event_ledger.Error || error{
    ByteLimitExceeded,
    DestinationTooLong,
    NetworkSessionIdExhausted,
    PolicyDenied,
    SessionCompleted,
    SessionBindingMismatch,
    SessionExpired,
    SessionNotFound,
    SessionRevoked,
    SessionTableFull,
    SourceMismatch,
};

const SessionSlot = struct {
    in_use: bool = false,
    record: SessionRecord = zeroSession(),
};

const SessionArena = indexed_arena.IndexedArenaWithKey(u64, SessionSlot, MAX_SESSIONS, SESSION_INDEX_CAPACITY, sessionSlotId);

pub const Service = struct {
    next_session_id: u64 = 1,
    sessions: SessionArena = SessionArena.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn open(
        self: *Service,
        network_policies: *network_policy.Directory,
        capabilities: *const capability.CapabilityTable,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: OpenRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*SessionRecord {
        const destination = try destinationLabel(request.evidence.destination);
        const private_data = manifest.isSensitive(request.sensitivity);
        const byte_limit = sessionByteLimit(request);
        if (request.expires_at_ticks <= request.now_ticks or request.task_id == 0 or request.subject.serial == 0) {
            try recordNetworkSession(ledger, request.subject, request.task_id, 0, .open, .policy_denied, false, false, false, private_data, request.now_ticks, request.detail);
            return error.PolicyDenied;
        }

        const destination_decision = policies.networkEgressDecision(subjects, destination);
        if (!destination_decision.allowed) {
            try recordNetworkSession(ledger, request.subject, request.task_id, 0, .open, .policy_denied, false, false, false, private_data, request.now_ticks, request.detail);
            return error.PolicyDenied;
        }

        const sensitive_decision = policies.sensitiveEgressDecision(subjects, .{
            .sensitivity = request.sensitivity,
            .remote_bytes = byte_limit,
        });
        if (!sensitive_decision.allowed) {
            const reason: event_ledger.NetworkSessionReason = if (sensitive_decision.reason == .private_egress_budget_denied)
                .byte_limit_exceeded
            else
                .policy_denied;
            try recordNetworkSession(ledger, request.subject, request.task_id, 0, .open, reason, false, false, false, private_data, request.now_ticks, request.detail);
            return error.PolicyDenied;
        }

        var broker = network_policy.EgressBroker.init(network_policies, capabilities);
        const decision = try broker.connect(.{
            .task_id = request.task_id,
            .principal_id = request.subject,
            .capability_id = request.capability_id,
            .policy_id = request.policy_id,
            .evidence = request.evidence,
            .now_ticks = request.now_ticks,
        });
        if (!decision.allowed) {
            try recordNetworkSession(
                ledger,
                request.subject,
                request.task_id,
                0,
                .open,
                networkSessionReasonFromEgress(decision.reason),
                false,
                request.evidence.hasVerifiedRemoteAttestation(),
                decision.policy_decision.identity_pinned,
                private_data,
                request.now_ticks,
                request.detail,
            );
            return error.PolicyDenied;
        }

        if (self.sessions.countInUse() >= MAX_SESSIONS) return error.SessionTableFull;
        const session_id = self.next_session_id;
        if (session_id == 0) return error.NetworkSessionIdExhausted;
        var record = zeroSession();
        record.id = session_id;
        record.subject = request.subject;
        record.task_id = request.task_id;
        record.policy_id = request.policy_id;
        record.capability_id = request.capability_id;
        record.matched_mode = decision.policy_decision.matched_mode;
        record.sensitivity = request.sensitivity;
        record.destination_len = native_util.copyTextExact(&record.destination, destination) catch return error.DestinationTooLong;
        record.byte_limit = byte_limit;
        record.opened_at_ticks = request.now_ticks;
        record.expires_at_ticks = request.expires_at_ticks;
        record.attested = request.evidence.hasVerifiedRemoteAttestation();
        record.identity_pinned = decision.policy_decision.identity_pinned;

        const slot_index = self.sessions.reserveIndex(session_id) orelse return error.SessionTableFull;
        errdefer _ = self.sessions.removeIndex(slot_index);
        try recordNetworkSession(
            ledger,
            request.subject,
            request.task_id,
            session_id,
            .open,
            .none,
            true,
            record.attested,
            record.identity_pinned,
            private_data,
            request.now_ticks,
            request.detail,
        );
        const slot = &self.sessions.slots[slot_index];
        slot.record = record;
        self.advanceNextSessionId();
        return &slot.record;
    }

    pub fn recordTransfer(
        self: *Service,
        request: TransferRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*SessionRecord {
        const session = self.sessionForRequest(
            request.subject,
            request.task_id,
            request.session_id,
            request.expected_policy_id,
            request.expected_capability_id,
            request.now_ticks,
            ledger,
            .transfer,
            request.detail,
        ) catch |err| return err;
        if (request.bytes > session.remainingBytes()) {
            try recordNetworkSession(
                ledger,
                request.subject,
                request.task_id,
                request.session_id,
                .transfer,
                .byte_limit_exceeded,
                false,
                session.attested,
                session.identity_pinned,
                manifest.isSensitive(session.sensitivity),
                request.now_ticks,
                request.detail,
            );
            return error.ByteLimitExceeded;
        }
        session.bytes_used += request.bytes;
        try recordNetworkSession(
            ledger,
            request.subject,
            request.task_id,
            request.session_id,
            .transfer,
            .none,
            true,
            session.attested,
            session.identity_pinned,
            manifest.isSensitive(session.sensitivity),
            request.now_ticks,
            request.detail,
        );
        return session;
    }

    pub fn revoke(
        self: *Service,
        request: RevokeRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*SessionRecord {
        const session = self.sessionForRequest(
            request.subject,
            request.task_id,
            request.session_id,
            request.expected_policy_id,
            request.expected_capability_id,
            request.now_ticks,
            ledger,
            .revoke,
            request.detail,
        ) catch |err| return err;
        session.state = .revoked;
        try recordNetworkSession(
            ledger,
            request.subject,
            request.task_id,
            request.session_id,
            .revoke,
            .none,
            true,
            session.attested,
            session.identity_pinned,
            manifest.isSensitive(session.sensitivity),
            request.now_ticks,
            request.detail,
        );
        return session;
    }

    pub fn complete(
        self: *Service,
        request: RevokeRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*SessionRecord {
        const session = self.sessionForRequest(
            request.subject,
            request.task_id,
            request.session_id,
            request.expected_policy_id,
            request.expected_capability_id,
            request.now_ticks,
            ledger,
            .complete,
            request.detail,
        ) catch |err| return err;
        session.state = .completed;
        try recordNetworkSession(
            ledger,
            request.subject,
            request.task_id,
            request.session_id,
            .complete,
            .none,
            true,
            session.attested,
            session.identity_pinned,
            manifest.isSensitive(session.sensitivity),
            request.now_ticks,
            request.detail,
        );
        return session;
    }

    pub fn find(self: *const Service, session_id: u64) ?*const SessionRecord {
        const slot = self.sessions.getConst(session_id) orelse return null;
        return &slot.record;
    }

    fn sessionForRequest(
        self: *Service,
        subject: principal.PrincipalId,
        task_id: u64,
        session_id: u64,
        expected_policy_id: u64,
        expected_capability_id: u64,
        now_ticks: u64,
        ledger: ?*event_ledger.Ledger,
        action: event_ledger.NetworkSessionAction,
        detail: []const u8,
    ) Error!*SessionRecord {
        const slot = self.sessions.get(session_id) orelse return error.SessionNotFound;
        const session = &slot.record;
        const private_data = manifest.isSensitive(session.sensitivity);
        if (!session.subject.eql(subject) or session.task_id != task_id) {
            try recordNetworkSession(ledger, subject, task_id, session_id, action, .source_mismatch, false, session.attested, session.identity_pinned, private_data, now_ticks, detail);
            return error.SourceMismatch;
        }
        if (session.policy_id != expected_policy_id or session.capability_id != expected_capability_id) {
            try recordNetworkSession(ledger, subject, task_id, session_id, action, .source_mismatch, false, session.attested, session.identity_pinned, private_data, now_ticks, detail);
            return error.SessionBindingMismatch;
        }
        if (session.state == .revoked) {
            try recordNetworkSession(ledger, subject, task_id, session_id, action, .session_revoked, false, session.attested, session.identity_pinned, private_data, now_ticks, detail);
            return error.SessionRevoked;
        }
        if (session.state == .completed) {
            try recordNetworkSession(ledger, subject, task_id, session_id, action, .session_completed, false, session.attested, session.identity_pinned, private_data, now_ticks, detail);
            return error.SessionCompleted;
        }
        if (now_ticks >= session.expires_at_ticks) {
            try recordNetworkSession(ledger, subject, task_id, session_id, action, .session_expired, false, session.attested, session.identity_pinned, private_data, now_ticks, detail);
            return error.SessionExpired;
        }
        return session;
    }

    fn advanceNextSessionId(self: *Service) void {
        self.next_session_id = if (self.next_session_id == std.math.maxInt(u64))
            0
        else
            self.next_session_id + 1;
    }
};

fn zeroSession() SessionRecord {
    return .{
        .id = 0,
        .subject = .{ .kind = .app, .serial = 0 },
        .task_id = 0,
        .policy_id = 0,
        .capability_id = 0,
        .matched_mode = .none,
        .sensitivity = .internal_data,
        .destination_len = 0,
        .destination = [_]u8{0} ** MAX_DESTINATION_BYTES,
        .byte_limit = 0,
        .opened_at_ticks = 0,
        .expires_at_ticks = 0,
    };
}

fn sessionSlotId(slot: *const SessionSlot) u64 {
    return slot.record.id;
}

fn sessionByteLimit(request: OpenRequest) usize {
    if (request.max_session_bytes != 0) return request.max_session_bytes;
    return request.remote_bytes;
}

fn destinationLabel(destination: network_policy.Destination) Error![]const u8 {
    return switch (destination) {
        .local_network => "local-network",
        .discovery_class => |label| label,
        .service_identity => |label| label,
        .domain => |label| label,
        .inbound_session_type => |label| label,
        .public_internet => "public-internet",
    };
}

fn networkSessionReasonFromEgress(reason: network_policy.EgressDecisionReason) event_ledger.NetworkSessionReason {
    return switch (reason) {
        .none => .none,
        .invalid_request,
        .capability_missing,
        .capability_revoked,
        .holder_mismatch,
        .scope_violation,
        .target_mismatch,
        .missing_local_right,
        .missing_remote_right,
        => .capability_denied,
        .policy_denied,
        .explicit_grant_required,
        => .policy_denied,
        .destination_mismatch => .destination_mismatch,
        .attestation_required => .attestation_required,
        .identity_pin_mismatch => .attestation_required,
    };
}

fn recordNetworkSession(
    ledger: ?*event_ledger.Ledger,
    subject: principal.PrincipalId,
    task_id: u64,
    session_id: u64,
    action: event_ledger.NetworkSessionAction,
    reason: event_ledger.NetworkSessionReason,
    allowed: bool,
    attested: bool,
    identity_pinned: bool,
    private_data: bool,
    tick: u64,
    detail: []const u8,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordNetworkSession(
            subject,
            task_id,
            session_id,
            action,
            reason,
            allowed,
            attested,
            identity_pinned,
            private_data,
            tick,
            detail,
        );
    }
}

test "network session publication rejects invalid destinations and id reuse" {
    const signing = @import("../core/signing.zig");

    var network_policies = network_policy.Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 901 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 902 };
    const internet = try network_policies.create(.{
        .owner = owner,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    var capabilities = capability.CapabilityTable.init();
    const network_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 901 },
        .target = .{ .kind = .network_policy, .id = internet.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 9902 },
        .lease = .{
            .issued_at_ticks = 1,
            .expires_at_ticks = 100,
        },
    });

    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = 900,
        .issuer = .{ .kind = .policy_authority, .serial = 901 },
        .label = "network-session-egress",
        .network_egress_mode = .unrestricted,
    }, signing.SignerIdentity{
        .label = "network-session-egress",
        .seed = signing.seedFromByte(0x91),
    });
    const subjects = policy_object.SubjectSet{ .user_id = 900 };

    var service = Service.init();
    const oversized_destination = [_]u8{'a'} ** (MAX_DESTINATION_BYTES + 1);
    try std.testing.expectError(error.DestinationTooLong, service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 9902,
            .policy_id = internet.id,
            .capability_id = network_capability.id,
            .evidence = .{ .destination = .{ .domain = oversized_destination[0..] } },
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 40,
            .now_ticks = 10,
            .detail = "long destination rejected",
        },
        null,
    ));
    try std.testing.expectEqual(@as(usize, 0), service.sessions.countInUse());
    try std.testing.expect(service.find(1) == null);
    try std.testing.expectEqual(@as(u64, 1), service.next_session_id);

    const session = try service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 9902,
            .policy_id = internet.id,
            .capability_id = network_capability.id,
            .evidence = .{ .destination = .{ .domain = "updates.example" } },
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 40,
            .now_ticks = 11,
            .detail = "valid destination opened",
        },
        null,
    );
    try std.testing.expectEqual(@as(u64, 1), session.id);
    try std.testing.expectEqualStrings("updates.example", session.destinationSlice());
    try std.testing.expectEqual(@as(usize, 1), service.sessions.countInUse());

    service.next_session_id = std.math.maxInt(u64);
    const final_session = try service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 9902,
            .policy_id = internet.id,
            .capability_id = network_capability.id,
            .evidence = .{ .destination = .{ .domain = "final.example" } },
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 40,
            .now_ticks = 12,
            .detail = "final session id opened",
        },
        null,
    );
    try std.testing.expectEqual(std.math.maxInt(u64), final_session.id);
    try std.testing.expectEqual(@as(u64, 0), service.next_session_id);

    try std.testing.expectError(error.NetworkSessionIdExhausted, service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 9902,
            .policy_id = internet.id,
            .capability_id = network_capability.id,
            .evidence = .{ .destination = .{ .domain = "reused.example" } },
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 40,
            .now_ticks = 13,
            .detail = "session id reuse rejected",
        },
        null,
    ));
    try std.testing.expectEqual(@as(u64, 0), service.next_session_id);
    try std.testing.expectEqual(@as(usize, 2), service.sessions.countInUse());
    try std.testing.expectEqual(std.math.maxInt(u64), service.find(std.math.maxInt(u64)).?.id);
}

test "network session service opens leased attested sessions and audits revocation" {
    const crypto_hash = @import("../core/crypto_hash.zig");
    const signing = @import("../core/signing.zig");

    var network_policies = network_policy.Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 801 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 802 };
    const relay = try network_policies.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
        .require_remote_attestation = true,
    });

    var capabilities = capability.CapabilityTable.init();
    const network_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 801 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
            .capability_derive = true,
        } },
        .scope = .{
            .task_id = 8802,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 1,
            .expires_at_ticks = 100,
        },
    });

    var policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = 800,
        .issuer = .{ .kind = .policy_authority, .serial = 801 },
        .label = "network-session-policy",
        .network_egress_mode = .allow_list,
        .allowed_network_destinations = &.{"relay.zigos.dev"},
        .max_remote_private_egress_bytes = 1024,
    }, signing.SignerIdentity{
        .label = "network-session-policy",
        .seed = signing.seedFromByte(0x8A),
    });
    const subjects = policy_object.SubjectSet{ .user_id = 800 };

    var service = Service.init();
    var ledger = event_ledger.Ledger.init();
    const attested_evidence = network_policy.ConnectionEvidence{
        .destination = .{ .domain = "relay.zigos.dev" },
        .attested = true,
        .verified_remote_attestation = true,
        .attestation_request_digest_present = true,
        .attestation_request_digest = crypto_hash.digestFromByte(0x81),
        .peer_root_digest_present = true,
        .peer_root_digest = crypto_hash.digestFromByte(0x82),
    };

    try std.testing.expectError(error.PolicyDenied, service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8802,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = .{ .destination = .{ .domain = "other.example" } },
            .sensitivity = .private_user_data,
            .remote_bytes = 128,
            .max_session_bytes = 256,
            .expires_at_ticks = 40,
            .now_ticks = 10,
            .detail = "private denied destination detail",
        },
        &ledger,
    ));
    try std.testing.expectError(error.PolicyDenied, service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8802,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = attested_evidence,
            .sensitivity = .private_user_data,
            .remote_bytes = 128,
            .max_session_bytes = 2048,
            .expires_at_ticks = 40,
            .now_ticks = 10,
            .detail = "private oversized session budget",
        },
        &ledger,
    ));

    const session = try service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8802,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = attested_evidence,
            .sensitivity = .private_user_data,
            .remote_bytes = 512,
            .max_session_bytes = 768,
            .expires_at_ticks = 40,
            .now_ticks = 11,
            .detail = "private relay session opened",
        },
        &ledger,
    );
    try std.testing.expectEqual(@as(u64, 1), session.id);
    try std.testing.expect(session.attested);
    try std.testing.expectEqualStrings("relay.zigos.dev", session.destinationSlice());

    try std.testing.expectError(error.SessionBindingMismatch, service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = session.id,
        .expected_policy_id = relay.id + 1,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 12,
        .detail = "private wrong policy relay transfer",
    }, &ledger));
    try std.testing.expectEqual(@as(usize, 0), service.find(session.id).?.bytes_used);

    const transferred = try service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 256,
        .now_ticks = 12,
        .detail = "private relay transfer",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 256), transferred.bytes_used);
    try std.testing.expectEqual(@as(usize, 512), transferred.remainingBytes());

    try std.testing.expectError(error.ByteLimitExceeded, service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 600,
        .now_ticks = 13,
        .detail = "private relay transfer over budget",
    }, &ledger));

    const revoked = try service.revoke(.{
        .subject = app,
        .task_id = 8802,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .now_ticks = 14,
        .detail = "private relay session revoked",
    }, &ledger);
    try std.testing.expectEqual(SessionState.revoked, revoked.state);
    try std.testing.expectError(error.SessionRevoked, service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 15,
        .detail = "private revoked relay transfer",
    }, &ledger));

    const completed_session = try service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8802,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = attested_evidence,
            .sensitivity = .private_user_data,
            .remote_bytes = 256,
            .max_session_bytes = 256,
            .expires_at_ticks = 40,
            .now_ticks = 16,
            .detail = "private completed relay session opened",
        },
        &ledger,
    );
    const completed = try service.complete(.{
        .subject = app,
        .task_id = 8802,
        .session_id = completed_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .now_ticks = 17,
        .detail = "private relay session completed",
    }, &ledger);
    try std.testing.expectEqual(SessionState.completed, completed.state);
    try std.testing.expectError(error.SessionCompleted, service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = completed_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 18,
        .detail = "private completed relay transfer",
    }, &ledger));

    var expiry_service = Service.init();
    var expiry_ledger = event_ledger.Ledger.init();
    try std.testing.expectError(error.PolicyDenied, expiry_service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8802,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = attested_evidence,
            .sensitivity = .private_user_data,
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 20,
            .now_ticks = 20,
            .detail = "private instant-expired relay session",
        },
        &expiry_ledger,
    ));
    const expiring_session = try expiry_service.open(
        &network_policies,
        &capabilities,
        &policies,
        subjects,
        .{
            .subject = app,
            .task_id = 8802,
            .policy_id = relay.id,
            .capability_id = network_capability.id,
            .evidence = attested_evidence,
            .sensitivity = .private_user_data,
            .remote_bytes = 16,
            .max_session_bytes = 16,
            .expires_at_ticks = 22,
            .now_ticks = 20,
            .detail = "private expiring relay session",
        },
        &expiry_ledger,
    );
    _ = try expiry_service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = expiring_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 21,
        .detail = "private pre-expiry relay transfer",
    }, &expiry_ledger);
    try std.testing.expectError(error.SessionExpired, expiry_service.recordTransfer(.{
        .subject = app,
        .task_id = 8802,
        .session_id = expiring_session.id,
        .expected_policy_id = relay.id,
        .expected_capability_id = network_capability.id,
        .bytes = 1,
        .now_ticks = 22,
        .detail = "private at-expiry relay transfer",
    }, &expiry_ledger));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 11), summary.network_session_events);
    try std.testing.expectEqual(@as(usize, 6), summary.network_session_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.network_session_revocations);
    try std.testing.expectEqual(@as(usize, 2), summary.network_session_byte_denials);
    try std.testing.expect(summary.network_session_attested >= 7);

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=network_session") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "private relay") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "detail=redacted") != null);
}
