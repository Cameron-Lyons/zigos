const std = @import("std");
const native_util = @import("util.zig");
const principal = @import("principal.zig");
const copyText = native_util.copyText;

pub const MAX_POLICIES: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_TARGET_BYTES: usize = 64;

pub const PolicyMode = enum(u8) {
    none,
    local_network,
    local_subnet_discovery,
    named_service_identity,
    named_domain,
    inbound_collaborative_session,
    unrestricted_internet,
};

pub const DecisionReason = enum(u8) {
    none,
    policy_denied,
    destination_mismatch,
    explicit_grant_required,
    attestation_required,
    identity_pin_mismatch,
};

pub const Destination = union(enum) {
    local_network,
    discovery_class: []const u8,
    service_identity: []const u8,
    domain: []const u8,
    inbound_session_type: []const u8,
    public_internet,
};

pub const CreateRequest = struct {
    owner: principal.PrincipalId,
    workspace_id: ?u64 = null,
    label: []const u8,
    mode: PolicyMode,
    target: []const u8 = "",
    explicit_internet_grant: bool = false,
    require_remote_attestation: bool = false,
    pinned_root_digest: ?[32]u8 = null,
};

pub const PolicyRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    workspace_id: ?u64,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    mode: PolicyMode,
    target_len: usize,
    target: [MAX_TARGET_BYTES]u8,
    explicit_internet_grant: bool,
    require_remote_attestation: bool,
    pinned_root_digest_present: bool,
    pinned_root_digest: [32]u8,

    pub fn labelSlice(self: *const PolicyRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn targetSlice(self: *const PolicyRecord) []const u8 {
        return self.target[0..self.target_len];
    }
};

pub const Decision = struct {
    allowed: bool,
    reason: DecisionReason = .none,
    matched_mode: PolicyMode = .none,
    attestation_required: bool = false,
    identity_pinned: bool = false,
};

pub const ConnectionEvidence = struct {
    destination: Destination,
    attested: bool = false,
    peer_root_digest_present: bool = false,
    peer_root_digest: [32]u8 = [_]u8{0} ** 32,
};

pub const Error = error{
    TargetRequired,
    PolicyNotFound,
    PolicyTableFull,
};

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyRecord = zeroPolicy(),
};

pub const Directory = struct {
    next_policy_id: u64 = 1,
    policies: [MAX_POLICIES]PolicySlot = [_]PolicySlot{PolicySlot{}} ** MAX_POLICIES,

    pub fn init() Directory {
        return .{};
    }

    pub fn reset(self: *Directory) void {
        self.next_policy_id = 1;
        for (&self.policies) |*slot| {
            slot.* = .{};
        }
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*PolicyRecord {
        switch (request.mode) {
            .local_subnet_discovery,
            .named_service_identity,
            .named_domain,
            .inbound_collaborative_session,
            => {
                if (request.target.len == 0) return error.TargetRequired;
            },
            else => {},
        }

        for (&self.policies) |*slot| {
            if (!slot.in_use) continue;
            if (policyMatchesRequest(&slot.policy, request)) return &slot.policy;
        }

        for (&self.policies) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.policy = zeroPolicy();
            slot.policy.id = self.nextPolicyId();
            slot.policy.owner = request.owner;
            slot.policy.workspace_id = request.workspace_id;
            slot.policy.label_len = copyText(&slot.policy.label, request.label);
            slot.policy.mode = request.mode;
            slot.policy.target_len = copyText(&slot.policy.target, request.target);
            slot.policy.explicit_internet_grant = request.explicit_internet_grant;
            slot.policy.require_remote_attestation = request.require_remote_attestation;
            if (request.pinned_root_digest) |digest| {
                slot.policy.pinned_root_digest_present = true;
                slot.policy.pinned_root_digest = digest;
            }
            return &slot.policy;
        }
        return error.PolicyTableFull;
    }

    pub fn find(self: *Directory, policy_id: u64) ?*PolicyRecord {
        for (&self.policies) |*slot| {
            if (slot.in_use and slot.policy.id == policy_id) return &slot.policy;
        }
        return null;
    }

    pub fn authorize(self: *Directory, policy_id: u64, destination: Destination) Error!Decision {
        const policy = self.find(policy_id) orelse return error.PolicyNotFound;
        return switch (policy.mode) {
            .none => .{
                .allowed = false,
                .reason = .policy_denied,
                .matched_mode = .none,
            },
            .local_network => switch (destination) {
                .local_network => .{
                    .allowed = true,
                    .matched_mode = .local_network,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .local_network,
                },
            },
            .local_subnet_discovery => switch (destination) {
                .discovery_class => |discovery_class| .{
                    .allowed = std.mem.eql(u8, discovery_class, policy.targetSlice()),
                    .reason = if (std.mem.eql(u8, discovery_class, policy.targetSlice())) .none else .destination_mismatch,
                    .matched_mode = .local_subnet_discovery,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .local_subnet_discovery,
                },
            },
            .named_service_identity => switch (destination) {
                .service_identity => |identity| .{
                    .allowed = std.mem.eql(u8, identity, policy.targetSlice()),
                    .reason = if (std.mem.eql(u8, identity, policy.targetSlice())) .none else .destination_mismatch,
                    .matched_mode = .named_service_identity,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .named_service_identity,
                },
            },
            .named_domain => switch (destination) {
                .domain => |domain| .{
                    .allowed = std.mem.eql(u8, domain, policy.targetSlice()),
                    .reason = if (std.mem.eql(u8, domain, policy.targetSlice())) .none else .destination_mismatch,
                    .matched_mode = .named_domain,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .named_domain,
                },
            },
            .inbound_collaborative_session => switch (destination) {
                .inbound_session_type => |session_type| .{
                    .allowed = std.mem.eql(u8, session_type, policy.targetSlice()),
                    .reason = if (std.mem.eql(u8, session_type, policy.targetSlice())) .none else .destination_mismatch,
                    .matched_mode = .inbound_collaborative_session,
                },
                else => .{
                    .allowed = false,
                    .reason = .destination_mismatch,
                    .matched_mode = .inbound_collaborative_session,
                },
            },
            .unrestricted_internet => blk: {
                if (!policy.explicit_internet_grant) {
                    break :blk .{
                        .allowed = false,
                        .reason = .explicit_grant_required,
                        .matched_mode = .unrestricted_internet,
                    };
                }
                break :blk switch (destination) {
                    .public_internet, .domain => .{
                        .allowed = true,
                        .matched_mode = .unrestricted_internet,
                    },
                    else => .{
                        .allowed = false,
                        .reason = .destination_mismatch,
                        .matched_mode = .unrestricted_internet,
                    },
                };
            },
        };
    }

    pub fn authorizeConnection(self: *Directory, policy_id: u64, evidence: ConnectionEvidence) Error!Decision {
        const policy = self.find(policy_id) orelse return error.PolicyNotFound;
        var decision = try self.authorize(policy_id, evidence.destination);
        if (!decision.allowed) return decision;

        if (policy.require_remote_attestation and !evidence.attested) {
            return .{
                .allowed = false,
                .reason = .attestation_required,
                .matched_mode = decision.matched_mode,
                .attestation_required = true,
            };
        }

        if (policy.pinned_root_digest_present) {
            if (!evidence.attested) {
                return .{
                    .allowed = false,
                    .reason = .attestation_required,
                    .matched_mode = decision.matched_mode,
                    .attestation_required = true,
                };
            }
            if (!evidence.peer_root_digest_present or
                !std.mem.eql(u8, &evidence.peer_root_digest, &policy.pinned_root_digest))
            {
                return .{
                    .allowed = false,
                    .reason = .identity_pin_mismatch,
                    .matched_mode = decision.matched_mode,
                    .attestation_required = true,
                    .identity_pinned = true,
                };
            }
            decision.identity_pinned = true;
        }

        decision.attestation_required = policy.require_remote_attestation or policy.pinned_root_digest_present;
        return decision;
    }

    fn nextPolicyId(self: *Directory) u64 {
        defer self.next_policy_id += 1;
        return self.next_policy_id;
    }
};

fn zeroPolicy() PolicyRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .workspace_id = null,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .mode = .none,
        .target_len = 0,
        .target = [_]u8{0} ** MAX_TARGET_BYTES,
        .explicit_internet_grant = false,
        .require_remote_attestation = false,
        .pinned_root_digest_present = false,
        .pinned_root_digest = [_]u8{0} ** 32,
    };
}


fn policyMatchesRequest(policy: *const PolicyRecord, request: CreateRequest) bool {
    if (!policy.owner.eql(request.owner)) return false;
    if (policy.workspace_id != request.workspace_id) return false;
    if (!std.mem.eql(u8, policy.labelSlice(), request.label)) return false;
    if (policy.mode != request.mode) return false;
    if (!std.mem.eql(u8, policy.targetSlice(), request.target)) return false;
    if (policy.explicit_internet_grant != request.explicit_internet_grant) return false;
    if (policy.require_remote_attestation != request.require_remote_attestation) return false;

    if (request.pinned_root_digest) |digest| {
        return policy.pinned_root_digest_present and std.mem.eql(u8, &policy.pinned_root_digest, &digest);
    }
    return !policy.pinned_root_digest_present;
}

test "network policy objects enforce discovery inbound service domain and explicit internet grants" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 8 };

    const none_policy = try directory.create(.{
        .owner = owner,
        .label = "none",
        .mode = .none,
    });
    const local_policy = try directory.create(.{
        .owner = owner,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try directory.create(.{
        .owner = owner,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const service_policy = try directory.create(.{
        .owner = owner,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    });
    const domain_policy = try directory.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    const inbound_policy = try directory.create(.{
        .owner = owner,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const internet_policy = try directory.create(.{
        .owner = owner,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    });

    try std.testing.expect(!(try directory.authorize(none_policy.id, .public_internet)).allowed);
    try std.testing.expect((try directory.authorize(local_policy.id, .local_network)).allowed);
    try std.testing.expect(!(try directory.authorize(local_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect((try directory.authorize(discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect(!(try directory.authorize(discovery_policy.id, .{ .discovery_class = "camera" })).allowed);
    try std.testing.expect((try directory.authorize(service_policy.id, .{ .service_identity = "overlay.notes.sync" })).allowed);
    try std.testing.expect(!(try directory.authorize(service_policy.id, .{ .service_identity = "overlay.other" })).allowed);
    try std.testing.expect((try directory.authorize(domain_policy.id, .{ .domain = "relay.zigos.dev" })).allowed);
    try std.testing.expect(!(try directory.authorize(domain_policy.id, .{ .domain = "example.com" })).allowed);
    try std.testing.expect((try directory.authorize(inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect(!(try directory.authorize(inbound_policy.id, .{ .inbound_session_type = "pair-screen/v1" })).allowed);
    try std.testing.expect((try directory.authorize(internet_policy.id, .public_internet)).allowed);
}

test "network policy objects require explicit targets for scoped discovery and inbound policies" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 9 };

    try std.testing.expectError(error.TargetRequired, directory.create(.{
        .owner = owner,
        .label = "missing-discovery-target",
        .mode = .local_subnet_discovery,
    }));
    try std.testing.expectError(error.TargetRequired, directory.create(.{
        .owner = owner,
        .label = "missing-session-target",
        .mode = .inbound_collaborative_session,
    }));
}

test "network policy connections can require remote attestation and pinned service identities" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 10 };
    const pinned_digest = [_]u8{0xAB} ** 32;
    const policy = try directory.create(.{
        .owner = owner,
        .label = "notes-overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });

    try std.testing.expectEqual(DecisionReason.attestation_required, (try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
    })).reason);
    try std.testing.expectEqual(DecisionReason.identity_pin_mismatch, (try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .peer_root_digest_present = true,
        .peer_root_digest = [_]u8{0xCD} ** 32,
    })).reason);

    const decision = try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .peer_root_digest_present = true,
        .peer_root_digest = pinned_digest,
    });
    try std.testing.expect(decision.allowed);
    try std.testing.expect(decision.attestation_required);
    try std.testing.expect(decision.identity_pinned);
}

test "network policy creation is idempotent for identical requests" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 11 };
    const pinned_digest = [_]u8{0xBC} ** 32;

    const first = try directory.create(.{
        .owner = owner,
        .workspace_id = 91,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });
    const second = try directory.create(.{
        .owner = owner,
        .workspace_id = 91,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
    });

    try std.testing.expectEqual(first.id, second.id);
}
