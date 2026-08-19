const std = @import("std");
const attestation_service = @import("../platform/attestation_service.zig");
const capability = @import("../kernel_api/capability.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const hash_seeds = @import("../core/hash_seeds.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_TARGET_BYTES: usize = 64;
pub const COMPACT_POLICY_METADATA = true;
pub const POLICY_RECORD_SIZE_CEILING_BYTES: usize = 224;
pub const DIRECTORY_SIZE_CEILING_BYTES: usize = 4_848;
const POLICY_INDEX_CAPACITY: usize = MAX_POLICIES * 2;

comptime {
    if (MAX_LABEL_BYTES > std.math.maxInt(u8) or MAX_TARGET_BYTES > std.math.maxInt(u8)) {
        @compileError("network policy metadata no longer fits compact lengths");
    }
}

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
    pinned_root_digest: ?crypto_hash.Digest = null,
    pinned_attestation_verifier_metadata_digest: ?crypto_hash.Digest = null,
};

pub const PolicyRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    workspace_id: ?u64,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    mode: PolicyMode,
    target_len: u8,
    target: [MAX_TARGET_BYTES]u8,
    explicit_internet_grant: bool,
    require_remote_attestation: bool,
    pinned_root_digest_present: bool,
    pinned_root_digest: crypto_hash.Digest,
    pinned_attestation_verifier_metadata_digest_present: bool,
    pinned_attestation_verifier_metadata_digest: crypto_hash.Digest,

    pub fn labelSlice(self: *const PolicyRecord) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    pub fn targetSlice(self: *const PolicyRecord) []const u8 {
        return self.target[0..@as(usize, self.target_len)];
    }

    comptime {
        if (@sizeOf(@This()) > POLICY_RECORD_SIZE_CEILING_BYTES) {
            @compileError("network policy record exceeds its compact size ceiling");
        }
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
    verified_remote_attestation: bool = false,
    attestation_request_digest_present: bool = false,
    attestation_request_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    peer_root_digest_present: bool = false,
    peer_root_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    attestation_verifier_metadata_digest_present: bool = false,
    attestation_verifier_metadata_digest_bound: bool = false,
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn fromVerifiedRemoteAttestation(
        destination: Destination,
        response: attestation_service.RemoteAttestationResponse,
        request: attestation_service.RemoteAttestationRequest,
        boot: *const measured_boot.BootRecord,
        trusted_root: signing.PublicIdentity,
    ) ?ConnectionEvidence {
        if (!attestation_service.Service.verifyRemoteAttestationResponse(response, request, boot, trusted_root)) return null;
        if (!destinationMatchesRemoteParty(destination, request.remotePartySlice())) return null;
        return .{
            .destination = destination,
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = response.request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = response.statement.root_digest,
            .attestation_verifier_metadata_digest_present = response.attestation_verifier_metadata_digest_present,
            .attestation_verifier_metadata_digest_bound = request.attestation_verifier_metadata_digest_required,
            .attestation_verifier_metadata_digest = response.attestation_verifier_metadata_digest,
        };
    }

    pub fn hasVerifiedRemoteAttestation(self: *const ConnectionEvidence) bool {
        return self.attested and
            self.verified_remote_attestation and
            self.attestation_request_digest_present and
            !std.mem.allEqual(u8, &self.attestation_request_digest, 0) and
            self.peer_root_digest_present and
            !std.mem.allEqual(u8, &self.peer_root_digest, 0);
    }

    pub fn hasAttestationVerifierMetadataDigest(self: *const ConnectionEvidence) bool {
        return self.attestation_verifier_metadata_digest_present and
            self.attestation_verifier_metadata_digest_bound and
            !std.mem.allEqual(u8, &self.attestation_verifier_metadata_digest, 0);
    }
};

fn destinationMatchesRemoteParty(destination: Destination, remote_party: []const u8) bool {
    if (remote_party.len == 0) return false;
    return switch (destination) {
        .service_identity => |identity| std.mem.eql(u8, identity, remote_party),
        .domain => |domain| std.mem.eql(u8, domain, remote_party),
        .discovery_class => |discovery_class| std.mem.eql(u8, discovery_class, remote_party),
        .inbound_session_type => |session_type| std.mem.eql(u8, session_type, remote_party),
        .local_network, .public_internet => false,
    };
}

pub const EgressDecisionReason = enum(u8) {
    none,
    invalid_request,
    capability_missing,
    capability_revoked,
    holder_mismatch,
    scope_violation,
    target_mismatch,
    missing_local_right,
    missing_remote_right,
    policy_denied,
    destination_mismatch,
    explicit_grant_required,
    attestation_required,
    identity_pin_mismatch,
};

pub const EgressConnectionRequest = struct {
    task_id: u64,
    principal_id: principal.PrincipalId,
    capability_id: u64,
    policy_id: u64,
    evidence: ConnectionEvidence,
    now_ticks: u64,
};

pub const EgressDecision = struct {
    allowed: bool,
    reason: EgressDecisionReason = .none,
    policy_id: u64,
    capability_id: u64,
    policy_decision: Decision = .{ .allowed = false },
};

pub const Error = error{
    DomainTargetInvalid,
    LabelTooLong,
    TargetRequired,
    TargetTooLong,
    UnexpectedTarget,
    PolicyNotFound,
    PolicyTableFull,
    EmptyAttestationPin,
};

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyRecord = zeroPolicy(),
};

fn policySlotKey(slot: *const PolicySlot) u64 {
    return slot.policy.id;
}

const PolicyArena = indexed_arena.IndexedArenaWithKey(u64, PolicySlot, MAX_POLICIES, POLICY_INDEX_CAPACITY, policySlotKey);
const PolicyRequestIndex = indexed_arena.MultimapIndex(MAX_POLICIES, MAX_POLICIES, POLICY_INDEX_CAPACITY);

pub const Directory = struct {
    next_policy_id: u64 = 1,
    policies: PolicyArena = PolicyArena.init(),
    request_index: PolicyRequestIndex = PolicyRequestIndex.init(),

    pub fn init() Directory {
        return .{};
    }

    pub fn reset(self: *Directory) void {
        self.* = Directory.init();
    }

    pub fn create(self: *Directory, request: CreateRequest) Error!*PolicyRecord {
        try validateCreateRequest(request);

        const request_key = policyRequestKey(request);
        if (self.findByRequestKey(request_key, request)) |policy| return policy;

        if (self.policies.countInUse() >= MAX_POLICIES) return error.PolicyTableFull;
        const policy_id = self.next_policy_id;
        var policy = zeroPolicy();
        policy.id = policy_id;
        policy.owner = request.owner;
        policy.workspace_id = request.workspace_id;
        policy.label_len = @intCast(native_util.copyTextExact(&policy.label, request.label) catch return error.LabelTooLong);
        policy.mode = request.mode;
        policy.target_len = @intCast(native_util.copyTextExact(&policy.target, request.target) catch return error.TargetTooLong);
        policy.explicit_internet_grant = request.explicit_internet_grant;
        policy.require_remote_attestation = request.require_remote_attestation;
        if (request.pinned_root_digest) |digest| {
            policy.pinned_root_digest_present = true;
            policy.pinned_root_digest = digest;
        }
        if (request.pinned_attestation_verifier_metadata_digest) |digest| {
            policy.pinned_attestation_verifier_metadata_digest_present = true;
            policy.pinned_attestation_verifier_metadata_digest = digest;
        }

        const slot_index = self.policies.reserveIndex(policy_id) orelse return error.PolicyTableFull;
        const slot = &self.policies.slots[slot_index];
        slot.policy = policy;
        self.next_policy_id += 1;
        self.indexPolicy(slot_index);
        return &slot.policy;
    }

    pub fn find(self: *Directory, policy_id: u64) ?*PolicyRecord {
        if (policy_id == 0) return null;
        const slot = self.policies.get(policy_id) orelse return null;
        return &slot.policy;
    }

    pub fn rebuildIndexes(self: *Directory) void {
        self.policies.rebuildPrimaryIndex();
        self.request_index.reset();
        for (self.policies.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) continue;
            self.indexPolicy(slot_index);
        }
    }

    pub fn authorize(self: *Directory, policy_id: u64, destination: Destination) Error!Decision {
        const policy = self.find(policy_id) orelse return error.PolicyNotFound;
        return authorizePolicy(policy, destination);
    }

    pub fn authorizeConnection(self: *Directory, policy_id: u64, evidence: ConnectionEvidence) Error!Decision {
        const policy = self.find(policy_id) orelse return error.PolicyNotFound;
        var decision = authorizePolicy(policy, evidence.destination);
        if (!decision.allowed) return decision;

        if (policy.require_remote_attestation and !evidence.hasVerifiedRemoteAttestation()) {
            return .{
                .allowed = false,
                .reason = .attestation_required,
                .matched_mode = decision.matched_mode,
                .attestation_required = true,
            };
        }

        if (policy.pinned_root_digest_present) {
            if (!evidence.hasVerifiedRemoteAttestation()) {
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

        if (policy.pinned_attestation_verifier_metadata_digest_present) {
            if (!evidence.hasVerifiedRemoteAttestation()) {
                return .{
                    .allowed = false,
                    .reason = .attestation_required,
                    .matched_mode = decision.matched_mode,
                    .attestation_required = true,
                };
            }
            if (!evidence.hasAttestationVerifierMetadataDigest() or
                !std.mem.eql(u8, &evidence.attestation_verifier_metadata_digest, &policy.pinned_attestation_verifier_metadata_digest))
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

        decision.attestation_required = policy.require_remote_attestation or
            policy.pinned_root_digest_present or
            policy.pinned_attestation_verifier_metadata_digest_present;
        return decision;
    }

    fn findByRequestKey(
        self: *Directory,
        request_key: u64,
        request: CreateRequest,
    ) ?*PolicyRecord {
        var cursor = self.request_index.head(request_key);
        while (cursor != indexed_arena.no_index) : (cursor = self.request_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("network policy request index points outside slots");
            const slot = &self.policies.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("network policy request index points at a free slot");
            if (policyMatchesRequest(&slot.policy, request)) return &slot.policy;
        }
        return null;
    }

    fn indexPolicy(self: *Directory, slot_index: usize) void {
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("network policy index update points outside slots");
        const slot = &self.policies.slots[slot_index];
        if (!slot.in_use or slot.policy.id == 0) native_util.impossibleByInvariant("network policy index update requires a live policy");
        const request_key = policyRecordRequestKey(&slot.policy);
        if (!self.request_index.append(request_key, slot_index)) {
            native_util.impossibleByInvariant("network policy request index capacity covers policy slots");
        }
    }

    comptime {
        if (@sizeOf(@This()) > DIRECTORY_SIZE_CEILING_BYTES) {
            @compileError("network policy directory exceeds its compact size ceiling");
        }
    }
};

fn authorizePolicy(policy: *const PolicyRecord, destination: Destination) Decision {
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
            else => targetDecision(false, .local_network),
        },
        .local_subnet_discovery => switch (destination) {
            .discovery_class => |discovery_class| targetDecision(
                std.mem.eql(u8, discovery_class, policy.targetSlice()),
                .local_subnet_discovery,
            ),
            else => targetDecision(false, .local_subnet_discovery),
        },
        .named_service_identity => switch (destination) {
            .service_identity => |identity| targetDecision(
                std.mem.eql(u8, identity, policy.targetSlice()),
                .named_service_identity,
            ),
            else => targetDecision(false, .named_service_identity),
        },
        .named_domain => switch (destination) {
            .domain => |domain| targetDecision(
                std.mem.eql(u8, domain, policy.targetSlice()),
                .named_domain,
            ),
            else => targetDecision(false, .named_domain),
        },
        .inbound_collaborative_session => switch (destination) {
            .inbound_session_type => |session_type| targetDecision(
                std.mem.eql(u8, session_type, policy.targetSlice()),
                .inbound_collaborative_session,
            ),
            else => targetDecision(false, .inbound_collaborative_session),
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
                else => targetDecision(false, .unrestricted_internet),
            };
        },
    };
}

fn targetDecision(allowed: bool, mode: PolicyMode) Decision {
    return .{
        .allowed = allowed,
        .reason = if (allowed) .none else .destination_mismatch,
        .matched_mode = mode,
    };
}

pub const EgressBroker = struct {
    policies: *Directory,
    capabilities: *const capability.CapabilityTable,

    pub fn init(
        policies: *Directory,
        capabilities: *const capability.CapabilityTable,
    ) EgressBroker {
        return .{
            .policies = policies,
            .capabilities = capabilities,
        };
    }

    pub fn connect(self: *EgressBroker, request: EgressConnectionRequest) Error!EgressDecision {
        if (request.now_ticks == 0 or request.task_id == 0 or request.principal_id.serial == 0) {
            return denyEgress(request, .invalid_request, .{ .allowed = false });
        }
        const presented = self.capabilities.requireUsable(request.capability_id, request.now_ticks) catch |err| switch (err) {
            error.CapabilityNotFound => return denyEgress(request, .capability_missing, .{ .allowed = false }),
            error.CapabilityRevoked => return denyEgress(request, .capability_revoked, .{ .allowed = false }),
        };

        if (!presented.holder.eql(request.principal_id)) {
            return denyEgress(request, .holder_mismatch, .{ .allowed = false });
        }
        if (presented.scope.task_id) |task_id| {
            if (task_id != request.task_id) {
                return denyEgress(request, .scope_violation, .{ .allowed = false });
            }
        }
        if (presented.target.kind != .network_policy or presented.target.id != request.policy_id) {
            return denyEgress(request, .target_mismatch, .{ .allowed = false });
        }

        const policy_decision = try self.policies.authorizeConnection(request.policy_id, request.evidence);
        if (!policy_decision.allowed) {
            return denyEgress(request, egressReasonFromPolicy(policy_decision.reason), policy_decision);
        }
        if (presented.scope.local_only and !policyModeIsLocal(policy_decision.matched_mode)) {
            return denyEgress(request, .scope_violation, policy_decision);
        }
        if (!capabilityAllowsMode(presented.rights, policy_decision.matched_mode)) {
            return denyEgress(
                request,
                if (policyModeIsLocal(policy_decision.matched_mode)) .missing_local_right else .missing_remote_right,
                policy_decision,
            );
        }

        return .{
            .allowed = true,
            .policy_id = request.policy_id,
            .capability_id = request.capability_id,
            .policy_decision = policy_decision,
        };
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
        .pinned_root_digest = crypto_hash.zero_digest,
        .pinned_attestation_verifier_metadata_digest_present = false,
        .pinned_attestation_verifier_metadata_digest = crypto_hash.zero_digest,
    };
}

fn policyRequestKey(request: CreateRequest) u64 {
    var hasher = std.hash.Wyhash.init(hash_seeds.network_policy_request_key);
    updatePrincipalHash(&hasher, request.owner);
    updateOptionalU64Hash(&hasher, request.workspace_id);
    updateSliceHash(&hasher, request.label);
    updateByteHash(&hasher, @intFromEnum(request.mode));
    updateSliceHash(&hasher, request.target);
    updateBoolHash(&hasher, request.explicit_internet_grant);
    updateBoolHash(&hasher, request.require_remote_attestation);
    updateBoolHash(&hasher, request.pinned_root_digest != null);
    if (request.pinned_root_digest) |digest| hasher.update(&digest);
    updateBoolHash(&hasher, request.pinned_attestation_verifier_metadata_digest != null);
    if (request.pinned_attestation_verifier_metadata_digest) |digest| hasher.update(&digest);
    return indexed_arena.nonZeroKey(hasher.final());
}

fn policyRecordRequestKey(policy: *const PolicyRecord) u64 {
    var hasher = std.hash.Wyhash.init(hash_seeds.network_policy_request_key);
    updatePrincipalHash(&hasher, policy.owner);
    updateOptionalU64Hash(&hasher, policy.workspace_id);
    updateSliceHash(&hasher, policy.labelSlice());
    updateByteHash(&hasher, @intFromEnum(policy.mode));
    updateSliceHash(&hasher, policy.targetSlice());
    updateBoolHash(&hasher, policy.explicit_internet_grant);
    updateBoolHash(&hasher, policy.require_remote_attestation);
    updateBoolHash(&hasher, policy.pinned_root_digest_present);
    if (policy.pinned_root_digest_present) hasher.update(&policy.pinned_root_digest);
    updateBoolHash(&hasher, policy.pinned_attestation_verifier_metadata_digest_present);
    if (policy.pinned_attestation_verifier_metadata_digest_present) hasher.update(&policy.pinned_attestation_verifier_metadata_digest);
    return indexed_arena.nonZeroKey(hasher.final());
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
        if (!policy.pinned_root_digest_present or !std.mem.eql(u8, &policy.pinned_root_digest, &digest)) return false;
    } else if (policy.pinned_root_digest_present) {
        return false;
    }
    if (request.pinned_attestation_verifier_metadata_digest) |digest| {
        return policy.pinned_attestation_verifier_metadata_digest_present and
            std.mem.eql(u8, &policy.pinned_attestation_verifier_metadata_digest, &digest);
    }
    return !policy.pinned_attestation_verifier_metadata_digest_present;
}

fn updatePrincipalHash(hasher: *std.hash.Wyhash, id: principal.PrincipalId) void {
    updateByteHash(hasher, @intFromEnum(id.kind));
    updateU64Hash(hasher, id.serial);
}

fn updateOptionalU64Hash(hasher: *std.hash.Wyhash, value: ?u64) void {
    updateBoolHash(hasher, value != null);
    updateU64Hash(hasher, value orelse 0);
}

fn updateBoolHash(hasher: *std.hash.Wyhash, value: bool) void {
    updateByteHash(hasher, if (value) 1 else 0);
}

fn updateByteHash(hasher: *std.hash.Wyhash, value: u8) void {
    const bytes = [_]u8{value};
    hasher.update(&bytes);
}

fn updateU64Hash(hasher: *std.hash.Wyhash, value: u64) void {
    var bytes: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hasher.update(&bytes);
}

fn updateSliceHash(hasher: *std.hash.Wyhash, value: []const u8) void {
    updateU64Hash(hasher, value.len);
    hasher.update(value);
}

fn denyEgress(
    request: EgressConnectionRequest,
    reason: EgressDecisionReason,
    policy_decision: Decision,
) EgressDecision {
    return .{
        .allowed = false,
        .reason = reason,
        .policy_id = request.policy_id,
        .capability_id = request.capability_id,
        .policy_decision = policy_decision,
    };
}

fn egressReasonFromPolicy(reason: DecisionReason) EgressDecisionReason {
    return switch (reason) {
        .none => .none,
        .policy_denied => .policy_denied,
        .destination_mismatch => .destination_mismatch,
        .explicit_grant_required => .explicit_grant_required,
        .attestation_required => .attestation_required,
        .identity_pin_mismatch => .identity_pin_mismatch,
    };
}

fn capabilityAllowsMode(rights: capability.CapabilityRights, mode: PolicyMode) bool {
    if (policyModeIsLocal(mode)) return rights.has(.network_local);
    return rights.has(.network_remote);
}

fn policyModeIsLocal(mode: PolicyMode) bool {
    return switch (mode) {
        .local_network, .local_subnet_discovery => true,
        .none,
        .named_service_identity,
        .named_domain,
        .inbound_collaborative_session,
        .unrestricted_internet,
        => false,
    };
}

fn validateCreateRequest(request: CreateRequest) Error!void {
    switch (request.mode) {
        .local_subnet_discovery,
        .named_service_identity,
        .named_domain,
        .inbound_collaborative_session,
        => {
            if (request.target.len == 0) return error.TargetRequired;
        },
        .none, .local_network, .unrestricted_internet => {
            if (request.target.len != 0) return error.UnexpectedTarget;
        },
    }

    if (request.mode == .named_domain and !validDomainTarget(request.target)) {
        return error.DomainTargetInvalid;
    }
    if (request.pinned_root_digest) |digest| {
        if (std.mem.allEqual(u8, &digest, 0)) return error.EmptyAttestationPin;
    }
    if (request.pinned_attestation_verifier_metadata_digest) |digest| {
        if (std.mem.allEqual(u8, &digest, 0)) return error.EmptyAttestationPin;
    }
}

fn validDomainTarget(target: []const u8) bool {
    if (target.len == 0) return false;
    if (target[0] == '.' or target[target.len - 1] == '.') return false;

    var previous_dot = false;
    for (target) |byte| {
        const is_lower = byte >= 'a' and byte <= 'z';
        const is_digit = byte >= '0' and byte <= '9';
        const is_dash = byte == '-';
        const is_dot = byte == '.';
        if (!is_lower and !is_digit and !is_dash and !is_dot) return false;
        if (is_dot and previous_dot) return false;
        previous_dot = is_dot;
    }
    return std.mem.indexOfScalar(u8, target, '.') != null;
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

test "compact network policy metadata preserves exact text capacities" {
    const full_label = [_]u8{'l'} ** MAX_LABEL_BYTES;
    const full_target = [_]u8{'t'} ** MAX_TARGET_BYTES;
    var directory = Directory.init();
    const policy = try directory.create(.{
        .owner = .{ .kind = .service, .serial = 79 },
        .label = &full_label,
        .mode = .named_service_identity,
        .target = &full_target,
    });

    try std.testing.expectEqual(@as(u8, MAX_LABEL_BYTES), policy.label_len);
    try std.testing.expectEqual(@as(u8, MAX_TARGET_BYTES), policy.target_len);
    try std.testing.expectEqualSlices(u8, &full_label, policy.labelSlice());
    try std.testing.expectEqualSlices(u8, &full_target, policy.targetSlice());
    try std.testing.expect((try directory.authorize(policy.id, .{ .service_identity = &full_target })).allowed);
}

test "network policy text rejects overlong values without publishing slots" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 80 };
    const oversized_label = [_]u8{'x'} ** (MAX_LABEL_BYTES + 1);
    const oversized_target = [_]u8{'a'} ** (MAX_TARGET_BYTES + 1);

    try std.testing.expectError(
        error.LabelTooLong,
        directory.create(.{
            .owner = owner,
            .label = oversized_label[0..],
            .mode = .local_network,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), directory.policies.countInUse());
    try std.testing.expect(directory.find(1) == null);

    try std.testing.expectError(
        error.TargetTooLong,
        directory.create(.{
            .owner = owner,
            .label = "egress",
            .mode = .named_service_identity,
            .target = oversized_target[0..],
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), directory.policies.countInUse());
    try std.testing.expect(directory.find(1) == null);

    const policy = try directory.create(.{
        .owner = owner,
        .label = "egress",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    });
    try std.testing.expectEqual(@as(u64, 1), policy.id);
    try std.testing.expectEqual(@as(usize, 1), directory.policies.countInUse());
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

test "network policy creation rejects misleading and malformed targets" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 90 };

    try std.testing.expectError(error.UnexpectedTarget, directory.create(.{
        .owner = owner,
        .label = "local-with-target",
        .mode = .local_network,
        .target = "printer",
    }));
    try std.testing.expectError(error.DomainTargetInvalid, directory.create(.{
        .owner = owner,
        .label = "bad-domain",
        .mode = .named_domain,
        .target = "HTTPS://Relay.Zigos.Dev/path",
    }));
    try std.testing.expectError(error.EmptyAttestationPin, directory.create(.{
        .owner = owner,
        .label = "empty-root-pin",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .pinned_root_digest = crypto_hash.zero_digest,
    }));
    try std.testing.expectError(error.EmptyAttestationPin, directory.create(.{
        .owner = owner,
        .label = "empty-metadata-pin",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .pinned_attestation_verifier_metadata_digest = crypto_hash.zero_digest,
    }));
}

test "network policy connections can require remote attestation and pinned service identities" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 10 };
    const pinned_digest = crypto_hash.digestFromByte(0xAB);
    const request_digest = crypto_hash.digestFromByte(0xAC);
    const metadata_digest = crypto_hash.digestFromByte(0xAD);
    const policy = try directory.create(.{
        .owner = owner,
        .label = "notes-overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
    });

    try std.testing.expectEqual(DecisionReason.attestation_required, (try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
    })).reason);
    try std.testing.expectEqual(DecisionReason.attestation_required, (try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .peer_root_digest_present = true,
        .peer_root_digest = pinned_digest,
    })).reason);
    try std.testing.expectEqual(DecisionReason.identity_pin_mismatch, (try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .verified_remote_attestation = true,
        .attestation_request_digest_present = true,
        .attestation_request_digest = request_digest,
        .peer_root_digest_present = true,
        .peer_root_digest = crypto_hash.digestFromByte(0xCD),
        .attestation_verifier_metadata_digest_present = true,
        .attestation_verifier_metadata_digest_bound = true,
        .attestation_verifier_metadata_digest = metadata_digest,
    })).reason);

    try std.testing.expectEqual(DecisionReason.identity_pin_mismatch, (try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .verified_remote_attestation = true,
        .attestation_request_digest_present = true,
        .attestation_request_digest = request_digest,
        .peer_root_digest_present = true,
        .peer_root_digest = pinned_digest,
    })).reason);

    const decision = try directory.authorizeConnection(policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .verified_remote_attestation = true,
        .attestation_request_digest_present = true,
        .attestation_request_digest = request_digest,
        .peer_root_digest_present = true,
        .peer_root_digest = pinned_digest,
        .attestation_verifier_metadata_digest_present = true,
        .attestation_verifier_metadata_digest_bound = true,
        .attestation_verifier_metadata_digest = metadata_digest,
    });
    try std.testing.expect(decision.allowed);
    try std.testing.expect(decision.attestation_required);
    try std.testing.expect(decision.identity_pinned);
}

test "network policy creation is idempotent for identical requests" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 11 };
    const pinned_digest = crypto_hash.digestFromByte(0xBC);
    const metadata_digest = crypto_hash.digestFromByte(0xBD);

    const first = try directory.create(.{
        .owner = owner,
        .workspace_id = 91,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
    });
    const second = try directory.create(.{
        .owner = owner,
        .workspace_id = 91,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
    });

    try std.testing.expectEqual(first.id, second.id);
}

fn paddedLabel(text: []const u8) [MAX_LABEL_BYTES]u8 {
    var buffer = [_]u8{0} ** MAX_LABEL_BYTES;
    @memcpy(buffer[0..text.len], text);
    return buffer;
}

fn paddedTarget(text: []const u8) [MAX_TARGET_BYTES]u8 {
    var buffer = [_]u8{0} ** MAX_TARGET_BYTES;
    @memcpy(buffer[0..text.len], text);
    return buffer;
}

test "network policy indexes rebuild after persisted slots are loaded" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 12 };
    const pinned_digest = crypto_hash.digestFromByte(0xDE);
    const metadata_digest = crypto_hash.digestFromByte(0xDF);

    directory.policies.slots[3] = .{
        .in_use = true,
        .policy = .{
            .id = 44,
            .owner = owner,
            .workspace_id = 91,
            .label_len = 7,
            .label = paddedLabel("overlay"),
            .mode = .named_service_identity,
            .target_len = 18,
            .target = paddedTarget("overlay.notes.sync"),
            .explicit_internet_grant = false,
            .require_remote_attestation = true,
            .pinned_root_digest_present = true,
            .pinned_root_digest = pinned_digest,
            .pinned_attestation_verifier_metadata_digest_present = true,
            .pinned_attestation_verifier_metadata_digest = metadata_digest,
        },
    };
    directory.next_policy_id = 45;
    directory.rebuildIndexes();

    const found = directory.find(44).?;
    try std.testing.expectEqual(@as(u64, 44), found.id);
    try std.testing.expectEqualStrings("overlay", found.labelSlice());

    const duplicate = try directory.create(.{
        .owner = owner,
        .workspace_id = 91,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
    });
    try std.testing.expectEqual(@as(u64, 44), duplicate.id);
}

test "egress broker requires a usable network policy capability before connecting" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 12 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 12 };

    const relay = try directory.create(.{
        .owner = owner,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    });
    const local = try directory.create(.{
        .owner = owner,
        .label = "local",
        .mode = .local_network,
    });

    var capabilities = capability.CapabilityTable.init();
    const remote_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = relay.id },
        .rights = .{ .network_policy = .{
            .capability_derive = true,
            .network_remote = true,
        } },
        .scope = .{
            .task_id = 701,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
    });
    const stale_remote_capability = try capabilities.derive(.{
        .parent_capability_id = remote_capability.id,
        .holder = app,
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = remote_capability.scope,
        .lease = .{
            .issued_at_ticks = 1,
            .expires_at_ticks = 90,
        },
    });
    const local_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = local.id },
        .rights = .{ .network_policy = .{
            .network_local = true,
        } },
        .scope = .{
            .task_id = 701,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
    });

    var broker = EgressBroker.init(&directory, &capabilities);
    const allowed = try broker.connect(.{
        .task_id = 701,
        .principal_id = app,
        .capability_id = remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 10,
    });
    try std.testing.expect(allowed.allowed);
    try std.testing.expectEqual(PolicyMode.named_domain, allowed.policy_decision.matched_mode);

    const zero_tick = try broker.connect(.{
        .task_id = 701,
        .principal_id = app,
        .capability_id = remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 0,
    });
    try std.testing.expect(!zero_tick.allowed);
    try std.testing.expectEqual(EgressDecisionReason.invalid_request, zero_tick.reason);

    const zero_task = try broker.connect(.{
        .task_id = 0,
        .principal_id = app,
        .capability_id = remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!zero_task.allowed);
    try std.testing.expectEqual(EgressDecisionReason.invalid_request, zero_task.reason);

    const zero_principal = try broker.connect(.{
        .task_id = 701,
        .principal_id = .{ .kind = .app, .serial = 0 },
        .capability_id = remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!zero_principal.allowed);
    try std.testing.expectEqual(EgressDecisionReason.invalid_request, zero_principal.reason);

    const wrong_domain = try broker.connect(.{
        .task_id = 701,
        .principal_id = app,
        .capability_id = remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "example.com" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!wrong_domain.allowed);
    try std.testing.expectEqual(EgressDecisionReason.destination_mismatch, wrong_domain.reason);

    const wrong_task = try broker.connect(.{
        .task_id = 702,
        .principal_id = app,
        .capability_id = remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!wrong_task.allowed);
    try std.testing.expectEqual(EgressDecisionReason.scope_violation, wrong_task.reason);

    const wrong_policy = try broker.connect(.{
        .task_id = 701,
        .principal_id = app,
        .capability_id = local_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!wrong_policy.allowed);
    try std.testing.expectEqual(EgressDecisionReason.target_mismatch, wrong_policy.reason);

    try capabilities.revokeTargetAuthority(remote_capability.id);
    const revoked = try broker.connect(.{
        .task_id = 701,
        .principal_id = app,
        .capability_id = stale_remote_capability.id,
        .policy_id = relay.id,
        .evidence = .{ .destination = .{ .domain = "relay.zigos.dev" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!revoked.allowed);
    try std.testing.expectEqual(EgressDecisionReason.capability_revoked, revoked.reason);
}

test "egress broker binds connection creation to attested pinned service identity" {
    var directory = Directory.init();
    const owner = principal.PrincipalId{ .kind = .service, .serial = 13 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 13 };
    const pinned_digest = crypto_hash.digestFromByte(0xD1);
    const wrong_digest = crypto_hash.digestFromByte(0xD2);
    const request_digest = crypto_hash.digestFromByte(0xD3);
    const metadata_digest = crypto_hash.digestFromByte(0xD4);

    const overlay = try directory.create(.{
        .owner = owner,
        .label = "notes-overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = pinned_digest,
        .pinned_attestation_verifier_metadata_digest = metadata_digest,
    });
    var capabilities = capability.CapabilityTable.init();
    const overlay_capability = try capabilities.mintBootRoot(.{
        .holder = app,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .network_policy, .id = overlay.id },
        .rights = .{ .network_policy = .{
            .network_remote = true,
        } },
        .scope = .{
            .task_id = 801,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
    });
    var broker = EgressBroker.init(&directory, &capabilities);

    const missing_attestation = try broker.connect(.{
        .task_id = 801,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{ .destination = .{ .service_identity = "overlay.notes.sync" } },
        .now_ticks = 10,
    });
    try std.testing.expect(!missing_attestation.allowed);
    try std.testing.expectEqual(EgressDecisionReason.attestation_required, missing_attestation.reason);

    const wrong_identity = try broker.connect(.{
        .task_id = 801,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.notes.sync" },
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = wrong_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
        },
        .now_ticks = 10,
    });
    try std.testing.expect(!wrong_identity.allowed);
    try std.testing.expectEqual(EgressDecisionReason.identity_pin_mismatch, wrong_identity.reason);

    const wrong_service = try broker.connect(.{
        .task_id = 801,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.other" },
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
        },
        .now_ticks = 10,
    });
    try std.testing.expect(!wrong_service.allowed);
    try std.testing.expectEqual(EgressDecisionReason.destination_mismatch, wrong_service.reason);

    const allowed = try broker.connect(.{
        .task_id = 801,
        .principal_id = app,
        .capability_id = overlay_capability.id,
        .policy_id = overlay.id,
        .evidence = .{
            .destination = .{ .service_identity = "overlay.notes.sync" },
            .attested = true,
            .verified_remote_attestation = true,
            .attestation_request_digest_present = true,
            .attestation_request_digest = request_digest,
            .peer_root_digest_present = true,
            .peer_root_digest = pinned_digest,
            .attestation_verifier_metadata_digest_present = true,
            .attestation_verifier_metadata_digest_bound = true,
            .attestation_verifier_metadata_digest = metadata_digest,
        },
        .now_ticks = 10,
    });
    try std.testing.expect(allowed.allowed);
    try std.testing.expect(allowed.policy_decision.attestation_required);
    try std.testing.expect(allowed.policy_decision.identity_pinned);
}
