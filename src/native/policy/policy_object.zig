const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_ALLOW_LIST: usize = 8;
pub const MAX_LABEL_BYTES: usize = 64;
const POLICY_INDEX_CAPACITY: usize = MAX_POLICIES * 2;

pub const Scope = enum(u8) {
    user,
    device,
    workspace,
    organization,
};

pub const InstallSourceMode = enum(u8) {
    any_signed,
    trusted_sources,
    platform_store_only,
};

pub const NetworkEgressMode = enum(u8) {
    inherit,
    none,
    local_only,
    allow_list,
    unrestricted,
};

pub const SubjectSet = struct {
    user_id: ?u64 = null,
    device_id: ?u64 = null,
    workspace_id: ?u64 = null,
    organization_id: ?u64 = null,
};

pub const DecisionReason = enum(u8) {
    none,
    unsigned_policy,
    install_source_denied,
    sync_destination_denied,
    removable_storage_denied,
    screen_capture_denied,
};

pub const PolicyDecision = struct {
    allowed: bool,
    reason: DecisionReason = .none,
    blocking_scope: ?Scope = null,
    blocking_policy_id: u64 = 0,
    blocking_generation: u32 = 0,
};

pub const CreateRequest = struct {
    scope: Scope,
    subject_id: u64,
    issuer: principal.PrincipalId,
    label: []const u8,
    install_source_mode: InstallSourceMode = .any_signed,
    allowed_install_sources: []const []const u8 = &.{},
    network_egress_mode: NetworkEgressMode = .inherit,
    allowed_sync_destinations: []const []const u8 = &.{},
    removable_storage_allowed: bool = false,
    screen_capture_allowed: bool = false,
    retention_days: u16 = 0,
    audit_export_required: bool = false,
};

pub const PolicyObject = struct {
    id: u64,
    generation: u32,
    scope: Scope,
    subject_id: u64,
    issuer: principal.PrincipalId,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    install_source_mode: InstallSourceMode,
    allowed_install_source_count: usize,
    allowed_install_sources: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_install_source_lens: [MAX_ALLOW_LIST]usize,
    network_egress_mode: NetworkEgressMode,
    allowed_sync_destination_count: usize,
    allowed_sync_destinations: [MAX_ALLOW_LIST][MAX_LABEL_BYTES]u8,
    allowed_sync_destination_lens: [MAX_ALLOW_LIST]usize,
    removable_storage_allowed: bool,
    screen_capture_allowed: bool,
    retention_days: u16,
    audit_export_required: bool,
    signature: manifest.Signature,

    pub fn labelSlice(self: *const PolicyObject) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn allowsInstallSource(self: *const PolicyObject, source_identity: []const u8) bool {
        return switch (self.install_source_mode) {
            .any_signed => true,
            .trusted_sources => listContains(
                self.allowed_install_sources[0..self.allowed_install_source_count],
                self.allowed_install_source_lens[0..self.allowed_install_source_count],
                source_identity,
            ),
            .platform_store_only => std.mem.startsWith(u8, source_identity, "store:") or listContains(
                self.allowed_install_sources[0..self.allowed_install_source_count],
                self.allowed_install_source_lens[0..self.allowed_install_source_count],
                source_identity,
            ),
        };
    }

    pub fn allowsSyncDestination(self: *const PolicyObject, destination: []const u8) bool {
        if (self.allowed_sync_destination_count == 0) {
            return switch (self.network_egress_mode) {
                .inherit, .unrestricted => true,
                .local_only => isLocalDestination(destination),
                .none, .allow_list => false,
            };
        }
        return listContains(
            self.allowed_sync_destinations[0..self.allowed_sync_destination_count],
            self.allowed_sync_destination_lens[0..self.allowed_sync_destination_count],
            destination,
        );
    }
};

pub const Error = error{
    InstallSourceTooLong,
    LabelTooLong,
    PolicyTableFull,
    SyncDestinationTooLong,
    TooManyInstallSources,
    TooManySyncDestinations,
};

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyObject = zeroPolicy(),
};

const PolicyIdIndex = indexed_arena.UniqueIndex(POLICY_INDEX_CAPACITY);
const PolicyScopeIndex = indexed_arena.MultimapIndex(MAX_POLICIES, MAX_POLICIES, POLICY_INDEX_CAPACITY);

pub const Directory = struct {
    next_policy_id: u64 = 1,
    slots: [MAX_POLICIES]PolicySlot = [_]PolicySlot{PolicySlot{}} ** MAX_POLICIES,
    policy_id_index: PolicyIdIndex = PolicyIdIndex.init(),
    scope_index: PolicyScopeIndex = PolicyScopeIndex.init(),

    pub fn init() Directory {
        return .{};
    }

    pub fn create(
        self: *Directory,
        request: CreateRequest,
        signer: signing.SignerIdentity,
    ) (Error || anyerror)!*PolicyObject {
        if (request.allowed_install_sources.len > MAX_ALLOW_LIST) return error.TooManyInstallSources;
        if (request.allowed_sync_destinations.len > MAX_ALLOW_LIST) return error.TooManySyncDestinations;

        const slot_index = self.firstFreeSlotIndex() orelse return error.PolicyTableFull;
        const slot = &self.slots[slot_index];
        slot.in_use = true;
        errdefer slot.* = .{};
        slot.policy = zeroPolicy();
        slot.policy.id = self.next_policy_id;
        self.next_policy_id += 1;
        slot.policy.generation = nextGeneration(self, request.scope, request.subject_id);
        slot.policy.scope = request.scope;
        slot.policy.subject_id = request.subject_id;
        slot.policy.issuer = request.issuer;
        slot.policy.label_len = native_util.copyTextExact(&slot.policy.label, request.label) catch return error.LabelTooLong;
        slot.policy.install_source_mode = request.install_source_mode;
        slot.policy.network_egress_mode = request.network_egress_mode;
        slot.policy.removable_storage_allowed = request.removable_storage_allowed;
        slot.policy.screen_capture_allowed = request.screen_capture_allowed;
        slot.policy.retention_days = request.retention_days;
        slot.policy.audit_export_required = request.audit_export_required;

        for (request.allowed_install_sources, 0..) |source_identity, index| {
            slot.policy.allowed_install_source_lens[index] = native_util.copyTextExact(&slot.policy.allowed_install_sources[index], source_identity) catch return error.InstallSourceTooLong;
            slot.policy.allowed_install_source_count += 1;
        }
        for (request.allowed_sync_destinations, 0..) |destination, index| {
            slot.policy.allowed_sync_destination_lens[index] = native_util.copyTextExact(&slot.policy.allowed_sync_destinations[index], destination) catch return error.SyncDestinationTooLong;
            slot.policy.allowed_sync_destination_count += 1;
        }

        const digest = policyDigest(&slot.policy);
        slot.policy.signature = try signing.sign(signer, &digest);
        self.indexPolicy(slot_index);
        return &slot.policy;
    }

    pub fn activeForScope(self: *Directory, scope: Scope, subject_id: u64) ?*PolicyObject {
        var candidate: ?*PolicyObject = null;
        var best_generation: u32 = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }

    pub fn verify(self: *const Directory, policy_id: u64) bool {
        const policy = self.findConst(policy_id) orelse return false;
        const digest = policyDigest(policy);
        return signing.verify(policy.signature, &digest);
    }

    pub fn installSourceAllowed(
        self: *const Directory,
        scope: Scope,
        subject_id: u64,
        source_identity: []const u8,
    ) bool {
        const policy = self.activeForScopeConst(scope, subject_id) orelse return true;
        if (!self.verify(policy.id)) return false;
        return policy.allowsInstallSource(source_identity);
    }

    pub fn syncDestinationAllowed(
        self: *const Directory,
        scope: Scope,
        subject_id: u64,
        destination: []const u8,
    ) bool {
        const policy = self.activeForScopeConst(scope, subject_id) orelse return true;
        if (!self.verify(policy.id)) return false;
        return policy.allowsSyncDestination(destination);
    }

    pub fn installSourceDecision(
        self: *const Directory,
        subjects: SubjectSet,
        source_identity: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsInstallSource(source_identity)) {
                return block(policy, .install_source_denied);
            }
        }
        return allow();
    }

    pub fn syncDestinationDecision(
        self: *const Directory,
        subjects: SubjectSet,
        destination: []const u8,
    ) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.allowsSyncDestination(destination)) {
                return block(policy, .sync_destination_denied);
            }
        }
        return allow();
    }

    pub fn removableStorageDecision(self: *const Directory, subjects: SubjectSet) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.removable_storage_allowed) return block(policy, .removable_storage_denied);
        }
        return allow();
    }

    pub fn screenCaptureDecision(self: *const Directory, subjects: SubjectSet) PolicyDecision {
        var iter = self.activePolicyIterator(subjects);
        while (iter.next()) |policy| {
            const signature_decision = self.requireVerified(policy);
            if (!signature_decision.allowed) return signature_decision;
            if (!policy.screen_capture_allowed) return block(policy, .screen_capture_denied);
        }
        return allow();
    }

    fn findConst(self: *const Directory, policy_id: u64) ?*const PolicyObject {
        if (policy_id == 0) return null;
        const slot_index = self.policy_id_index.lookup(policy_id) orelse return null;
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("policy id index points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.policy.id != policy_id) native_util.impossibleByInvariant("policy id index points at the wrong policy");
        return &slot.policy;
    }

    fn activeForScopeConst(self: *const Directory, scope: Scope, subject_id: u64) ?*const PolicyObject {
        var candidate: ?*const PolicyObject = null;
        var best_generation: u32 = 0;
        var cursor = self.scope_index.head(policyScopeKey(scope, subject_id));
        while (cursor != indexed_arena.no_index) : (cursor = self.scope_index.next(cursor)) {
            if (cursor >= MAX_POLICIES) native_util.impossibleByInvariant("policy scope index points outside slots");
            const slot = &self.slots[cursor];
            if (!slot.in_use) native_util.impossibleByInvariant("policy scope index points at a free slot");
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }

    fn activePolicyIterator(self: *const Directory, subjects: SubjectSet) ActivePolicyIterator {
        return .{
            .directory = self,
            .subjects = subjects,
        };
    }

    fn requireVerified(self: *const Directory, policy: *const PolicyObject) PolicyDecision {
        if (self.verify(policy.id)) return allow();
        return block(policy, .unsigned_policy);
    }

    fn firstFreeSlotIndex(self: *const Directory) ?usize {
        for (self.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) return slot_index;
        }
        return null;
    }

    fn indexPolicy(self: *Directory, slot_index: usize) void {
        if (slot_index >= MAX_POLICIES) native_util.impossibleByInvariant("policy index update points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.policy.id == 0) native_util.impossibleByInvariant("policy index update requires a live policy");
        self.policy_id_index.insert(slot.policy.id, slot_index);
        if (!self.scope_index.append(policyScopeKey(slot.policy.scope, slot.policy.subject_id), slot_index)) {
            native_util.impossibleByInvariant("policy scope index capacity covers policy slots");
        }
    }
};

const ActivePolicyIterator = struct {
    directory: *const Directory,
    subjects: SubjectSet,
    index: usize = 0,

    fn next(self: *ActivePolicyIterator) ?*const PolicyObject {
        while (self.index < 4) {
            const index = self.index;
            self.index += 1;
            switch (index) {
                0 => if (self.subjects.organization_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.organization, subject_id)) |policy| return policy;
                },
                1 => if (self.subjects.user_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.user, subject_id)) |policy| return policy;
                },
                2 => if (self.subjects.device_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.device, subject_id)) |policy| return policy;
                },
                3 => if (self.subjects.workspace_id) |subject_id| {
                    if (self.directory.activeForScopeConst(.workspace, subject_id)) |policy| return policy;
                },
                else => {},
            }
        }
        return null;
    }
};

fn allow() PolicyDecision {
    return .{ .allowed = true };
}

fn block(policy: *const PolicyObject, reason: DecisionReason) PolicyDecision {
    return .{
        .allowed = false,
        .reason = reason,
        .blocking_scope = policy.scope,
        .blocking_policy_id = policy.id,
        .blocking_generation = policy.generation,
    };
}

fn zeroPolicy() PolicyObject {
    return .{
        .id = 0,
        .generation = 0,
        .scope = .user,
        .subject_id = 0,
        .issuer = .{ .kind = .policy_authority, .serial = 0 },
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .install_source_mode = .any_signed,
        .allowed_install_source_count = 0,
        .allowed_install_sources = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_install_source_lens = [_]usize{0} ** MAX_ALLOW_LIST,
        .network_egress_mode = .inherit,
        .allowed_sync_destination_count = 0,
        .allowed_sync_destinations = [_][MAX_LABEL_BYTES]u8{[_]u8{0} ** MAX_LABEL_BYTES} ** MAX_ALLOW_LIST,
        .allowed_sync_destination_lens = [_]usize{0} ** MAX_ALLOW_LIST,
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .retention_days = 0,
        .audit_export_required = false,
        .signature = .{},
    };
}

fn nextGeneration(self: *const Directory, scope: Scope, subject_id: u64) u32 {
    const active = self.activeForScopeConst(scope, subject_id) orelse return 1;
    return active.generation + 1;
}

fn policyScopeKey(scope: Scope, subject_id: u64) u64 {
    var bytes: [9]u8 = undefined;
    bytes[0] = @intFromEnum(scope);
    std.mem.writeInt(u64, bytes[1..9], subject_id, .little);
    return indexed_arena.nonZeroKey(std.hash.Wyhash.hash(0x5A47_504F_4C53_434F, &bytes));
}

fn policyDigest(policy: *const PolicyObject) [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "scope", policy.scope);
    crypto_hash.updateEnum(&hasher, "issuer-kind", policy.issuer.kind);
    crypto_hash.updateInt(&hasher, "subject-id", policy.subject_id);
    crypto_hash.updateInt(&hasher, "issuer-serial", policy.issuer.serial);
    crypto_hash.updateBytes(&hasher, "label", policy.labelSlice());
    crypto_hash.updateEnum(&hasher, "install-source-mode", policy.install_source_mode);
    crypto_hash.updateEnum(&hasher, "network-egress-mode", policy.network_egress_mode);
    crypto_hash.updateBool(&hasher, "removable-storage-allowed", policy.removable_storage_allowed);
    crypto_hash.updateBool(&hasher, "screen-capture-allowed", policy.screen_capture_allowed);
    crypto_hash.updateInt(&hasher, "retention-days", policy.retention_days);
    crypto_hash.updateBool(&hasher, "audit-export-required", policy.audit_export_required);

    var allow_index: usize = 0;
    while (allow_index < policy.allowed_install_source_count) : (allow_index += 1) {
        crypto_hash.updateInt(&hasher, "install-source-index", allow_index);
        crypto_hash.updateBytes(&hasher, "install-source", policy.allowed_install_sources[allow_index][0..policy.allowed_install_source_lens[allow_index]]);
    }
    var sync_index: usize = 0;
    while (sync_index < policy.allowed_sync_destination_count) : (sync_index += 1) {
        crypto_hash.updateInt(&hasher, "sync-destination-index", sync_index);
        crypto_hash.updateBytes(&hasher, "sync-destination", policy.allowed_sync_destinations[sync_index][0..policy.allowed_sync_destination_lens[sync_index]]);
    }
    return crypto_hash.finalize(&hasher);
}

fn listContains(items: []const [MAX_LABEL_BYTES]u8, lens: []const usize, needle: []const u8) bool {
    for (items, 0..) |item, index| {
        if (std.mem.eql(u8, item[0..lens[index]], needle)) return true;
    }
    return false;
}

fn isLocalDestination(destination: []const u8) bool {
    return std.mem.startsWith(u8, destination, "local:") or
        std.mem.startsWith(u8, destination, "lan.") or
        std.mem.eql(u8, destination, "local-network");
}

test "policy objects remain signed scoped and enforce enterprise controls" {
    var directory = Directory.init();
    const policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "corp-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp-apps" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{ "relay.corp.example", "overlay.corp.example" },
        .removable_storage_allowed = false,
        .screen_capture_allowed = true,
        .retention_days = 365,
        .audit_export_required = true,
    }, .{
        .label = "corp-policy-key",
        .seed = [_]u8{0x81} ** 32,
    });

    try std.testing.expectEqual(@as(u32, 1), policy.generation);
    try std.testing.expectEqualStrings("corp-defaults", policy.labelSlice());
    try std.testing.expect(directory.verify(policy.id));
    try std.testing.expect(directory.installSourceAllowed(.organization, 77, "store:zigos"));
    try std.testing.expect(!directory.installSourceAllowed(.organization, 77, "repo:unknown"));
    try std.testing.expect(directory.syncDestinationAllowed(.organization, 77, "relay.corp.example"));
    try std.testing.expect(!directory.syncDestinationAllowed(.organization, 77, "relay.personal.example"));
    try std.testing.expect(!policy.removable_storage_allowed);
    try std.testing.expect(policy.screen_capture_allowed);
    try std.testing.expect(policy.audit_export_required);
    try std.testing.expectEqual(@as(u16, 365), policy.retention_days);

    _ = try directory.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "corp-tightened",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
    }, .{
        .label = "corp-policy-key",
        .seed = [_]u8{0x81} ** 32,
    });
    const latest = directory.activeForScope(.organization, 77).?;
    try std.testing.expectEqual(@as(u32, 2), latest.generation);
    try std.testing.expect(latest.allowsInstallSource("store:zigos"));
    try std.testing.expect(!latest.allowsInstallSource("repo:corp-apps"));
}

test "policy directory composes active user device workspace and organization policy" {
    var directory = Directory.init();
    const signer = signing.SignerIdentity{
        .label = "policy-compose-key",
        .seed = [_]u8{0x83} ** 32,
    };
    const org_policy = try directory.create(.{
        .scope = .organization,
        .subject_id = 7,
        .issuer = .{ .kind = .policy_authority, .serial = 7 },
        .label = "org-baseline",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .screen_capture_allowed = false,
    }, signer);
    _ = try directory.create(.{
        .scope = .user,
        .subject_id = 70,
        .issuer = .{ .kind = .policy_authority, .serial = 8 },
        .label = "user-preferences",
        .install_source_mode = .any_signed,
        .network_egress_mode = .inherit,
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
    }, signer);
    const device_policy = try directory.create(.{
        .scope = .device,
        .subject_id = 701,
        .issuer = .{ .kind = .policy_authority, .serial = 9 },
        .label = "device-hardening",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = true,
    }, signer);
    _ = try directory.create(.{
        .scope = .workspace,
        .subject_id = 9_001,
        .issuer = .{ .kind = .policy_authority, .serial = 10 },
        .label = "workspace-sync",
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{ "relay.corp.example", "overlay.project.example" },
        .removable_storage_allowed = true,
        .screen_capture_allowed = true,
    }, signer);

    const subjects = SubjectSet{
        .user_id = 70,
        .device_id = 701,
        .workspace_id = 9_001,
        .organization_id = 7,
    };
    const store_decision = directory.installSourceDecision(subjects, "store:zigos");
    try std.testing.expect(store_decision.allowed);

    const corp_repo_decision = directory.installSourceDecision(subjects, "repo:corp");
    try std.testing.expect(!corp_repo_decision.allowed);
    try std.testing.expectEqual(DecisionReason.install_source_denied, corp_repo_decision.reason);
    try std.testing.expectEqual(Scope.device, corp_repo_decision.blocking_scope.?);
    try std.testing.expectEqual(device_policy.id, corp_repo_decision.blocking_policy_id);

    const relay_decision = directory.syncDestinationDecision(subjects, "relay.corp.example");
    try std.testing.expect(relay_decision.allowed);
    const overlay_decision = directory.syncDestinationDecision(subjects, "overlay.project.example");
    try std.testing.expect(!overlay_decision.allowed);
    try std.testing.expectEqual(DecisionReason.sync_destination_denied, overlay_decision.reason);
    try std.testing.expectEqual(Scope.organization, overlay_decision.blocking_scope.?);

    const removable_decision = directory.removableStorageDecision(subjects);
    try std.testing.expect(!removable_decision.allowed);
    try std.testing.expectEqual(Scope.organization, removable_decision.blocking_scope.?);

    const screen_decision = directory.screenCaptureDecision(subjects);
    try std.testing.expect(!screen_decision.allowed);
    try std.testing.expectEqual(org_policy.id, screen_decision.blocking_policy_id);

    const tightened_org = try directory.create(.{
        .scope = .organization,
        .subject_id = 7,
        .issuer = .{ .kind = .policy_authority, .serial = 7 },
        .label = "org-store-only",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
        .network_egress_mode = .none,
    }, signer);
    const next_overlay_decision = directory.syncDestinationDecision(subjects, "relay.corp.example");
    try std.testing.expect(!next_overlay_decision.allowed);
    try std.testing.expectEqual(tightened_org.id, next_overlay_decision.blocking_policy_id);
    try std.testing.expectEqual(@as(u32, 2), next_overlay_decision.blocking_generation);
}

test "policy objects reject oversized lists and refuse authorization after tampering" {
    var directory = Directory.init();
    const too_many = [_][]const u8{
        "a", "b", "c", "d", "e", "f", "g", "h", "i",
    };
    try std.testing.expectError(error.TooManyInstallSources, directory.create(.{
        .scope = .user,
        .subject_id = 5,
        .issuer = .{ .kind = .policy_authority, .serial = 2 },
        .label = "overflow",
        .allowed_install_sources = &too_many,
    }, .{
        .label = "policy-key",
        .seed = [_]u8{0x52} ** 32,
    }));

    const policy = try directory.create(.{
        .scope = .device,
        .subject_id = 8,
        .issuer = .{ .kind = .policy_authority, .serial = 3 },
        .label = "signed-device-policy",
        .install_source_mode = .platform_store_only,
        .allowed_install_sources = &.{"store:zigos"},
    }, .{
        .label = "device-policy-key",
        .seed = [_]u8{0x53} ** 32,
    });
    try std.testing.expect(directory.verify(policy.id));

    policy.signature.value[0] ^=
        0x5A;
    try std.testing.expect(!directory.verify(policy.id));
    try std.testing.expect(!directory.installSourceAllowed(.device, 8, "store:zigos"));
}
