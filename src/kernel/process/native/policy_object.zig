const std = @import("std");
const manifest = @import("manifest.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");

pub const MAX_POLICIES: usize = 16;
pub const MAX_ALLOW_LIST: usize = 8;
pub const MAX_LABEL_BYTES: usize = 64;

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
            return self.network_egress_mode != .none;
        }
        return listContains(
            self.allowed_sync_destinations[0..self.allowed_sync_destination_count],
            self.allowed_sync_destination_lens[0..self.allowed_sync_destination_count],
            destination,
        );
    }
};

pub const Error = error{
    PolicyTableFull,
    TooManyInstallSources,
    TooManySyncDestinations,
};

const PolicySlot = struct {
    in_use: bool = false,
    policy: PolicyObject = zeroPolicy(),
};

pub const Directory = struct {
    next_policy_id: u64 = 1,
    slots: [MAX_POLICIES]PolicySlot = [_]PolicySlot{PolicySlot{}} ** MAX_POLICIES,

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

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;

            slot.in_use = true;
            slot.policy = zeroPolicy();
            slot.policy.id = self.next_policy_id;
            self.next_policy_id += 1;
            slot.policy.generation = nextGeneration(self, request.scope, request.subject_id);
            slot.policy.scope = request.scope;
            slot.policy.subject_id = request.subject_id;
            slot.policy.issuer = request.issuer;
            slot.policy.label_len = copyText(&slot.policy.label, request.label);
            slot.policy.install_source_mode = request.install_source_mode;
            slot.policy.network_egress_mode = request.network_egress_mode;
            slot.policy.removable_storage_allowed = request.removable_storage_allowed;
            slot.policy.screen_capture_allowed = request.screen_capture_allowed;
            slot.policy.retention_days = request.retention_days;
            slot.policy.audit_export_required = request.audit_export_required;

            for (request.allowed_install_sources, 0..) |source_identity, index| {
                slot.policy.allowed_install_source_lens[index] = copyText(&slot.policy.allowed_install_sources[index], source_identity);
                slot.policy.allowed_install_source_count += 1;
            }
            for (request.allowed_sync_destinations, 0..) |destination, index| {
                slot.policy.allowed_sync_destination_lens[index] = copyText(&slot.policy.allowed_sync_destinations[index], destination);
                slot.policy.allowed_sync_destination_count += 1;
            }

            const digest = policyDigest(&slot.policy);
            slot.policy.signature = try signing.sign(signer, &digest);
            return &slot.policy;
        }

        return error.PolicyTableFull;
    }

    pub fn activeForScope(self: *Directory, scope: Scope, subject_id: u64) ?*PolicyObject {
        var candidate: ?*PolicyObject = null;
        var best_generation: u32 = 0;
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
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

    fn findConst(self: *const Directory, policy_id: u64) ?*const PolicyObject {
        for (&self.slots) |*slot| {
            if (slot.in_use and slot.policy.id == policy_id) return &slot.policy;
        }
        return null;
    }

    fn activeForScopeConst(self: *const Directory, scope: Scope, subject_id: u64) ?*const PolicyObject {
        var candidate: ?*const PolicyObject = null;
        var best_generation: u32 = 0;
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
            if (slot.policy.generation < best_generation) continue;
            candidate = &slot.policy;
            best_generation = slot.policy.generation;
        }
        return candidate;
    }
};

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
    var best: u32 = 0;
    for (self.slots) |slot| {
        if (!slot.in_use) continue;
        if (slot.policy.scope != scope or slot.policy.subject_id != subject_id) continue;
        best = @max(best, slot.policy.generation);
    }
    return best + 1;
}

fn policyDigest(policy: *const PolicyObject) [32]u8 {
    var digest = [_]u8{0} ** 32;
    const seeds = [_]u64{
        0xCBF29CE484222325,
        0x9E3779B185EBCA87,
        0xD6E8FEB86659FD93,
        0x94D049BB133111EB,
    };
    for (seeds, 0..) |seed, index| {
        var hash = seed;
        hash = hashByte(hash, @intFromEnum(policy.scope));
        hash = hashByte(hash, @intFromEnum(policy.issuer.kind));
        hash = hashU64(hash, policy.subject_id);
        hash = hashU64(hash, policy.issuer.serial);
        hash = hashBytes(hash, policy.labelSlice());
        hash = hashByte(hash, @intFromEnum(policy.install_source_mode));
        hash = hashByte(hash, @intFromEnum(policy.network_egress_mode));
        hash = hashByte(hash, if (policy.removable_storage_allowed) 1 else 0);
        hash = hashByte(hash, if (policy.screen_capture_allowed) 1 else 0);
        hash = hashU64(hash, policy.retention_days);
        hash = hashByte(hash, if (policy.audit_export_required) 1 else 0);

        var allow_index: usize = 0;
        while (allow_index < policy.allowed_install_source_count) : (allow_index += 1) {
            hash = hashBytes(hash, policy.allowed_install_sources[allow_index][0..policy.allowed_install_source_lens[allow_index]]);
        }
        var sync_index: usize = 0;
        while (sync_index < policy.allowed_sync_destination_count) : (sync_index += 1) {
            hash = hashBytes(hash, policy.allowed_sync_destinations[sync_index][0..policy.allowed_sync_destination_lens[sync_index]]);
        }
        std.mem.writeInt(u64, digest[index * 8 ..][0..8], hash, .little);
    }
    return digest;
}

fn listContains(items: []const [MAX_LABEL_BYTES]u8, lens: []const usize, needle: []const u8) bool {
    for (items, 0..) |item, index| {
        if (std.mem.eql(u8, item[0..lens[index]], needle)) return true;
    }
    return false;
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

fn hashBytes(start: u64, bytes: []const u8) u64 {
    var hash = start;
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return hash;
}

fn hashByte(start: u64, byte: u8) u64 {
    return hashBytes(start, &.{byte});
}

fn hashU64(start: u64, value: u64) u64 {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, value, .little);
    return hashBytes(start, &buffer);
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
