const std = @import("std");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const MAX_ENVIRONMENTS: usize = 8;
pub const MAX_PORTALS_PER_ENVIRONMENT: usize = 8;
const ENVIRONMENT_INDEX_CAPACITY: usize = MAX_ENVIRONMENTS * 2;

pub const EnvironmentKind = enum(u8) {
    vm,
    container,
    emulation_layer,
    remote_application_session,
};

pub const EnvironmentState = enum(u8) {
    staged,
    active,
    terminated,
};

pub const NetworkClass = enum(u8) {
    none,
    local_only,
    named_service_only,
    restricted_internet,
};

pub const PortalKind = enum(u8) {
    file_import,
    file_export,
    clipboard_bridge,
    open_uri,
    collaboration_session,
};

pub const PortalGrant = struct {
    kind: PortalKind,
    capability_id: u64,
    read_only: bool = true,
    expires_at_ticks: u64 = 0,
};

pub const LaunchRequest = struct {
    service_id: u64,
    owner: principal.PrincipalId,
    kind: EnvironmentKind,
    label: []const u8,
    bundle: manifest.BundleManifest,
    network_class: NetworkClass = .none,
    isolated: bool = true,
    clearly_labeled: bool = true,
    portal_only_host_access: bool = true,
};

pub const EnvironmentRecord = struct {
    id: u64,
    service_id: u64,
    owner: principal.PrincipalId,
    kind: EnvironmentKind,
    state: EnvironmentState,
    network_class: NetworkClass,
    isolated: bool,
    clearly_labeled: bool,
    portal_only_host_access: bool,
    limited_host_integration: bool,
    label_len: usize,
    label: [48]u8,
    signer_len: usize,
    signer: [32]u8,
    portal_count: usize,
    portals: [MAX_PORTALS_PER_ENVIRONMENT]PortalGrant,

    pub fn labelSlice(self: *const EnvironmentRecord) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn signerSlice(self: *const EnvironmentRecord) []const u8 {
        return self.signer[0..self.signer_len];
    }

    pub fn hasPortal(self: *const EnvironmentRecord, kind: PortalKind) bool {
        for (self.portals[0..self.portal_count]) |portal| {
            if (portal.kind == kind) return true;
        }
        return false;
    }
};

pub const Error = error{
    EnvironmentTableFull,
    PortalTableFull,
    EnvironmentNotFound,
    EmptyLabel,
    InvalidBundleSignature,
    DirectHostAccessForbidden,
    HiddenEnvironmentForbidden,
    IsolationRequired,
    InvalidPortalCapability,
    LabelTooLong,
    SignerTooLong,
};

const EnvironmentSlot = struct {
    in_use: bool = false,
    environment: EnvironmentRecord = zeroEnvironment(),
};

const EnvironmentIdIndex = indexed_arena.UniqueIndex(ENVIRONMENT_INDEX_CAPACITY);

pub const Manager = struct {
    next_environment_id: u64 = 1,
    slots: [MAX_ENVIRONMENTS]EnvironmentSlot = [_]EnvironmentSlot{EnvironmentSlot{}} ** MAX_ENVIRONMENTS,
    environment_id_index: EnvironmentIdIndex = EnvironmentIdIndex.init(),
    active_count: usize = 0,

    pub fn init() Manager {
        return .{};
    }

    pub fn launch(self: *Manager, request: LaunchRequest) Error!*EnvironmentRecord {
        if (request.label.len == 0) return error.EmptyLabel;
        if (request.bundle.signature.signer.len == 0) return error.InvalidBundleSignature;
        if (!request.portal_only_host_access) return error.DirectHostAccessForbidden;
        if (!request.clearly_labeled) return error.HiddenEnvironmentForbidden;
        if (!request.isolated) return error.IsolationRequired;

        const slot_index = self.firstFreeSlotIndex() orelse return error.EnvironmentTableFull;
        const slot = &self.slots[slot_index];
        slot.in_use = true;
        errdefer slot.* = .{};
        slot.environment = .{
            .id = self.allocateEnvironmentId(),
            .service_id = request.service_id,
            .owner = request.owner,
            .kind = request.kind,
            .state = .active,
            .network_class = request.network_class,
            .isolated = request.isolated,
            .clearly_labeled = request.clearly_labeled,
            .portal_only_host_access = request.portal_only_host_access,
            .limited_host_integration = true,
            .label_len = 0,
            .label = [_]u8{0} ** 48,
            .signer_len = 0,
            .signer = [_]u8{0} ** 32,
            .portal_count = 0,
            .portals = [_]PortalGrant{emptyPortal()} ** MAX_PORTALS_PER_ENVIRONMENT,
        };
        slot.environment.label_len = native_util.copyTextExact(slot.environment.label[0..], request.label) catch return error.LabelTooLong;
        slot.environment.signer_len = native_util.copyTextExact(slot.environment.signer[0..], request.bundle.signature.signer) catch return error.SignerTooLong;
        self.environment_id_index.insert(slot.environment.id, slot_index);
        self.active_count += 1;
        return &slot.environment;
    }

    pub fn find(self: *Manager, environment_id: u64) ?*EnvironmentRecord {
        if (environment_id == 0) return null;
        const slot_index = self.environment_id_index.lookup(environment_id) orelse return null;
        if (slot_index >= MAX_ENVIRONMENTS) native_util.impossibleByInvariant("compatibility environment id index points outside slots");
        const slot = &self.slots[slot_index];
        if (!slot.in_use or slot.environment.id != environment_id) {
            native_util.impossibleByInvariant("compatibility environment id index points at the wrong environment");
        }
        return &slot.environment;
    }

    pub fn grantPortal(self: *Manager, environment_id: u64, grant: PortalGrant) Error!void {
        if (grant.capability_id == 0) return error.InvalidPortalCapability;

        const environment = self.find(environment_id) orelse return error.EnvironmentNotFound;
        if (environment.portal_count >= environment.portals.len) return error.PortalTableFull;

        environment.portals[environment.portal_count] = grant;
        environment.portal_count += 1;
    }

    pub fn revokeExpiredPortals(self: *Manager, now_ticks: u64) usize {
        var revoked: usize = 0;
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;

            var kept_count: usize = 0;
            var read_index: usize = 0;
            while (read_index < slot.environment.portal_count) : (read_index += 1) {
                const grant = slot.environment.portals[read_index];
                if (grant.expires_at_ticks != 0 and grant.expires_at_ticks < now_ticks) {
                    revoked += 1;
                    continue;
                }
                slot.environment.portals[kept_count] = grant;
                kept_count += 1;
            }
            var clear_index = kept_count;
            while (clear_index < slot.environment.portals.len) : (clear_index += 1) {
                slot.environment.portals[clear_index] = emptyPortal();
            }
            slot.environment.portal_count = kept_count;
        }
        return revoked;
    }

    pub fn environmentCount(self: *const Manager) usize {
        return self.active_count;
    }

    fn allocateEnvironmentId(self: *Manager) u64 {
        defer self.next_environment_id += 1;
        return self.next_environment_id;
    }

    fn firstFreeSlotIndex(self: *const Manager) ?usize {
        for (self.slots, 0..) |slot, slot_index| {
            if (!slot.in_use) return slot_index;
        }
        return null;
    }
};

fn zeroEnvironment() EnvironmentRecord {
    return .{
        .id = 0,
        .service_id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .kind = .vm,
        .state = .staged,
        .network_class = .none,
        .isolated = true,
        .clearly_labeled = true,
        .portal_only_host_access = true,
        .limited_host_integration = true,
        .label_len = 0,
        .label = [_]u8{0} ** 48,
        .signer_len = 0,
        .signer = [_]u8{0} ** 32,
        .portal_count = 0,
        .portals = [_]PortalGrant{emptyPortal()} ** MAX_PORTALS_PER_ENVIRONMENT,
    };
}

fn emptyPortal() PortalGrant {
    return .{
        .kind = .file_import,
        .capability_id = 0,
        .read_only = true,
        .expires_at_ticks = 0,
    };
}

test "compatibility environments stay isolated labeled and portal-only" {
    var manager = Manager.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "compat.legacy.cad",
        .display_name = "Legacy CAD",
        .publisher = "zigos.dev",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-compat-key",
        },
    };

    const environment = try manager.launch(.{
        .service_id = 91,
        .owner = .{ .kind = .user, .serial = 7 },
        .kind = .vm,
        .label = "Legacy CAD VM",
        .bundle = bundle,
        .network_class = .named_service_only,
    });
    try std.testing.expect(environment.isolated);
    try std.testing.expect(environment.clearly_labeled);
    try std.testing.expect(environment.portal_only_host_access);
    try std.testing.expect(environment.limited_host_integration);
    try std.testing.expectEqualStrings("zigos-compat-key", environment.signerSlice());

    try manager.grantPortal(environment.id, .{
        .kind = .file_import,
        .capability_id = 41,
        .read_only = true,
        .expires_at_ticks = 80,
    });
    try manager.grantPortal(environment.id, .{
        .kind = .clipboard_bridge,
        .capability_id = 42,
        .read_only = false,
        .expires_at_ticks = 120,
    });
    try std.testing.expect(environment.hasPortal(.file_import));
    try std.testing.expect(environment.hasPortal(.clipboard_bridge));
    try std.testing.expectEqual(@as(usize, 1), manager.revokeExpiredPortals(100));
    try std.testing.expect(!environment.hasPortal(.file_import));
    try std.testing.expect(environment.hasPortal(.clipboard_bridge));
}

test "compatibility environments reject unsigned hidden or host-integrated launches" {
    var manager = Manager.init();
    const unsigned_bundle = manifest.BundleManifest{
        .bundle_id = "compat.legacy.db",
        .display_name = "Legacy DB",
        .publisher = "zigos.dev",
    };

    try std.testing.expectError(error.InvalidBundleSignature, manager.launch(.{
        .service_id = 92,
        .owner = .{ .kind = .user, .serial = 9 },
        .kind = .container,
        .label = "Legacy DB",
        .bundle = unsigned_bundle,
    }));

    const signed_bundle = manifest.BundleManifest{
        .bundle_id = "compat.legacy.erp",
        .display_name = "Legacy ERP",
        .publisher = "zigos.dev",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-compat-key",
        },
    };

    try std.testing.expectError(error.DirectHostAccessForbidden, manager.launch(.{
        .service_id = 93,
        .owner = .{ .kind = .user, .serial = 9 },
        .kind = .remote_application_session,
        .label = "ERP Remote Session",
        .bundle = signed_bundle,
        .portal_only_host_access = false,
    }));
    try std.testing.expectError(error.HiddenEnvironmentForbidden, manager.launch(.{
        .service_id = 93,
        .owner = .{ .kind = .user, .serial = 9 },
        .kind = .emulation_layer,
        .label = "DOS Game",
        .bundle = signed_bundle,
        .clearly_labeled = false,
    }));
    try std.testing.expectError(error.IsolationRequired, manager.launch(.{
        .service_id = 93,
        .owner = .{ .kind = .user, .serial = 9 },
        .kind = .container,
        .label = "Legacy Utility",
        .bundle = signed_bundle,
        .isolated = false,
    }));
}
