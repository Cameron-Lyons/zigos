const std = @import("std");
const manifest = @import("manifest.zig");
const policy_object = @import("policy_object.zig");
const signing = @import("signing.zig");

pub const MAX_INSTALLED_BUNDLES: usize = 16;
pub const MAX_LABEL_BYTES: usize = 64;

pub const InstallRequest = struct {
    bundle: manifest.BundleManifest,
    source_identity: []const u8,
    data_schema_version: u32 = 1,
    migration_manifest: []const u8 = "",
    declared_permission_change: bool = false,
};

pub const InstallResult = struct {
    installed_new: bool,
    updated_existing: bool,
    permissions_changed: bool,
    rollback_available: bool,
    migration_applied: bool,
};

pub const InstalledBundle = struct {
    bundle_id_len: usize,
    bundle_id: [MAX_LABEL_BYTES]u8,
    publisher_len: usize,
    publisher: [MAX_LABEL_BYTES]u8,
    current_version_major: u16,
    current_version_minor: u16,
    current_channel: manifest.UpdateChannel,
    current_permission_digest: [32]u8,
    current_schema_version: u32,
    previous_version_major: u16,
    previous_version_minor: u16,
    previous_channel: manifest.UpdateChannel,
    previous_permission_digest: [32]u8,
    previous_schema_version: u32,
    rollback_available: bool,
    last_migration_manifest_len: usize,
    last_migration_manifest: [MAX_LABEL_BYTES]u8,

    pub fn bundleIdSlice(self: *const InstalledBundle) []const u8 {
        return self.bundle_id[0..self.bundle_id_len];
    }

    pub fn publisherSlice(self: *const InstalledBundle) []const u8 {
        return self.publisher[0..self.publisher_len];
    }
};

pub const Error = manifest.ValidationError || error{
    BundleNotFound,
    BundleTableFull,
    InstallSourceDenied,
    InvalidManifestSignature,
    MigrationManifestRequired,
    NoRollbackVersion,
    PermissionChangeUndeclared,
};

const BundleSlot = struct {
    in_use: bool = false,
    bundle: InstalledBundle = zeroBundle(),
};

pub const Service = struct {
    slots: [MAX_INSTALLED_BUNDLES]BundleSlot = [_]BundleSlot{BundleSlot{}} ** MAX_INSTALLED_BUNDLES,

    pub fn init() Service {
        return .{};
    }

    pub fn install(
        self: *Service,
        request: InstallRequest,
        policy: ?*const policy_object.PolicyObject,
    ) Error!InstallResult {
        try manifest.validate(request.bundle);
        const digest = digestBundle(request.bundle);
        if (!signing.verify(request.bundle.signature, &digest)) {
            return error.InvalidManifestSignature;
        }
        if (policy) |active_policy| {
            if (!active_policy.allowsInstallSource(request.source_identity)) {
                return error.InstallSourceDenied;
            }
        }

        const permission_digest = permissionDigest(request.bundle.requested_permissions);
        const existing = self.find(request.bundle.bundle_id);
        if (existing) |bundle| {
            const permissions_changed = !std.mem.eql(u8, &bundle.current_permission_digest, &permission_digest);
            if (permissions_changed and !request.declared_permission_change) {
                return error.PermissionChangeUndeclared;
            }
            if (request.data_schema_version > bundle.current_schema_version and request.migration_manifest.len == 0) {
                return error.MigrationManifestRequired;
            }

            bundle.previous_version_major = bundle.current_version_major;
            bundle.previous_version_minor = bundle.current_version_minor;
            bundle.previous_channel = bundle.current_channel;
            bundle.previous_permission_digest = bundle.current_permission_digest;
            bundle.previous_schema_version = bundle.current_schema_version;
            bundle.rollback_available = true;

            bundle.publisher_len = copyText(&bundle.publisher, request.bundle.publisher);
            bundle.current_version_major = request.bundle.version_major;
            bundle.current_version_minor = request.bundle.version_minor;
            bundle.current_channel = request.bundle.update_channel;
            bundle.current_permission_digest = permission_digest;
            bundle.current_schema_version = request.data_schema_version;
            bundle.last_migration_manifest_len = copyText(&bundle.last_migration_manifest, request.migration_manifest);

            return .{
                .installed_new = false,
                .updated_existing = true,
                .permissions_changed = permissions_changed,
                .rollback_available = bundle.rollback_available,
                .migration_applied = request.migration_manifest.len != 0,
            };
        }

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.bundle = zeroBundle();
            slot.bundle.bundle_id_len = copyText(&slot.bundle.bundle_id, request.bundle.bundle_id);
            slot.bundle.publisher_len = copyText(&slot.bundle.publisher, request.bundle.publisher);
            slot.bundle.current_version_major = request.bundle.version_major;
            slot.bundle.current_version_minor = request.bundle.version_minor;
            slot.bundle.current_channel = request.bundle.update_channel;
            slot.bundle.current_permission_digest = permission_digest;
            slot.bundle.current_schema_version = request.data_schema_version;
            slot.bundle.last_migration_manifest_len = copyText(&slot.bundle.last_migration_manifest, request.migration_manifest);
            return .{
                .installed_new = true,
                .updated_existing = false,
                .permissions_changed = false,
                .rollback_available = false,
                .migration_applied = request.migration_manifest.len != 0,
            };
        }

        return error.BundleTableFull;
    }

    pub fn rollback(self: *Service, bundle_id: []const u8) Error!InstallResult {
        const bundle = self.find(bundle_id) orelse return error.BundleNotFound;
        if (!bundle.rollback_available) return error.NoRollbackVersion;

        const current_major = bundle.current_version_major;
        const current_minor = bundle.current_version_minor;
        const current_channel = bundle.current_channel;
        const current_permission_digest = bundle.current_permission_digest;
        const current_schema_version = bundle.current_schema_version;

        bundle.current_version_major = bundle.previous_version_major;
        bundle.current_version_minor = bundle.previous_version_minor;
        bundle.current_channel = bundle.previous_channel;
        bundle.current_permission_digest = bundle.previous_permission_digest;
        bundle.current_schema_version = bundle.previous_schema_version;

        bundle.previous_version_major = current_major;
        bundle.previous_version_minor = current_minor;
        bundle.previous_channel = current_channel;
        bundle.previous_permission_digest = current_permission_digest;
        bundle.previous_schema_version = current_schema_version;

        return .{
            .installed_new = false,
            .updated_existing = true,
            .permissions_changed = true,
            .rollback_available = true,
            .migration_applied = false,
        };
    }

    pub fn find(self: *Service, bundle_id: []const u8) ?*InstalledBundle {
        for (&self.slots) |*slot| {
            if (slot.in_use and std.mem.eql(u8, slot.bundle.bundleIdSlice(), bundle_id)) return &slot.bundle;
        }
        return null;
    }
};

pub fn digestBundle(bundle: manifest.BundleManifest) [32]u8 {
    var digest = [_]u8{0} ** 32;
    const seeds = [_]u64{
        0x6A09E667F3BCC909,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
    };
    for (seeds, 0..) |seed, index| {
        var hash = seed;
        hash = hashBytes(hash, bundle.bundle_id);
        hash = hashBytes(hash, bundle.display_name);
        hash = hashBytes(hash, bundle.publisher);
        hash = hashU64(hash, bundle.version_major);
        hash = hashU64(hash, bundle.version_minor);
        hash = hashByte(hash, @intFromEnum(bundle.update_channel));
        hash = hashBytes(hash, bundle.ai_metadata.model_family);
        hash = hashByte(hash, @intFromEnum(bundle.ai_metadata.locality));
        hash = hashByte(hash, if (bundle.ai_metadata.offline_required) 1 else 0);

        for (bundle.provided_interfaces) |interface| {
            hash = hashBytes(hash, interface.name);
            hash = hashU64(hash, interface.version_major);
            hash = hashU64(hash, interface.version_minor);
        }
        for (bundle.consumed_interfaces) |interface| {
            hash = hashBytes(hash, interface.name);
            hash = hashU64(hash, interface.version_major);
            hash = hashU64(hash, interface.version_minor);
        }
        for (bundle.requested_permissions) |permission| {
            const rights_bits: u32 = @bitCast(permission.rights);
            hash = hashByte(hash, @intFromEnum(permission.kind));
            hash = hashBytes(hash, permission.resource);
            hash = hashU64(hash, rights_bits);
            hash = hashByte(hash, if (permission.required) 1 else 0);
            hash = hashByte(hash, if (permission.local_only) 1 else 0);
            hash = hashU64(hash, permission.max_lease_ticks);
            hash = hashU64(hash, permission.target_id);
        }
        for (bundle.background_triggers) |trigger| {
            hash = hashByte(hash, @intFromEnum(trigger));
        }
        std.mem.writeInt(u64, digest[index * 8 ..][0..8], hash, .little);
    }
    return digest;
}

fn permissionDigest(requests: []const manifest.PermissionRequest) [32]u8 {
    var digest = [_]u8{0} ** 32;
    const seeds = [_]u64{
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    };
    for (seeds, 0..) |seed, index| {
        var hash = seed;
        for (requests) |request| {
            const rights_bits: u32 = @bitCast(request.rights);
            hash = hashByte(hash, @intFromEnum(request.kind));
            hash = hashBytes(hash, request.resource);
            hash = hashU64(hash, rights_bits);
            hash = hashByte(hash, if (request.required) 1 else 0);
            hash = hashByte(hash, if (request.local_only) 1 else 0);
        }
        std.mem.writeInt(u64, digest[index * 8 ..][0..8], hash, .little);
    }
    return digest;
}

fn zeroBundle() InstalledBundle {
    return .{
        .bundle_id_len = 0,
        .bundle_id = [_]u8{0} ** MAX_LABEL_BYTES,
        .publisher_len = 0,
        .publisher = [_]u8{0} ** MAX_LABEL_BYTES,
        .current_version_major = 0,
        .current_version_minor = 0,
        .current_channel = .stable,
        .current_permission_digest = [_]u8{0} ** 32,
        .current_schema_version = 0,
        .previous_version_major = 0,
        .previous_version_minor = 0,
        .previous_channel = .stable,
        .previous_permission_digest = [_]u8{0} ** 32,
        .previous_schema_version = 0,
        .rollback_available = false,
        .last_migration_manifest_len = 0,
        .last_migration_manifest = [_]u8{0} ** MAX_LABEL_BYTES,
    };
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

fn hashU64(start: u64, value: anytype) u64 {
    var buffer: [8]u8 = [_]u8{0} ** 8;
    std.mem.writeInt(u64, &buffer, @intCast(value), .little);
    return hashBytes(start, &buffer);
}

test "package service enforces signed manifests policy gated sources updates and rollback" {
    var policies = policy_object.Directory.init();
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 1,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "org-app-sources",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
    }, .{
        .label = "policy-key",
        .seed = [_]u8{0x22} ** 32,
    });

    const bundle_key = signing.SignerIdentity{
        .label = "bundle-key",
        .seed = [_]u8{0x23} ** 32,
    };
    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 0,
        .requested_permissions = &v1_permissions,
        .update_channel = .stable,
    };
    v1.signature = try signing.sign(bundle_key, &digestBundle(v1));

    var service = Service.init();
    const first = try service.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, org_policy);
    try std.testing.expect(first.installed_new);
    try std.testing.expect(!first.rollback_available);

    try std.testing.expectError(error.InstallSourceDenied, service.install(.{
        .bundle = v1,
        .source_identity = "repo:personal",
        .data_schema_version = 1,
    }, org_policy));

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "relay.notes.example",
            .rights = .{ .network_remote = true },
            .required = false,
        },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .requested_permissions = &v2_permissions,
        .update_channel = .stable,
    };
    v2.signature = try signing.sign(bundle_key, &digestBundle(v2));

    try std.testing.expectError(error.PermissionChangeUndeclared, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
    }, org_policy));

    try std.testing.expectError(error.MigrationManifestRequired, service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .declared_permission_change = true,
    }, org_policy));

    const updated = try service.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "notes-v2-migration",
        .declared_permission_change = true,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);
    try std.testing.expect(updated.migration_applied);

    const installed = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_major);
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_minor);
    try std.testing.expectEqual(@as(u32, 2), installed.current_schema_version);

    _ = try service.rollback("app.notes");
    const rolled_back = service.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), rolled_back.current_version_major);
    try std.testing.expectEqual(@as(u16, 0), rolled_back.current_version_minor);
    try std.testing.expectEqual(@as(u32, 1), rolled_back.current_schema_version);
}

test "package service rejects invalid signatures and rollback before any update" {
    var service = Service.init();
    const signer_identity = signing.SignerIdentity{
        .label = "pkg-test",
        .seed = [_]u8{0x31} ** 32,
    };
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true },
            .local_only = true,
        },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .requested_permissions = &permissions,
    };
    bundle.signature = try signing.sign(signer_identity, &digestBundle(bundle));

    var tampered = bundle;
    tampered.publisher = "Malicious Fork";
    try std.testing.expectError(error.InvalidManifestSignature, service.install(.{
        .bundle = tampered,
        .source_identity = "store:zigos",
    }, null));

    _ = try service.install(.{
        .bundle = bundle,
        .source_identity = "store:zigos",
    }, null);
    try std.testing.expectError(error.NoRollbackVersion, service.rollback("app.notes"));
}
