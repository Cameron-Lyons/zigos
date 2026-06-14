const std = @import("std");
const capability = @import("../../native/kernel_api/capability.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const hash_seeds = @import("../../native/core/hash_seeds.zig");
const manifest = @import("../../native/policy/manifest.zig");
const principal = @import("../../native/core/principal.zig");
const package_service = @import("../../native/services/package_service.zig");
const service_authority = @import("../../native/services/service_authority.zig");
const signing = @import("../../native/core/signing.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const units = @import("../../native/core/units.zig");

pub fn signer(label: []const u8, fill: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = signing.seedFromByte(fill),
    };
}

pub fn signReleaseBundle(bundle: manifest.BundleManifest, identity: signing.SignerIdentity) !manifest.Signature {
    return signing.signWithDefaultRegistry(
        .ed25519,
        identity,
        &package_service.digestBundle(bundle),
    );
}

pub fn user(serial: u64) principal.PrincipalId {
    return .{ .kind = .user, .serial = serial };
}

pub fn device(serial: u64) principal.PrincipalId {
    return .{ .kind = .device, .serial = serial };
}

pub fn app(serial: u64) principal.PrincipalId {
    return .{ .kind = .app, .serial = serial };
}

pub fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

pub fn policyAuthority(serial: u64) principal.PrincipalId {
    return .{ .kind = .policy_authority, .serial = serial };
}

pub fn trustPackagePublisher(
    port: *package_service.PackagePort,
    authority: service_authority.Context,
    identity: signing.SignerIdentity,
    publisher: []const u8,
) !void {
    const issuer = policyAuthority(1);
    _ = try port.trustPolicyAuthorityRoot(authority, issuer, signing.publicKeyFromByte(0x5A));
    _ = try port.trustPublisher(
        authority,
        .{ .kind = .app, .serial = std.hash.Wyhash.hash(hash_seeds.package_spec_publisher, publisher) },
        issuer,
        publisher,
        try signing.publicKey(identity),
    );
}

pub fn serviceAuthority(
    capability_table: *capability.CapabilityTable,
    service_id: u64,
    holder: principal.PrincipalId,
    task_id: u64,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = policyAuthority(1),
        .target = .{ .kind = .service, .id = service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
            .capability_mint = true,
            .capability_revoke = true,
        } },
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
    });
}

pub fn serviceAuthorityContext(
    task_id: u64,
    holder: principal.PrincipalId,
    authority: capability.Capability,
    now_ticks: u64,
) service_authority.Context {
    return .{
        .task_id = task_id,
        .principal = holder,
        .capability_id = authority.id,
        .now_ticks = now_ticks,
    };
}

pub fn driverAuthority(
    capability_table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = policyAuthority(1),
        .target = driver_service.authorityTarget(device_id),
        .rights = driver_service.allowedRightsFor(device_class),
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
    });
}

pub fn defaultBudget(background_allowed: bool) task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 10_000,
        .memory_bytes = units.kibibytes(256),
        .endpoint_slots = 8,
        .shared_memory_bytes = units.kibibytes(16),
        .background_allowed = background_allowed,
    };
}
