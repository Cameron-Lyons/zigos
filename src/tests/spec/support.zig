const std = @import("std");
const capability = @import("../../native/kernel_api/capability.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const principal = @import("../../native/core/principal.zig");
const package_service = @import("../../native/services/package_service.zig");
const signing = @import("../../native/core/signing.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");

pub fn signer(label: []const u8, fill: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = [_]u8{fill} ** 32,
    };
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
    packages: *package_service.Service,
    identity: signing.SignerIdentity,
    publisher: []const u8,
) !void {
    const issuer = policyAuthority(1);
    _ = try packages.trustPolicyAuthorityRoot(issuer, [_]u8{0x5A} ** 32);
    _ = try packages.trustPublisher(
        .{ .kind = .app, .serial = std.hash.Wyhash.hash(0x5A47_5350_4543, publisher) },
        issuer,
        publisher,
        try signing.publicKey(identity),
    );
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
        .memory_bytes = 256 * 1024,
        .endpoint_slots = 8,
        .shared_memory_bytes = 16 * 1024,
        .background_allowed = background_allowed,
    };
}
