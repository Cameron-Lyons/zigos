const std = @import("std");
const capability = @import("../kernel/process/native/capability.zig");
const driver_service = @import("../kernel/process/native/driver_service.zig");
const principal = @import("../kernel/process/native/principal.zig");
const signing = @import("../kernel/process/native/signing.zig");
const task_runtime = @import("../kernel/process/native/task_runtime.zig");

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

pub fn driverAuthority(
    holder: principal.PrincipalId,
    capability_id: u64,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) capability.Capability {
    return .{
        .id = capability_id,
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
        .revocation_generation = 1,
        .audit = .{},
    };
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
