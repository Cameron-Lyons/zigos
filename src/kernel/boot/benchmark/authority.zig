const std = @import("std");
const benchmark_reporting = @import("reporting.zig");
const identities = @import("identities.zig");
const capability = @import("../../../native/kernel_api/capability.zig");
const driver_service = @import("../../../native/drivers/driver_service.zig");
const principal = @import("../../../native/core/principal.zig");
const sync_service = @import("../../../native/sync/sync_service.zig");

pub fn zeroSyncAuthority() sync_service.AuthorityContext {
    return .{
        .task_id = 0,
        .principal = .{ .kind = .service, .serial = 0 },
        .capability_id = 0,
        .now_ticks = 0,
    };
}

pub fn mintBenchmarkSyncAuthority(
    capability_table: *capability.CapabilityTable,
    service_instance: *const sync_service.Service,
) capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = service_instance.owner,
        .issuer = identities.policyAuthority(1),
        .target = .{ .kind = .service, .id = service_instance.service_id },
        .rights = .{ .service = .{
            .endpoint_connect = true,
        } },
        .scope = .{
            .task_id = service_instance.task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{},
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark authority", err);
}

pub fn benchmarkSyncAuthority(
    service_instance: *const sync_service.Service,
    authority_capability: capability.Capability,
    now_ticks: u64,
) sync_service.AuthorityContext {
    return .{
        .task_id = service_instance.task_id,
        .principal = service_instance.owner,
        .capability_id = authority_capability.id,
        .now_ticks = now_ticks,
    };
}

pub fn mintDriverAuthority(
    capability_table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) capability.Capability {
    return capability_table.mintBootRoot(.{
        .holder = holder,
        .issuer = identities.policyAuthority(1),
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
    }) catch |err| benchmark_reporting.benchStepFailure("benchmark authority", err);
}
