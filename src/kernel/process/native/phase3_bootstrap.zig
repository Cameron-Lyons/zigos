const std = @import("std");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const contract = @import("contract.zig");
const device_inventory = @import("device_inventory.zig");
const driver_service = @import("driver_service.zig");
const manifest = @import("manifest.zig");
const principal = @import("principal.zig");
const service_contract = @import("service_contract.zig");
const service_registry = @import("service_registry.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_boot_registry = @import("userspace_boot_registry.zig");
const userspace_launch = @import("userspace_launch.zig");
const userspace_loader = @import("userspace_loader.zig");

pub const ServiceBinding = struct {
    task_id: u64,
    endpoint_id: u64,
};

pub fn launchContractService(
    catalog: *userspace_loader.Catalog,
    kernel_port: *component_port.KernelPort,
    supervisor: *supervisor_mod.Supervisor,
    authority_capability_id: u64,
    controller_task_id: u64,
    schedule_task: anytype,
    owner: principal.PrincipalId,
    service_id: u64,
    entry: service_contract.Phase3Contract,
    correlation_base: u64,
    now_ticks: u64,
) ServiceBinding {
    return launchBundleService(
        catalog,
        kernel_port,
        supervisor,
        authority_capability_id,
        controller_task_id,
        schedule_task,
        owner,
        service_id,
        userspace_boot_registry.bundleIdForServiceClass(entry.class) catch unreachable,
        entry.interface,
        serviceBudget(entry.class),
        correlation_base,
        now_ticks,
    );
}

pub fn launchBundleService(
    catalog: *userspace_loader.Catalog,
    kernel_port: *component_port.KernelPort,
    supervisor: *supervisor_mod.Supervisor,
    authority_capability_id: u64,
    controller_task_id: u64,
    schedule_task: anytype,
    owner: principal.PrincipalId,
    service_id: u64,
    bundle_id: []const u8,
    interface: manifest.InterfaceDecl,
    budget: task_runtime.ResourceBudget,
    correlation_base: u64,
    now_ticks: u64,
) ServiceBinding {
    const service_task = userspace_launch.launchRegisteredKernel(
        catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = authority_capability_id,
            .controller_task_id = controller_task_id,
            .correlation_id = correlation_base,
            .now_ticks = now_ticks,
        },
        bundle_id,
        .{
            .owner = owner,
            .budget = budget,
            .local_only = true,
        },
        schedule_task,
    );

    const endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, correlation_base + 1, service_task.task_id),
        .authority_capability_id = authority_capability_id,
        .owner_task_id = service_task.task_id,
        .label = interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, now_ticks) catch unreachable;
    kernel_port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, correlation_base + 2, service_task.task_id),
        .authority_capability_id = authority_capability_id,
        .service_id = service_id,
        .owner_task_id = service_task.task_id,
        .endpoint_capability_id = endpoint.capability_id,
        .interface = interface,
    }, now_ticks) catch unreachable;
    _ = supervisor.noteContractBound(service_id, endpoint.endpoint.endpoint_id, now_ticks);

    return .{
        .task_id = service_task.task_id,
        .endpoint_id = endpoint.endpoint.endpoint_id,
    };
}

pub fn attachDriver(
    kernel_port: *component_port.KernelPort,
    capability_table: *capability.CapabilityTable,
    directory: *driver_service.Directory,
    supervisor: *supervisor_mod.Supervisor,
    policy_authority: principal.PrincipalId,
    policy_capability_id: u64,
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    device_class: driver_service.DeviceClass,
    now_ticks: u64,
) *driver_service.DriverRecord {
    const driver_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 360 + now_ticks, task_id),
        .policy_capability_id = policy_capability_id,
        .request = .{
            .holder = owner,
            .issuer = policy_authority,
            .target = driver_service.authorityTarget(deviceId(device_class)),
            .rights = driver_service.allowedRightsFor(device_class),
            .scope = .{
                .task_id = task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = now_ticks,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = true,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = task_id,
                .broker_service_id = service_id,
            },
        },
    }, now_ticks) catch unreachable;
    const driver = directory.register(.{
        .service_id = service_id,
        .owner_task_id = task_id,
        .device_id = deviceId(device_class),
        .device_class = device_class,
        .authority = capability_table.query(driver_capability.capability_id).?,
        .bundle = driverBundle(device_class),
    }) catch unreachable;
    _ = supervisor.noteDriverAttached(service_id, device_class, driver_capability.capability_id, now_ticks);
    return driver;
}

pub fn serviceBudget(class: contract.ServiceClass) task_runtime.ResourceBudget {
    return switch (class) {
        .network_stack, .storage_object, .compositor_ui_session => .{
            .cpu_time_ticks = 16_000,
            .memory_bytes = 1024 * 1024,
            .endpoint_slots = 8,
            .shared_memory_bytes = 128 * 1024,
            .background_allowed = false,
        },
        else => .{
            .cpu_time_ticks = 8_000,
            .memory_bytes = 512 * 1024,
            .endpoint_slots = 6,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = false,
        },
    };
}

pub fn contractsReady(service_directory: *const service_registry.Registry) bool {
    for (service_contract.ordered_phase3_contracts) |entry| {
        _ = service_directory.connect(entry.interface) catch return false;
    }
    return true;
}

fn deviceId(device_class: driver_service.DeviceClass) u64 {
    return device_inventory.deviceIdForClass(device_class);
}

fn driverBundle(device_class: driver_service.DeviceClass) manifest.BundleManifest {
    return switch (device_class) {
        .network_adapter => .{
            .bundle_id = "svc.driver.network",
            .display_name = "Network Driver",
            .publisher = "zigos.dev",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-driver-key",
            },
        },
        .storage_controller => .{
            .bundle_id = "svc.driver.storage",
            .display_name = "Storage Driver",
            .publisher = "zigos.dev",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-driver-key",
            },
        },
        .graphics_adapter => .{
            .bundle_id = "svc.driver.graphics",
            .display_name = "Graphics Driver",
            .publisher = "zigos.dev",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-driver-key",
            },
        },
        .audio_print_io => .{
            .bundle_id = "svc.driver.media",
            .display_name = "Media Driver",
            .publisher = "zigos.dev",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-driver-key",
            },
        },
    };
}

test "contractsReady requires every ordered phase3 contract" {
    var registry = service_registry.Registry.init();

    try std.testing.expect(!contractsReady(&registry));

    for (service_contract.ordered_phase3_contracts, 0..) |entry, index| {
        try registry.register(
            10 + @as(u64, @intCast(index)),
            20 + @as(u64, @intCast(index)),
            30 + @as(u64, @intCast(index)),
            entry.interface,
            0,
        );
    }

    try std.testing.expect(contractsReady(&registry));
}
