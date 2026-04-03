const abi = @import("../core/abi.zig");
const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const contract = @import("contract.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contracts.zig");
const service_registry = @import("../kernel_api/service_registry.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_boot_registry = @import("../task/userspace_boot_registry.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");

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
    entry: service_contract.ServiceContract,
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
    if (!kernel_port.kernel.runtime.hasCapability(service_task.task_id, authority_capability_id)) {
        kernel_port.kernel.runtime.grantCapability(service_task.task_id, authority_capability_id) catch unreachable;
    }

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
    bootstrap_transport: driver_service.BootstrapTransport,
    driver_bundle_id: []const u8,
    now_ticks: u64,
) *driver_service.DriverRecord {
    if (!kernel_port.kernel.runtime.hasCapability(task_id, policy_capability_id)) {
        kernel_port.kernel.runtime.grantCapability(task_id, policy_capability_id) catch unreachable;
    }
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
        .bundle = driverBundle(device_class, driver_bundle_id),
        .bootstrap_transport = bootstrap_transport,
    }) catch unreachable;
    _ = supervisor.noteDriverAttached(service_id, device_class, driver_capability.capability_id, now_ticks);
    return driver;
}

pub fn launchDriverTask(
    catalog: *userspace_loader.Catalog,
    kernel_port: *component_port.KernelPort,
    authority_capability_id: u64,
    controller_task_id: u64,
    schedule_task: anytype,
    owner: principal.PrincipalId,
    bundle_id: []const u8,
    device_class: driver_service.DeviceClass,
    correlation_base: u64,
    now_ticks: u64,
) abi.TaskDescriptor {
    return userspace_launch.launchRegisteredKernel(
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
            .budget = driverBudget(device_class),
            .local_only = true,
        },
        schedule_task,
    );
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

pub fn driverBudget(device_class: driver_service.DeviceClass) task_runtime.ResourceBudget {
    return switch (device_class) {
        .network_adapter, .storage_controller => .{
            .cpu_time_ticks = 6_000,
            .memory_bytes = 384 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 32 * 1024,
            .background_allowed = false,
        },
        .graphics_adapter => .{
            .cpu_time_ticks = 10_000,
            .memory_bytes = 768 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 64 * 1024,
            .background_allowed = false,
        },
        .audio_print_io => .{
            .cpu_time_ticks = 4_000,
            .memory_bytes = 256 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 16 * 1024,
            .background_allowed = false,
        },
    };
}

pub fn contractsReady(service_directory: *const service_registry.Registry) bool {
    for (service_contract.ordered_service_contracts) |entry| {
        _ = service_directory.connect(entry.interface) catch return false;
    }
    return true;
}

fn deviceId(device_class: driver_service.DeviceClass) u64 {
    return device_inventory.deviceIdForClass(device_class);
}

fn driverBundle(device_class: driver_service.DeviceClass, bundle_id: []const u8) manifest.BundleManifest {
    if (bundle_id.len != 0) {
        return userspace_boot_registry.manifestFor(bundle_id) catch unreachable;
    }

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

test "contractsReady requires every ordered service contract" {
    var registry = service_registry.Registry.init();

    try std.testing.expect(!contractsReady(&registry));

    for (service_contract.ordered_service_contracts, 0..) |entry, index| {
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
