const abi = @import("../core/abi.zig");
const bootstrap_capabilities = @import("bootstrap_capabilities.zig");
const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const contract = @import("contract.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contracts.zig");
const service_catalog = @import("service_catalog.zig");
const native_util = @import("../core/util.zig");
const service_registry = @import("../services/service_registry.zig");
const kernel_descriptors = @import("../kernel_api/native_kernel_descriptors.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_boot_registry = @import("../task/userspace_boot_registry.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");

pub const Error = error{MissingBootstrapGrant} || userspace_launch.Error || userspace_boot_registry.Error || component_port.Error || driver_service.Error || service_registry.Error;

pub const ServiceBinding = struct {
    task_id: u64,
    endpoint_id: u64,
};

pub fn launchContractService(
    catalog: *userspace_loader.Catalog,
    kernel_port: *component_port.KernelPort,
    service_directory: *service_registry.Service,
    supervisor: *supervisor_mod.Supervisor,
    authority_capability_id: u64,
    controller_task_id: u64,
    schedule_task: anytype,
    owner: principal.PrincipalId,
    service_id: u64,
    entry: service_contract.ServiceContract,
    correlation_base: u64,
    now_ticks: u64,
) Error!ServiceBinding {
    return launchBundleService(
        catalog,
        kernel_port,
        service_directory,
        supervisor,
        authority_capability_id,
        controller_task_id,
        schedule_task,
        owner,
        service_id,
        try userspace_boot_registry.bundleIdForServiceClass(entry.class),
        entry.interface,
        entry.boot_budget,
        entry.class,
        rightsForGrant(entry.bootstrap_grants, .service_task_authority) orelse return error.MissingBootstrapGrant,
        correlation_base,
        now_ticks,
    );
}

pub fn launchBundleService(
    catalog: *userspace_loader.Catalog,
    kernel_port: *component_port.KernelPort,
    service_directory: *service_registry.Service,
    supervisor: *supervisor_mod.Supervisor,
    authority_capability_id: u64,
    controller_task_id: u64,
    schedule_task: anytype,
    owner: principal.PrincipalId,
    service_id: u64,
    bundle_id: []const u8,
    interface: manifest.InterfaceDecl,
    budget: task_runtime.ResourceBudget,
    class: contract.ServiceClass,
    bootstrap_rights: capability.CapabilityRights,
    correlation_base: u64,
    now_ticks: u64,
) Error!ServiceBinding {
    const service_task = try userspace_launch.launchRegisteredKernel(
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
    const service_authority_capability_id = try bootstrap_capabilities.deriveTaskCapability(
        kernel_port,
        controller_task_id,
        authority_capability_id,
        service_task.task_id,
        bootstrap_rights,
        correlation_base + 1,
        now_ticks,
    );

    const endpoint = try kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, correlation_base + 2, service_task.task_id),
        .authority_capability_id = service_authority_capability_id,
        .owner_task_id = service_task.task_id,
        .label = interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, now_ticks);
    if (class == .service_registry) {
        service_directory.bindBootstrap(.{
            .task_id = service_task.task_id,
            .endpoint_id = endpoint.endpoint.endpoint_id,
            .endpoint_capability_id = endpoint.capability_id,
        });
    }
    const service_record = kernel_port.kernel.runtime.find(service_task.task_id) orelse return error.TaskNotFound;
    try service_directory.register(
        service_id,
        service_task.task_id,
        endpoint.endpoint.endpoint_id,
        interface,
        kernel_descriptors.serviceBindingFlags(service_record),
    );
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
    controller_task_id: u64,
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    device_class: driver_service.DeviceClass,
    bootstrap_transport: driver_service.BootstrapTransport,
    driver_bundle_id: []const u8,
    now_ticks: u64,
) Error!*driver_service.DriverRecord {
    _ = owner;
    const driver_capability_id = try bootstrap_capabilities.mintTaskCapability(
        kernel_port,
        controller_task_id,
        policy_capability_id,
        task_id,
        driver_service.authorityTarget(deviceId(device_class)),
        driver_service.allowedRightsFor(device_class),
        policy_authority,
        360 + now_ticks,
        now_ticks,
    );
    const requester = kernel_port.kernel.runtime.find(task_id) orelse return error.TaskNotFound;
    const driver = try directory.registerSigned(.{
        .service_id = service_id,
        .owner_task_id = task_id,
        .device_id = deviceId(device_class),
        .device_class = device_class,
        .authority_capability_id = driver_capability_id,
        .capability_table = capability_table,
        .requester = requester.owner,
        .now_ticks = now_ticks,
        .signer = try driverSigner(device_class, driver_bundle_id),
        .bootstrap_transport = bootstrap_transport,
    });
    _ = supervisor.noteDriverAttached(service_id, device_class, driver_capability_id, now_ticks);
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
) Error!abi.TaskDescriptor {
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
    return (service_catalog.bootstrapLaunchForClass(class) orelse
        native_util.impossibleByInvariant("service budget is only requested for bootstrap service classes")).budget;
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

pub fn contractsReady(service_directory: *const service_registry.Service) bool {
    for (service_contract.ordered_service_contracts) |entry| {
        _ = service_directory.connect(entry.interface) catch return false;
    }
    return true;
}

fn deviceId(device_class: driver_service.DeviceClass) u64 {
    return device_inventory.deviceIdForClass(device_class);
}

fn driverSigner(device_class: driver_service.DeviceClass, bundle_id: []const u8) userspace_boot_registry.Error![]const u8 {
    if (bundle_id.len != 0) {
        return try userspace_boot_registry.signerFor(bundle_id);
    }

    return switch (device_class) {
        .network_adapter,
        .storage_controller,
        .graphics_adapter,
        .audio_print_io,
        => "zigos-driver-key",
    };
}

fn rightsForGrant(
    grants: []const service_catalog.BootstrapGrantKind,
    requested: service_catalog.BootstrapGrantKind,
) ?capability.CapabilityRights {
    for (grants) |grant| {
        if (grant == requested) return service_catalog.rightsForBootstrapGrant(grant);
    }
    return null;
}

test "contractsReady requires every ordered service contract" {
    var registry = service_registry.Service.initWithBootstrap(.{
        .task_id = 1,
        .endpoint_id = 1,
        .endpoint_capability_id = 1,
    });

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
