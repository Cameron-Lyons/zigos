const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const bootstrap_capabilities = @import("bootstrap_capabilities.zig");
const component_port = @import("../kernel_api/component_port.zig");
const contract = @import("contract.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contract.zig");
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
    const service_authority_capability_id = bootstrap_capabilities.deriveTaskCapability(
        kernel_port,
        controller_task_id,
        authority_capability_id,
        service_task.task_id,
        bootstrap_capabilities.serviceBootstrapRights(),
        correlation_base + 1,
        now_ticks,
    ) catch unreachable;

    const endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, correlation_base + 2, service_task.task_id),
        .authority_capability_id = service_authority_capability_id,
        .owner_task_id = service_task.task_id,
        .label = interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, now_ticks) catch unreachable;
    kernel_port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, correlation_base + 3, service_task.task_id),
        .authority_capability_id = service_authority_capability_id,
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
    controller_task_id: u64,
    service_id: u64,
    task_id: u64,
    owner: principal.PrincipalId,
    device_class: driver_service.DeviceClass,
    now_ticks: u64,
) *driver_service.DriverRecord {
    _ = owner;
    const driver_capability_id = bootstrap_capabilities.mintTaskCapability(
        kernel_port,
        controller_task_id,
        policy_capability_id,
        task_id,
        driver_service.authorityTarget(deviceId(device_class)),
        driver_service.allowedRightsFor(device_class),
        policy_authority,
        360 + now_ticks,
        now_ticks,
    ) catch unreachable;
    const driver = directory.register(.{
        .service_id = service_id,
        .owner_task_id = task_id,
        .device_id = deviceId(device_class),
        .device_class = device_class,
        .authority_capability_id = driver_capability_id,
        .capability_table = capability_table,
        .requester = kernel_port.kernel.runtime.find(task_id).?.owner,
        .now_ticks = now_ticks,
        .bundle = driverBundle(device_class),
    }) catch unreachable;
    _ = supervisor.noteDriverAttached(service_id, device_class, driver_capability_id, now_ticks);
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
