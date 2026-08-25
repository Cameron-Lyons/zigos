const abi = @import("../core/abi.zig");
const bootstrap_capabilities = @import("bootstrap_capabilities.zig");
const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const contract = @import("contract.zig");
const device_inventory = @import("../drivers/device_inventory.zig");
const driver_service = @import("../drivers/driver_service.zig");
const principal = @import("../core/principal.zig");
const service_contract = @import("service_contracts.zig");
const service_catalog = @import("service_catalog.zig");
const units = @import("../core/units.zig");
const native_util = @import("../core/util.zig");
const service_registry = @import("../services/service_registry.zig");
const kernel_descriptors = @import("../kernel_api/native_kernel_descriptors.zig");
const supervisor_mod = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const userspace_boot_registry = @import("../task/userspace_boot_registry.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const Error = error{ MissingBootstrapGrant, DriverAttachmentNotAllowed } || device_inventory.Error || userspace_launch.Error || userspace_boot_registry.Error || component_port.Error || driver_service.Error || service_registry.Error;
pub const DIRECT_SERVICE_AUTHORITY_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const BOOTSTRAP_DRIVER_TASK_INDEX_LOOKUPS: u8 = 1;

const driver_endpoint_slots = 4;
const kibibytes = units.kibibytes;

pub const ServiceBinding = struct {
    task_id: u64,
    endpoint_id: u64,
};

pub const LaunchServiceRequest = struct {
    catalog: *userspace_loader.Catalog,
    kernel_port: *component_port.KernelPort,
    service_directory: *service_registry.Service,
    supervisor: *supervisor_mod.Supervisor,
    authority_capability_id: u64,
    controller_task_id: u64,
    schedule_task: *userspace_scheduler.Scheduler,
    owner: principal.PrincipalId,
    service_id: u64,
    entry: service_contract.ServiceContract,
};

pub fn launchContractService(request: LaunchServiceRequest) Error!ServiceBinding {
    const bundle_id = try userspace_boot_registry.bundleIdForServiceClass(request.entry.class);
    const bootstrap_rights = rightsForGrant(request.entry.bootstrap_grants, .service_task_authority) orelse return error.MissingBootstrapGrant;
    const service_task_id, const service_authority_capability_id = if (request.controller_task_id == 0) blk: {
        const service_task = try userspace_launch.launchRegisteredDirect(
            request.catalog,
            request.kernel_port.kernel.runtime,
            bundle_id,
            .{
                .owner = request.owner,
                .budget = request.entry.boot_budget,
                .ui_surface_id = request.entry.ui_surface_id,
                .local_only = true,
            },
            request.schedule_task,
        );
        const service_authority = try request.kernel_port.kernel.capability_table.mintBootRoot(.{
            .holder = request.owner,
            .issuer = request.kernel_port.kernel.policy_authority,
            .target = .{ .kind = .service, .id = request.service_id },
            .rights = bootstrap_rights,
            .scope = .{
                .task_id = service_task.id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                // Contract ticks order the boot graph; they are not the runtime
                // timer domain used to authorize userspace syscalls.
                .issued_at_ticks = 0,
                .expires_at_ticks = std.math.maxInt(u64),
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = 0,
                .broker_service_id = request.service_id,
            },
        });
        try task_runtime.grantCapabilityToTask(service_task, service_authority.id);
        break :blk .{ service_task.id, service_authority.id };
    } else blk: {
        const service_task = try userspace_launch.launchRegisteredKernel(
            request.catalog,
            .{
                .port = request.kernel_port,
                .authority_capability_id = request.authority_capability_id,
                .controller_task_id = request.controller_task_id,
                .correlation_id = request.entry.boot_correlation_base,
                .now_ticks = request.entry.boot_tick,
            },
            bundle_id,
            .{
                .owner = request.owner,
                .budget = request.entry.boot_budget,
                .ui_surface_id = request.entry.ui_surface_id,
                .local_only = true,
            },
            request.schedule_task,
        );
        const derived_authority = try bootstrap_capabilities.deriveTaskCapability(
            request.kernel_port,
            request.controller_task_id,
            request.authority_capability_id,
            service_task.task_id,
            bootstrap_rights,
            request.entry.boot_correlation_base + 1,
            0,
        );
        break :blk .{ service_task.task_id, derived_authority };
    };

    const endpoint = try request.kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, request.entry.boot_correlation_base + 2, service_task_id),
        .authority_capability_id = service_authority_capability_id,
        .owner_task_id = service_task_id,
        .label = request.entry.interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, request.entry.boot_tick);
    if (request.entry.class == .service_registry) {
        request.service_directory.bindBootstrap(.{
            .task_id = service_task_id,
            .endpoint_id = endpoint.endpoint.endpoint_id,
            .endpoint_capability_id = endpoint.capability_id,
        });
    }
    const service_record = request.kernel_port.kernel.runtime.find(service_task_id) orelse return error.TaskNotFound;
    try request.service_directory.register(
        request.service_id,
        service_task_id,
        endpoint.endpoint.endpoint_id,
        endpoint.capability_id,
        request.entry.interface_id,
        kernel_descriptors.serviceBindingFlags(service_record),
    );
    _ = request.supervisor.noteContractBound(request.service_id, endpoint.endpoint.endpoint_id, request.entry.boot_tick);

    return .{
        .task_id = service_task_id,
        .endpoint_id = endpoint.endpoint.endpoint_id,
    };
}

pub fn attachDriver(
    runtime: *task_runtime.Runtime,
    capability_table: *capability.CapabilityTable,
    directory: *driver_service.Directory,
    supervisor: *supervisor_mod.Supervisor,
    policy_authority: principal.PrincipalId,
    service_id: u64,
    task_id: u64,
    device_class: driver_service.DeviceClass,
    bootstrap_transport: driver_service.BootstrapTransport,
    driver_bundle_id: []const u8,
    now_ticks: u64,
) Error!*driver_service.DriverRecord {
    if (!supervisor.allowsDriverAttachment(service_id, device_class)) return error.DriverAttachmentNotAllowed;
    const device_id = try device_inventory.requireProductionDriverDeviceId(device_class);
    const requester = runtime.find(task_id) orelse return error.TaskNotFound;
    const driver_capability = try capability_table.mintBootRoot(.{
        .holder = requester.owner,
        .issuer = policy_authority,
        .target = driver_service.authorityTarget(device_id),
        .rights = driver_service.allowedRightsFor(device_class),
        .scope = .{
            .task_id = requester.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = now_ticks,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = 0,
            .broker_service_id = service_id,
        },
    });
    errdefer capability_table.rollbackGrant(&.{driver_capability});
    try task_runtime.grantCapabilityToTask(requester, driver_capability.id);
    errdefer _ = task_runtime.revokeCapabilityFromTask(requester, driver_capability.id);

    const driver = try directory.registerSigned(.{
        .service_id = service_id,
        .owner_task_id = requester.id,
        .device_id = device_id,
        .device_class = device_class,
        .authority_capability_id = driver_capability.id,
        .capability_table = capability_table,
        .requester = requester.owner,
        .now_ticks = now_ticks,
        .signer = try driverSigner(device_class, driver_bundle_id),
        .bootstrap_transport = bootstrap_transport,
    });
    _ = supervisor.noteDriverAttached(service_id, device_class, driver_capability.id, now_ticks);
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
    if (controller_task_id == 0) {
        const task = try userspace_launch.launchRegisteredDirect(
            catalog,
            kernel_port.kernel.runtime,
            bundle_id,
            .{
                .owner = owner,
                .budget = driverBudget(device_class),
                .local_only = true,
            },
            schedule_task,
        );
        return kernel_descriptors.taskDescriptor(task);
    }
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
        .network_adapter, .storage_controller => driverResourceBudget(6_000, kibibytes(384), kibibytes(32)),
        .usb_controller => driverResourceBudget(6_000, kibibytes(384), kibibytes(32)),
        .graphics_adapter => driverResourceBudget(10_000, kibibytes(768), kibibytes(64)),
        .audio_print_io, .input_device => driverResourceBudget(4_000, kibibytes(256), kibibytes(16)),
        .compositor_policy => driverResourceBudget(4_000, kibibytes(256), kibibytes(16)),
    };
}

fn driverResourceBudget(cpu_time_ticks: u64, memory_bytes: usize, shared_memory_bytes: usize) task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = cpu_time_ticks,
        .memory_bytes = memory_bytes,
        .endpoint_slots = driver_endpoint_slots,
        .shared_memory_bytes = shared_memory_bytes,
        .background_allowed = false,
    };
}

pub fn contractsReady(service_directory: *const service_registry.Service) bool {
    for (service_contract.ordered_service_contracts) |entry| {
        _ = service_directory.connect(entry.interface_id) catch return false;
    }
    return true;
}

fn driverSigner(device_class: driver_service.DeviceClass, bundle_id: []const u8) userspace_boot_registry.Error![]const u8 {
    if (bundle_id.len != 0) {
        return try userspace_boot_registry.signerFor(bundle_id);
    }

    return switch (device_class) {
        .network_adapter,
        .storage_controller,
        .usb_controller,
        .graphics_adapter,
        .audio_print_io,
        .input_device,
        .compositor_policy,
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
            40 + @as(u64, @intCast(index)),
            entry.interface_id,
            service_registry.REQUIRED_BINDING_FLAGS,
        );
    }

    try std.testing.expect(contractsReady(&registry));
}

test "bootstrap driver attachment rolls back authority when signer resolution fails" {
    device_inventory.reset();
    defer device_inventory.reset();
    device_inventory.registerDetected(.network_adapter, 0x8086_15F2_0001, .intel_i225_lm_inventory, false);

    const owner = principal.PrincipalId{ .kind = .service, .serial = 700 };
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = owner,
        .component_class = .service_component,
        .budget = driverBudget(.network_adapter),
        .local_only = true,
    });
    var capability_table = capability.CapabilityTable.init();
    var directory = driver_service.Directory.init();
    var supervisor = supervisor_mod.Supervisor.init();
    const service = try supervisor.register(.network_stack, owner);

    try std.testing.expectError(error.UnknownBundleId, attachDriver(
        &runtime,
        &capability_table,
        &directory,
        &supervisor,
        .{ .kind = .policy_authority, .serial = 1 },
        service.id,
        task.id,
        .network_adapter,
        .none,
        "zigos.system.unknown-driver",
        1,
    ));

    try std.testing.expectEqual(@as(usize, 0), capability_table.activeCount());
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);
    try std.testing.expect(directory.findByServiceAndClass(service.id, .network_adapter) == null);
    try std.testing.expect(!supervisor.hasDiagnostic(service.id, .driver_attached));
}
