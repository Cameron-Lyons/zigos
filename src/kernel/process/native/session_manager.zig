const builtin = @import("builtin");
const std = @import("std");
const abi = @import("abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const contract = @import("contract.zig");
const device_inventory = @import("device_inventory.zig");
const driver_runtime_mod = @import("driver_runtime.zig");
const driver_service = @import("driver_service.zig");
const network_policy = @import("network_policy.zig");
const endpoint_mod = @import("endpoint.zig");
const immutable_base = @import("immutable_base.zig");
const native_util = @import("util.zig");
const manifest = @import("manifest.zig");
const measured_boot = @import("measured_boot.zig");
const native_ux = @import("native_ux.zig");
const native_kernel = @import("native_kernel.zig");
const object_store_mod = @import("object_store.zig");
const native_service_registry = @import("service_registry.zig");
const permission_review_service = @import("permission_review_service.zig");
const policy_mediation = @import("policy_mediation.zig");
const policy_component_port = @import("policy_component_port.zig");
const principal = @import("principal.zig");
const phase3_bootstrap = @import("phase3_bootstrap.zig");
const recovery_environment = @import("recovery_environment.zig");
const review_component_port = @import("review_component_port.zig");
const service_contract = @import("service_contract.zig");
const shared_memory_mod = @import("shared_memory.zig");
const signing = @import("signing.zig");
const storage_service_mod = @import("storage_service.zig");
const storage_volume_mod = @import("storage_volume.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("sync_service.zig");
const task_runtime = @import("task_runtime.zig");
const task_runtime_service_mod = @import("task_runtime_service.zig");
const userspace_boot_registry = @import("userspace_boot_registry.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_launch = @import("userspace_launch.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_scheduler = @import("userspace_scheduler.zig");
const workspace_mod = @import("workspace.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

var initialized = false;
var capability_table = capability.CapabilityTable.init();
var endpoint_table = endpoint_mod.Table.init();
var runtime = task_runtime.Runtime.init();
var runtime_service = task_runtime_service_mod.Service.init(&runtime);
var service_directory = native_service_registry.Registry.init();
var shared_memory_table = shared_memory_mod.Table.init();
var userspace_catalog = userspace_loader.Catalog.init();
var kernel_instance: native_kernel.Kernel = undefined;
var kernel_port_instance: component_port.KernelPort = undefined;
var kernel_port_ready = false;
var driver_directory = driver_service.Directory.init();
var driver_runtime = driver_runtime_mod.Runtime.init();
var supervisor = supervisor_mod.Supervisor.init();
var phase4_storage_service = emptyStorageService();
var phase4_export_package = workspace_mod.emptyExportPackage();
const bootstrap_storage_interface = manifest.InterfaceDecl{ .name = "zigos.bootstrap.workspace" };
const compatibility_portal_interface = manifest.InterfaceDecl{ .name = "zigos.compat.portal" };
const phase4_storage_signer = signing.SignerIdentity{
    .label = "zigos-storage-key",
    .seed = [_]u8{0x81} ** 32,
};
const phase4_workspace_signer = signing.SignerIdentity{
    .label = "zigos-workspace-key",
    .seed = [_]u8{0x82} ** 32,
};
const phase4_export_signer = signing.SignerIdentity{
    .label = "zigos-export-key",
    .seed = [_]u8{0x83} ** 32,
};

fn latestInsertedVersion(store: *const object_store_mod.Store) ?*const object_store_mod.VersionRecord {
    var latest: ?*const object_store_mod.VersionRecord = null;
    for (&store.versions) |*slot| {
        if (!slot.in_use) continue;
        if (latest == null or slot.version.id > latest.?.id) {
            latest = &slot.version;
        }
    }
    return latest;
}

fn emptyStorageService() storage_service_mod.Service {
    return .{
        .service_id = 0,
        .task_id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .store = undefined,
        .workspaces = undefined,
    };
}

fn resetStateForTest() void {
    initialized = false;
    capability_table = capability.CapabilityTable.init();
    endpoint_table = endpoint_mod.Table.init();
    runtime = task_runtime.Runtime.init();
    runtime_service = task_runtime_service_mod.Service.init(&runtime);
    service_directory = native_service_registry.Registry.init();
    shared_memory_table = shared_memory_mod.Table.init();
    userspace_catalog = userspace_loader.Catalog.init();
    kernel_instance = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 0 },
        runtime_service.runtimePtr(),
        &capability_table,
        &endpoint_table,
        &shared_memory_table,
        &service_directory,
    );
    kernel_port_instance = component_port.KernelPort.init(&kernel_instance);
    kernel_port_ready = false;
    driver_directory = driver_service.Directory.init();
    driver_runtime = driver_runtime_mod.Runtime.init();
    supervisor = supervisor_mod.Supervisor.init();
    phase4_storage_service = emptyStorageService();
    phase4_export_package = workspace_mod.emptyExportPackage();
    userspace_scheduler.reset();
    storage_service_mod.Service.resetPersistentState();
    sync_service_mod.Service.resetPersistentState();
}

pub fn kernelPort() ?*component_port.KernelPort {
    if (!kernel_port_ready) return null;
    return &kernel_port_instance;
}

fn taskCount() usize {
    var count: usize = 0;
    for (runtime.tasks) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn taskCountInState(state: task_runtime.TaskState) usize {
    var count: usize = 0;
    for (runtime.tasks) |slot| {
        if (slot.in_use and slot.task.state == state) count += 1;
    }
    return count;
}

fn serviceCount() usize {
    var count: usize = 0;
    for (supervisor.services) |slot| {
        if (slot.in_use) count += 1;
    }
    return count;
}

fn findTaskByLabel(label: []const u8) ?*task_runtime.TaskRecord {
    var match: ?*task_runtime.TaskRecord = null;
    for (&runtime.tasks) |*slot| {
        if (!slot.in_use or slot.task.execution_component_count == 0) continue;
        if (std.mem.eql(u8, slot.task.execution_components[0].labelSlice(), label)) {
            match = &slot.task;
        }
    }
    return match;
}

fn executeUserspaceProbe(task_id: u64) void {
    _ = userspace_executor.executeTask(&userspace_catalog, &runtime, task_id);
}

fn scheduleUserspaceTask(task_id: u64) bool {
    return userspace_scheduler.registerTask(task_id);
}

pub fn runUserspaceScheduler(now_ticks: u64) bool {
    return userspace_scheduler.runNext(now_ticks);
}

pub fn boot() void {
    if (initialized) return;
    initialized = true;
    kernel_port_ready = false;

    common.printBootMarker("ZIGOS:NATIVE:BOOTSTRAP");
    common.printBootMarker("ZIGOS:TCB:DEFINED");

    const policy_authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const session_service = principal.PrincipalId{ .kind = .service, .serial = 1 };
    const session_user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const network_service_principal = principal.PrincipalId{ .kind = .service, .serial = 2 };
    const compositor_service_principal = principal.PrincipalId{ .kind = .service, .serial = 3 };
    const storage_service_principal = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const review_service_principal = principal.PrincipalId{ .kind = .service, .serial = 5 };
    const package_service_principal = principal.PrincipalId{ .kind = .service, .serial = 6 };
    const indexing_service_principal = principal.PrincipalId{ .kind = .service, .serial = 7 };
    const sync_service_principal = principal.PrincipalId{ .kind = .service, .serial = 8 };
    const media_service_principal = principal.PrincipalId{ .kind = .service, .serial = 9 };
    const task_runtime_principal = principal.PrincipalId{ .kind = .service, .serial = 10 };
    const compatibility_service_principal = principal.PrincipalId{ .kind = .service, .serial = 11 };
    userspace_catalog = userspace_loader.Catalog.init();
    userspace_boot_registry.registerAll(&userspace_catalog) catch unreachable;
    userspace_scheduler.init(&userspace_catalog, &runtime);
    if (userspace_catalog.imageCount() != 0) {
        common.printBootMarker("ZIGOS:USERSPACE:ARTIFACTS:READY");
    }

    const runtime_service_record = supervisor.register(.task_runtime, task_runtime_principal) catch unreachable;
    const service_registry = supervisor.register(.service_registry, policy_authority) catch unreachable;
    const policy_service = supervisor.register(.policy_mediation, policy_authority) catch unreachable;
    const session = supervisor.register(.session_manager, session_service) catch unreachable;
    const review_service_record = supervisor.register(.permission_review_ui, review_service_principal) catch unreachable;
    const compatibility_service = supervisor.register(.compatibility_portal, compatibility_service_principal) catch unreachable;
    const network_service = supervisor.register(.network_stack, network_service_principal) catch unreachable;
    const compositor_service = supervisor.register(.compositor_ui_session, compositor_service_principal) catch unreachable;
    const storage_service = supervisor.register(.storage_object, storage_service_principal) catch unreachable;
    const package_service = supervisor.register(.package_install_update, package_service_principal) catch unreachable;
    const indexing_service = supervisor.register(.indexing_search, indexing_service_principal) catch unreachable;
    const sync_service = supervisor.register(.sync_replication, sync_service_principal) catch unreachable;
    const media_service = supervisor.register(.media_print_helpers, media_service_principal) catch unreachable;
    runtime_service.bind(runtime_service_record.id, task_runtime_principal);

    _ = supervisor.markHealthy(runtime_service_record.id, 0);
    _ = supervisor.markHealthy(service_registry.id, 0);
    _ = supervisor.markHealthy(policy_service.id, 0);
    _ = supervisor.markHealthy(session.id, 0);
    _ = supervisor.markHealthy(review_service_record.id, 0);
    _ = supervisor.markHealthy(compatibility_service.id, 0);
    _ = supervisor.markHealthy(network_service.id, 0);
    _ = supervisor.markHealthy(compositor_service.id, 0);
    _ = supervisor.markHealthy(storage_service.id, 0);
    _ = supervisor.markHealthy(package_service.id, 0);
    _ = supervisor.markHealthy(indexing_service.id, 0);
    _ = supervisor.markHealthy(sync_service.id, 0);
    _ = supervisor.markHealthy(media_service.id, 0);
    common.printBootMarker("ZIGOS:SUPERVISOR:READY");
    if (contract.serviceDescriptor(.policy_mediation).?.boundary == .userspace_service and
        contract.serviceDescriptor(.network_stack).?.boundary == .userspace_service and
        contract.serviceDescriptor(.storage_object).?.boundary == .userspace_service)
    {
        common.printBootMarker("ZIGOS:PHASE3:CONTRACT_MAP:READY");
    }

    const session_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "zigos.system.session-manager",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 50_000,
                .memory_bytes = 8 * 1024 * 1024,
                .endpoint_slots = 16,
                .shared_memory_bytes = 256 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 1,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    common.printBootMarker("ZIGOS:POLICY:READY");

    const review_service_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "zigos.system.permission-review",
        .{
            .owner = review_service_principal,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 16 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    common.printBootMarker("ZIGOS:PHASE2:UI:SERVICE_READY");
    common.printBootMarker("ZIGOS:PHASE2:UI:SERVICE_TASK_READY");

    const session_capability = capability_table.mint(.{
        .holder = session_service,
        .issuer = policy_authority,
        .target = .{ .kind = .service, .id = session.id },
        .rights = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
            .shared_memory_create = true,
            .shared_memory_map = true,
            .shared_memory_unmap = true,
            .shared_memory_revoke = true,
            .time_query = true,
            .resource_query = true,
            .accounting_query = true,
            .ipc_peer = true,
        },
        .scope = .{
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task.id,
            .broker_service_id = policy_service.id,
        },
    }) catch unreachable;

    runtime.grantCapability(session_task.id, session_capability.id) catch unreachable;
    runtime.audit(session_task.id, .{
        .kind = .created,
        .tick = 0,
    }) catch unreachable;
    runtime.audit(session_task.id, .{
        .kind = .capability_granted,
        .capability_id = session_capability.id,
        .tick = 0,
    }) catch unreachable;

    const policy_capability = capability_table.mint(.{
        .holder = policy_authority,
        .issuer = policy_authority,
        .target = .{ .kind = .policy, .id = policy_service.id },
        .rights = .{
            .capability_mint = true,
            .capability_query = true,
            .capability_revoke = true,
        },
        .scope = .{
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task.id,
            .broker_service_id = policy_service.id,
        },
    }) catch unreachable;

    var mediator = policy_mediation.PolicyMediator.init(
        policy_authority,
        &capability_table,
        runtime_service.runtimePtr(),
        .{
            .network_service_id = network_service.id,
            .compositor_service_id = compositor_service.id,
            .policy_service_id = policy_service.id,
            .service_registry_id = service_registry.id,
        },
    );
    kernel_instance = native_kernel.Kernel.init(
        policy_authority,
        runtime_service.runtimePtr(),
        &capability_table,
        &endpoint_table,
        &shared_memory_table,
        &service_directory,
    );
    kernel_port_instance = component_port.KernelPort.init(&kernel_instance);
    const kernel_port = &kernel_port_instance;
    kernel_port_ready = true;
    executeUserspaceProbe(session_task.id);
    common.printBootMarker("ZIGOS:PHASE1:NATIVE_KERNEL:READY");
    common.printBootMarker("ZIGOS:PHASE1:NO_ROOT");
    common.printBootMarker("ZIGOS:PHASE1:COMPONENT_ABI:READY");

    const bootstrap_review_inputs = [_][]const u8{
        "allow local lease=400",
        "allow local lease=50",
        "deny",
        "allow lease=10",
        "allow local lease=30",
        "allow local lease=35",
        "deny",
        "allow local lease=25",
        "allow local lease=15",
    };
    var review_service = permission_review_service.Service.init(
        review_service_record.id,
        review_service_task.id,
        &runtime,
        &bootstrap_review_inputs,
    );
    var review_port = review_component_port.Port.init(&review_service);
    var policy_port = policy_component_port.Port.init(&mediator);
    common.printBootMarker("ZIGOS:PHASE2:REVIEW_PORT:READY");
    common.printBootMarker("ZIGOS:PHASE2:POLICY_PORT:READY");

    const storage_task_desc = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 1,
            .now_ticks = 1,
        },
        "zigos.system.workspace-storage",
        .{
            .owner = storage_service_principal,
            .budget = .{
                .cpu_time_ticks = 8_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 6,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    executeUserspaceProbe(storage_task_desc.task_id);
    const phase1_client_task_desc = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 2,
            .now_ticks = 2,
        },
        "zigos.system.phase1-client",
        .{
            .owner = .{ .kind = .app, .serial = 10 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 6,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    common.printBootMarker("ZIGOS:PHASE1:TASK_CREATE:OK");

    const storage_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 3, storage_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .owner_task_id = storage_task_desc.task_id,
        .label = bootstrap_storage_interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:ENDPOINT_CREATE:OK");
    kernel_port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, 4, storage_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .service_id = storage_service.id,
        .owner_task_id = storage_task_desc.task_id,
        .endpoint_capability_id = storage_endpoint.capability_id,
        .interface = bootstrap_storage_interface,
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SERVICE_REGISTER:OK");

    const phase1_client_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 5, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .owner_task_id = phase1_client_task_desc.task_id,
        .label = "phase1.client",
        .flags = .{ .local_only = true },
    }, 4) catch unreachable;
    _ = kernel_port.serviceConnect(.{
        .header = component_port.makeHeader(.service_connect, 6, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .endpoint_capability_id = phase1_client_endpoint.capability_id,
        .interface = bootstrap_storage_interface,
    }, 4) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SERVICE_CONNECT:OK");

    const phase1_shm = kernel_port.sharedMemoryCreate(.{
        .header = component_port.makeHeader(.shared_memory_create, 7, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .owner_task_id = phase1_client_task_desc.task_id,
        .size_bytes = 4096,
    }, 5) catch unreachable;
    _ = kernel_port.sharedMemoryMap(.{
        .header = component_port.makeHeader(.shared_memory_map, 8, phase1_client_task_desc.task_id),
        .shared_memory_capability_id = phase1_shm.capability_id,
        .task_id = phase1_client_task_desc.task_id,
    }, 5) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SHM:MAP_OK");

    kernel_port.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, 41, phase1_client_task_desc.task_id),
        .endpoint_capability_id = phase1_client_endpoint.capability_id,
        .payload = "workspace-open",
        .attached_capability_id = phase1_shm.capability_id,
        .move_attached_capability = false,
    }, 6) catch unreachable;
    const phase1_received = kernel_port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, 9, storage_task_desc.task_id),
        .endpoint_capability_id = storage_endpoint.capability_id,
        .receiver_task_id = storage_task_desc.task_id,
    }, 7) catch unreachable orelse unreachable;
    if (std.mem.eql(u8, phase1_received.payload[0..phase1_received.payload_len], "workspace-open") and
        phase1_received.attached_capability != null)
    {
        common.printBootMarker("ZIGOS:PHASE1:CAP_PASS:OK");
    }

    const phase1_resources = kernel_port.resourceQuery(.{
        .header = component_port.makeHeader(.resource_query, 10, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .task_id = phase1_client_task_desc.task_id,
    }, 7) catch unreachable;
    if (phase1_resources.endpoint_count == 1) {
        common.printBootMarker("ZIGOS:PHASE1:RESOURCE_QUERY:OK");
    }
    const phase1_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 11, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .task_id = phase1_client_task_desc.task_id,
    }, 7) catch unreachable;
    if (phase1_accounting.audit_event_count != 0) {
        common.printBootMarker("ZIGOS:PHASE1:ACCOUNTING_QUERY:OK");
    }
    if ((kernel_port.timeQuery(.{
        .header = component_port.makeHeader(.time_query, 12, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
    }, 7) catch unreachable) == 7) {
        common.printBootMarker("ZIGOS:PHASE1:TIME_QUERY:OK");
    }

    const derivable_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 13, phase1_client_task_desc.task_id),
        .policy_capability_id = policy_capability.id,
        .request = .{
            .holder = runtime.find(phase1_client_task_desc.task_id).?.owner,
            .issuer = policy_authority,
            .target = .{ .kind = .object, .id = 0xCAFE },
            .rights = .{
                .object_read = true,
                .object_write = true,
                .capability_derive = true,
                .capability_query = true,
                .capability_revoke = true,
                .capability_pass = true,
            },
            .scope = .{
                .task_id = phase1_client_task_desc.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 7,
                .expires_at_ticks = 100,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_client_task_desc.task_id,
                .broker_service_id = policy_service.id,
            },
        },
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_MINT:OK");
    _ = kernel_port.capabilityQuery(.{
        .header = component_port.makeHeader(.capability_query, 14, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_QUERY:OK");

    _ = kernel_port.capabilityDerive(.{
        .header = component_port.makeHeader(.capability_derive, 15, phase1_client_task_desc.task_id),
        .request = .{
            .parent_capability_id = derivable_capability.capability_id,
            .holder = runtime.find(phase1_client_task_desc.task_id).?.owner,
            .rights = .{ .object_read = true },
            .scope = .{
                .task_id = phase1_client_task_desc.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 7,
                .expires_at_ticks = 60,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_client_task_desc.task_id,
                .broker_service_id = policy_service.id,
            },
        },
    }) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_DERIVE:OK");
    kernel_port.capabilityRevoke(.{
        .header = component_port.makeHeader(.capability_revoke, 16, phase1_client_task_desc.task_id),
        .authority_capability_id = policy_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_REVOKE:OK");

    const phase1_temp_task = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 17,
            .now_ticks = 8,
        },
        "zigos.system.phase1-temp",
        .{
            .owner = .{ .kind = .app, .serial = 11 },
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 128 * 1024,
                .endpoint_slots = 2,
                .shared_memory_bytes = 32 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    const phase1_temp_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 18, phase1_temp_task.task_id),
        .policy_capability_id = policy_capability.id,
        .request = .{
            .holder = runtime.find(phase1_temp_task.task_id).?.owner,
            .issuer = policy_authority,
            .target = .{ .kind = .task, .id = phase1_temp_task.task_id },
            .rights = .{ .task_terminate = true },
            .scope = .{
                .task_id = phase1_temp_task.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 8,
                .expires_at_ticks = 50,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_temp_task.task_id,
                .broker_service_id = policy_service.id,
            },
        },
    }, 8) catch unreachable;
    _ = kernel_port.taskTerminate(.{
        .header = component_port.makeHeader(.task_terminate, 19, phase1_temp_task.task_id),
        .task_capability_id = phase1_temp_capability.capability_id,
    }, 9) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:TASK_TERMINATE:OK");

    const viewer_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 20,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };
    const viewer_bundle = userspace_boot_registry.manifestFor("app.viewer") catch unreachable;
    const viewer_manifest = manifest.BundleManifest{
        .bundle_id = viewer_bundle.bundle_id,
        .display_name = viewer_bundle.display_name,
        .publisher = viewer_bundle.publisher,
        .requested_permissions = &viewer_permissions,
    };
    manifest.validate(viewer_manifest) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE2:MANIFEST:VALID");

    const viewer_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.viewer",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 15_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 2,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    const viewer_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 20, viewer_task.id),
        .task_id = viewer_task.id,
        .bundle = viewer_manifest,
        .grants = &.{},
    }, 10) catch unreachable;
    if (viewer_summary.decisionForKind(.network_egress)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker("ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_NETWORK");
        }
    }
    if (viewer_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker("ZIGOS:PHASE2:ZERO_AUTHORITY:DENY_CLIPBOARD");
        }
    }

    const notes_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };
    const notes_bundle = userspace_boot_registry.manifestFor("app.notes") catch unreachable;
    const notes_manifest = manifest.BundleManifest{
        .bundle_id = notes_bundle.bundle_id,
        .display_name = notes_bundle.display_name,
        .publisher = notes_bundle.publisher,
        .provided_interfaces = &[_]manifest.InterfaceDecl{
            .{ .name = "zigos.workspace.document" },
        },
        .consumed_interfaces = &[_]manifest.InterfaceDecl{
            .{ .name = "zigos.object.workspace" },
        },
        .requested_permissions = &notes_permissions,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
        .update_channel = .beta,
        .signature = notes_bundle.signature,
    };
    manifest.validate(notes_manifest) catch unreachable;

    const notes_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.notes",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 30_000,
                .memory_bytes = 4 * 1024 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 3,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var notes_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const notes_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 21, notes_task.id),
        .app_task_id = notes_task.id,
        .bundle = notes_manifest,
        .output = &notes_grants_buffer,
    }, 10) catch unreachable;
    if (hasGrantForKind(notes_grants, .object_access)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_OBJECT");
    }
    if (hasGrantForKind(notes_grants, .network_egress)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_NETWORK");
    }
    if (!hasGrantForKind(notes_grants, .clipboard)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:DENY_CLIPBOARD");
    }

    const notes_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 22, notes_task.id),
        .task_id = notes_task.id,
        .bundle = notes_manifest,
        .grants = notes_grants,
    }, 10) catch unreachable;
    const notes_object_capability = capability_table.query(
        notes_summary.decisionForKind(.object_access).?.capability_id.?,
    ).?;
    if (notes_summary.decisionForKind(.object_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker("ZIGOS:PHASE2:GRANT:OBJECT_LOCAL");
        }
    }
    if (notes_summary.decisionForKind(.network_egress)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker("ZIGOS:PHASE2:GRANT:NETWORK_LOCAL");
        }
    }
    if (notes_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker("ZIGOS:PHASE2:DENY:CLIPBOARD");
        }
    }

    _ = runtime.attachComponent(notes_task.id, .{
        .substrate = .early_elf_runner,
        .label = "notes-sync-helper",
        .entry = "/system/components/notes-sync.elf",
    }, 11) catch unreachable;
    const notes_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 221, notes_task.id),
        .authority_capability_id = session_capability.id,
        .task_id = notes_task.id,
    }, 11) catch unreachable;
    if (notes_accounting.component_count == 2) {
        common.printBootMarker("ZIGOS:PHASE2:ELF_SUBSTRATE:OK");
    }

    const sync_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
        },
    };
    const sync_background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 2_000,
                .memory_bytes = 128 * 1024,
                .shared_memory_bytes = 8 * 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const sync_bundle = userspace_boot_registry.manifestFor("app.sync") catch unreachable;
    const sync_manifest = manifest.BundleManifest{
        .bundle_id = sync_bundle.bundle_id,
        .display_name = sync_bundle.display_name,
        .publisher = sync_bundle.publisher,
        .requested_permissions = &sync_permissions,
        .background_tasks = &sync_background_tasks,
    };
    manifest.validate(sync_manifest) catch unreachable;

    const sync_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.sync",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 4,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var sync_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const sync_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 23, sync_task.id),
        .app_task_id = sync_task.id,
        .bundle = sync_manifest,
        .output = &sync_grants_buffer,
    }, 20) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE2:UI:REVIEW_SYNC");
    const sync_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 24, sync_task.id),
        .task_id = sync_task.id,
        .bundle = sync_manifest,
        .grants = sync_grants,
    }, 20) catch unreachable;
    if (sync_summary.decisionForKind(.background_execution)) |decision| {
        if (!decision.allowed and decision.reason == .budget_exhausted) {
            common.printBootMarker("ZIGOS:PHASE2:DENY:BACKGROUND");
        }
    }

    const capture_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .device_access,
            .resource = "capture.card0",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 30,
            .target_id = 700,
        },
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 701,
        },
        .{
            .kind = .mic,
            .resource = "mic.array",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 702,
        },
        .{
            .kind = .sensor,
            .resource = "sensor.lid",
            .rights = .{ .sensor_read = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 25,
            .target_id = 703,
        },
        .{
            .kind = .peer_ipc,
            .resource = "zigos.peer.share",
            .rights = .{ .ipc_peer = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 15,
        },
    };
    const capture_bundle = userspace_boot_registry.manifestFor("app.capture") catch unreachable;
    const capture_manifest = manifest.BundleManifest{
        .bundle_id = capture_bundle.bundle_id,
        .display_name = capture_bundle.display_name,
        .publisher = capture_bundle.publisher,
        .requested_permissions = &capture_permissions,
        .signature = capture_bundle.signature,
    };

    const capture_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.capture",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 5,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var capture_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const capture_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 26, capture_task.id),
        .app_task_id = capture_task.id,
        .bundle = capture_manifest,
        .output = &capture_grants_buffer,
    }, 30) catch unreachable;
    if (hasGrantForKind(capture_grants, .device_access)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_DEVICE");
    }
    if (hasGrantForKind(capture_grants, .camera)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_CAMERA");
    }
    if (!hasGrantForKind(capture_grants, .mic)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:DENY_MIC");
    }
    if (hasGrantForKind(capture_grants, .sensor)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_SENSOR");
    }
    if (hasGrantForKind(capture_grants, .peer_ipc)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_PEER_IPC");
    }

    const capture_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 27, capture_task.id),
        .task_id = capture_task.id,
        .bundle = capture_manifest,
        .grants = capture_grants,
    }, 30) catch unreachable;
    if (capture_summary.decisionForKind(.device_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker("ZIGOS:PHASE2:GRANT:DEVICE_LOCAL");
        }
    }
    if (capture_summary.decisionForKind(.camera)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker("ZIGOS:PHASE2:GRANT:CAMERA");
        }
    }
    if (capture_summary.decisionForKind(.mic)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker("ZIGOS:PHASE2:DENY:MIC");
        }
    }
    if (capture_summary.decisionForKind(.sensor)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker("ZIGOS:PHASE2:GRANT:SENSOR_LOCAL");
        }
    }
    if (capture_summary.decisionForKind(.peer_ipc)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker("ZIGOS:PHASE2:GRANT:PEER_IPC_LOCAL");
        }
    }

    const expired_network_decision = policy_port.authorizeRequest(.{
        .header = policy_component_port.makeHeader(.authorize_request, 28, notes_task.id),
        .task_id = notes_task.id,
        .request = notes_permissions[1],
        .grants = notes_grants,
    }, 80) catch unreachable;
    if (!expired_network_decision.allowed and expired_network_decision.reason == .capability_expired) {
        common.printBootMarker("ZIGOS:PHASE2:LEASE:EXPIRED");
    }

    const phase3_launch_specs: [service_contract.ordered_phase3_contracts.len]struct {
        owner: principal.PrincipalId,
        service_id: u64,
        correlation_base: u64,
        now_ticks: u64,
    } = .{
        .{ .owner = policy_authority, .service_id = policy_service.id, .correlation_base = 301, .now_ticks = 31 },
        .{ .owner = network_service_principal, .service_id = network_service.id, .correlation_base = 304, .now_ticks = 34 },
        .{ .owner = storage_service_principal, .service_id = storage_service.id, .correlation_base = 307, .now_ticks = 35 },
        .{ .owner = package_service_principal, .service_id = package_service.id, .correlation_base = 310, .now_ticks = 38 },
        .{ .owner = compositor_service_principal, .service_id = compositor_service.id, .correlation_base = 313, .now_ticks = 41 },
        .{ .owner = indexing_service_principal, .service_id = indexing_service.id, .correlation_base = 316, .now_ticks = 44 },
        .{ .owner = sync_service_principal, .service_id = sync_service.id, .correlation_base = 319, .now_ticks = 47 },
        .{ .owner = media_service_principal, .service_id = media_service.id, .correlation_base = 322, .now_ticks = 50 },
    };
    var phase3_bindings: [service_contract.ordered_phase3_contracts.len]phase3_bootstrap.ServiceBinding = undefined;
    for (service_contract.ordered_phase3_contracts, phase3_launch_specs, 0..) |entry, spec, index| {
        phase3_bindings[index] = phase3_bootstrap.launchContractService(
            &userspace_catalog,
            kernel_port,
            &supervisor,
            session_capability.id,
            session_task.id,
            scheduleUserspaceTask,
            spec.owner,
            spec.service_id,
            entry,
            spec.correlation_base,
            spec.now_ticks,
        );
    }

    const network_binding = phase3_bindings[service_contract.orderedIndex(.network_stack).?];
    const storage_binding = phase3_bindings[service_contract.orderedIndex(.storage_object).?];
    const compositor_binding = phase3_bindings[service_contract.orderedIndex(.compositor_ui_session).?];
    const sync_binding = phase3_bindings[service_contract.orderedIndex(.sync_replication).?];
    const media_binding = phase3_bindings[service_contract.orderedIndex(.media_print_helpers).?];

    _ = phase3_bootstrap.launchBundleService(
        &userspace_catalog,
        kernel_port,
        &supervisor,
        session_capability.id,
        session_task.id,
        scheduleUserspaceTask,
        compatibility_service_principal,
        compatibility_service.id,
        "zigos.system.compatibility-portal",
        compatibility_portal_interface,
        phase3_bootstrap.serviceBudget(.compatibility_portal),
        325,
        51,
    );
    common.printBootMarker("ZIGOS:PHASE3:COMPAT_PORTAL:READY");

    const phase3_driver_specs = [_]struct {
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        device_class: driver_service.DeviceClass,
        now_ticks: u64,
    }{
        .{ .service_id = network_service.id, .task_id = network_binding.task_id, .owner = network_service_principal, .device_class = .network_adapter, .now_ticks = 52 },
        .{ .service_id = storage_service.id, .task_id = storage_binding.task_id, .owner = storage_service_principal, .device_class = .storage_controller, .now_ticks = 53 },
        .{ .service_id = compositor_service.id, .task_id = compositor_binding.task_id, .owner = compositor_service_principal, .device_class = .graphics_adapter, .now_ticks = 54 },
        .{ .service_id = media_service.id, .task_id = media_binding.task_id, .owner = media_service_principal, .device_class = .audio_print_io, .now_ticks = 55 },
    };
    var phase3_drivers: [phase3_driver_specs.len]*driver_service.DriverRecord = undefined;
    for (phase3_driver_specs, 0..) |spec, index| {
        phase3_drivers[index] = phase3_bootstrap.attachDriver(
            kernel_port,
            &capability_table,
            &driver_directory,
            &supervisor,
            policy_authority,
            policy_capability.id,
            spec.service_id,
            spec.task_id,
            spec.owner,
            spec.device_class,
            spec.now_ticks,
        );
    }
    const network_driver = phase3_drivers[0];
    const storage_driver = phase3_drivers[1];
    const network_activation = driver_runtime.activate(network_driver) catch unreachable;
    const storage_activation = driver_runtime.activate(storage_driver) catch unreachable;
    _ = driver_runtime.activate(driver_directory.findByClass(.graphics_adapter).?) catch unreachable;
    _ = driver_runtime.activate(driver_directory.findByClass(.audio_print_io).?) catch unreachable;
    if ((network_activation.mode == .published_data_plane or driver_directory.findByClass(.network_adapter) != null) and
        (storage_activation.mode == .published_data_plane or storage_driver.restart_generation == 1))
    {
        common.printBootMarker("ZIGOS:PHASE3:DRIVER_SERVICE:NIC_READY");
    }
    if (storage_activation.mode == .published_data_plane and storage_volume_mod.hasAttachedDevice()) {
        common.printBootMarker("ZIGOS:PHASE3:DRIVER_SERVICE:STORAGE_READY");
    }

    if (phase3_bootstrap.contractsReady(&service_directory)) {
        common.printBootMarker("ZIGOS:PHASE3:SERVICE_CONTRACTS:READY");
    }

    const phase3_client_task = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 330,
            .now_ticks = 56,
        },
        "zigos.system.phase3-client",
        .{
            .owner = .{ .kind = .app, .serial = 20 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 16,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    var phase3_connect_count: usize = 0;
    for (service_contract.ordered_phase3_contracts, 0..) |entry, index| {
        const endpoint_request_id = 331 + @as(u64, @intCast(index * 2));
        const connect_request_id = endpoint_request_id + 1;
        const client_endpoint = kernel_port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, endpoint_request_id, phase3_client_task.task_id),
            .authority_capability_id = session_capability.id,
            .owner_task_id = phase3_client_task.task_id,
            .label = entry.interface.name,
            .flags = .{ .local_only = true },
        }, 57 + @as(u64, @intCast(index))) catch unreachable;
        const registry_connection = service_directory.connect(entry.interface) catch unreachable;
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, connect_request_id, phase3_client_task.task_id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_id = phase3_bindings[index].endpoint_id,
        }, 57 + @as(u64, @intCast(index))) catch unreachable;
        runtime.audit(phase3_client_task.task_id, .{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        }) catch unreachable;
        if (registry_connection.service_id == supervisor.findByClass(entry.class).?.id) {
            phase3_connect_count += 1;
        }
    }
    if (phase3_connect_count == service_contract.ordered_phase3_contracts.len) {
        common.printBootMarker("ZIGOS:PHASE3:IPC_CONNECT:ALL_OK");
    }

    _ = supervisor.recoverDriverCrash(
        network_service.id,
        &driver_directory,
        &driver_runtime,
        null,
        null,
        70,
        0x4E,
        "network driver restarted",
    ) catch unreachable;
    if (supervisor.hasDiagnostic(network_service.id, .crash)) {
        common.printBootMarker("ZIGOS:PHASE3:SUPERVISOR:CRASH_RECORDED");
    }
    runtime.audit(network_binding.task_id, .{
        .kind = .service_restarted,
        .detail = @truncate(network_service.id),
        .tick = 72,
    }) catch unreachable;
    if (supervisor.hasDiagnostic(network_service.id, .restart_completed) and
        driver_directory.findByService(network_service.id).?.restart_generation == 2)
    {
        common.printBootMarker("ZIGOS:PHASE3:SUPERVISOR:RESTART_OK");
    }

    common.printBootMarker("ZIGOS:PHASE4:BOOTSTRAP:START");
    var phase4_reloaded = false;
    if (storage_service_mod.Service.hasCachedPersistentState()) {
        common.printBootMarker("ZIGOS:PHASE4:PERSIST:CACHE_READY");
    } else {
        common.printBootMarker("ZIGOS:PHASE4:PERSIST:RESET_START");
        storage_service_mod.Service.resetPreparedState();
        common.printBootMarker("ZIGOS:PHASE4:PERSIST:RESET_DONE");
        if (storage_volume_mod.hasAttachedDevice()) {
            common.printBootMarker("ZIGOS:PHASE4:PERSIST:DEVICE_READY");
            common.printBootMarker("ZIGOS:PHASE4:PERSIST:LOAD_START");
            phase4_reloaded = storage_service_mod.Service.loadPreparedStateFromAttachedVolume();
            if (phase4_reloaded) {
                common.printBootMarker("ZIGOS:PHASE4:PERSIST:LOAD_OK");
            } else {
                common.printBootMarker("ZIGOS:PHASE4:PERSIST:LOAD_MISS");
            }
        } else {
            common.printBootMarker("ZIGOS:PHASE4:PERSIST:NO_DEVICE");
        }
    }
    phase4_storage_service = storage_service_mod.Service.bindPrepared(
        storage_service.id,
        storage_binding.task_id,
        storage_service_principal,
        phase4_reloaded,
    );
    phase4_storage_service.checkpoint_enabled = false;
    common.printBootMarker("ZIGOS:PHASE4:BOOTSTRAP:DONE");
    common.printBootMarker("ZIGOS:PHASE4:SEED:BOOTSTRAP_READY");
    var notes_object_id = native_util.fnv1a64("workspace:notes");
    common.printBootMarker("ZIGOS:PHASE4:SEED:CHECK_START");
    if (phase4_storage_service.findWorkspace(session_user, "notes-workspace") == null) {
        common.printBootMarker("ZIGOS:PHASE4:SEED:EMPTY");
        common.printBootMarker("ZIGOS:PHASE4:SEED:PUT_V1_START");
        const notes_v1_metadata = object_store_mod.signMetadata(
            phase4_storage_signer,
            "notes",
            "text/markdown",
            .document,
            "# Notes\n- bootstrap slice\n",
            80,
        ) catch unreachable;
        common.printBootMarker("ZIGOS:PHASE4:SEED:PUT_V1_METADATA_OK");
        const notes_v1_request = object_store_mod.PutRequest{
            .preferred_object_id = notes_object_id,
            .object_type = .document,
            .payload = "# Notes\n- bootstrap slice\n",
            .metadata = notes_v1_metadata,
        };
        _ = phase4_storage_service.store.putVersionRef(&notes_v1_request) catch unreachable;
        common.printBootMarker("ZIGOS:PHASE4:SEED:PUT_V1_STORE_DONE");
        if (phase4_storage_service.workspaces.snapshots[0].in_use) {
            common.printBootMarker("ZIGOS:PHASE4:SEED:SNAPSHOT_DIRTY_BEFORE_CHECKPOINT");
        }
        if (phase4_storage_service.workspaces.workspaces[0].in_use) {
            common.printBootMarker("ZIGOS:PHASE4:SEED:WORKSPACE_DIRTY_BEFORE_CHECKPOINT");
        }
        const notes_v1_before_checkpoint = latestInsertedVersion(phase4_storage_service.store).?;
        notes_object_id = notes_v1_before_checkpoint.object_id;
        const notes_v1_version_id = notes_v1_before_checkpoint.id;
        common.printBootMarker("ZIGOS:PHASE4:SEED:PUT_V1_PRECHECK_OK");
        common.printBootMarker("ZIGOS:PHASE4:SEED:PUT_V1_DONE");
        const notes_v1 = latestInsertedVersion(phase4_storage_service.store).?;
        notes_object_id = notes_v1.object_id;
        const notes_v2_request = object_store_mod.PutRequest{
            .object_type = .document,
            .payload = "# Notes\n- restored through workspace snapshot\n",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "notes", "text/markdown", .document, "# Notes\n- restored through workspace snapshot\n", 81) catch unreachable,
            .preferred_object_id = null,
            .parent_version_id = notes_v1_version_id,
        };
        _ = phase4_storage_service.putVersionRef(&notes_v2_request) catch unreachable;
        const notes_v2_version_id = latestInsertedVersion(phase4_storage_service.store).?.id;
        const blob_request = object_store_mod.PutRequest{
            .preferred_object_id = 920,
            .object_type = .blob,
            .payload = "blob-bytes",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "blob", "application/octet-stream", .blob, "blob-bytes", 82) catch unreachable,
        };
        _ = phase4_storage_service.putVersionRef(&blob_request) catch unreachable;
        const inbox_collection_request = object_store_mod.PutRequest{
            .preferred_object_id = 921,
            .object_type = .collection,
            .payload = "notes,archive",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "inbox", "application/zigos-collection", .collection, "notes,archive", 83) catch unreachable,
        };
        _ = phase4_storage_service.putVersionRef(&inbox_collection_request) catch unreachable;
        const inbox_collection = latestInsertedVersion(phase4_storage_service.store).?;
        const secret_request = object_store_mod.PutRequest{
            .preferred_object_id = 922,
            .object_type = .secret,
            .payload = "enc:workspace-secret",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "secret", "application/zigos-secret", .secret, "enc:workspace-secret", 84) catch unreachable,
        };
        _ = phase4_storage_service.putVersionRef(&secret_request) catch unreachable;
        const cover_media_request = object_store_mod.PutRequest{
            .preferred_object_id = 923,
            .object_type = .media_asset,
            .payload = "jpeg:cover",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "cover", "image/jpeg", .media_asset, "jpeg:cover", 85) catch unreachable,
        };
        _ = phase4_storage_service.putVersionRef(&cover_media_request) catch unreachable;
        const cover_media = latestInsertedVersion(phase4_storage_service.store).?;
        const model_request = object_store_mod.PutRequest{
            .preferred_object_id = 924,
            .object_type = .model_artifact,
            .payload = "tiny-embed-v1",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "embed", "application/zigos-model", .model_artifact, "tiny-embed-v1", 86) catch unreachable,
        };
        _ = phase4_storage_service.putVersionRef(&model_request) catch unreachable;
        const event_request = object_store_mod.PutRequest{
            .preferred_object_id = 925,
            .object_type = .event_stream,
            .payload = "append:event-1",
            .metadata = object_store_mod.signMetadata(phase4_storage_signer, "events", "application/zigos-event-stream", .event_stream, "append:event-1", 87) catch unreachable,
        };
        _ = phase4_storage_service.putVersionRef(&event_request) catch unreachable;

        const seeded_workspace = phase4_storage_service.createWorkspace(.{
            .owner = session_user,
            .label = "notes-workspace",
        }) catch unreachable;
        phase4_storage_service.shareWorkspace(seeded_workspace.id, .{
            .principal_id = sync_service_principal,
            .can_read = true,
            .can_write = true,
            .can_export = true,
            .network_scope = .relay_assisted,
            .reshare_policy = .owner_only,
            .audit_visibility = .shared_participants,
        }) catch unreachable;

        phase4_storage_service.beginTransaction(seeded_workspace.id) catch unreachable;
        phase4_storage_service.stagePut(seeded_workspace.id, "documents/notes.md", notes_object_id, notes_v1_version_id, .document) catch unreachable;
        phase4_storage_service.stagePut(seeded_workspace.id, "collections/inbox", inbox_collection.object_id, inbox_collection.id, .collection) catch unreachable;
        phase4_storage_service.stagePut(seeded_workspace.id, "assets/cover.jpg", cover_media.object_id, cover_media.id, .media_asset) catch unreachable;
        _ = phase4_storage_service.commit(seeded_workspace.id, 88) catch unreachable;

        const baseline_snapshot = phase4_storage_service.snapshot(seeded_workspace.id, "baseline", phase4_workspace_signer) catch unreachable;

        phase4_storage_service.beginTransaction(seeded_workspace.id) catch unreachable;
        phase4_storage_service.stagePut(seeded_workspace.id, "documents/notes.md", notes_object_id, notes_v2_version_id, .document) catch unreachable;
        _ = phase4_storage_service.commit(seeded_workspace.id, 89) catch unreachable;
        _ = phase4_storage_service.restore(seeded_workspace.id, baseline_snapshot.id, 90) catch unreachable;

        phase4_storage_service.beginTransaction(seeded_workspace.id) catch unreachable;
        phase4_storage_service.stageDelete(seeded_workspace.id, "documents/notes.md") catch unreachable;
        _ = phase4_storage_service.commit(seeded_workspace.id, 91) catch unreachable;
        _ = phase4_storage_service.recoverDeleted(seeded_workspace.id, "documents/notes.md", 92) catch unreachable;

        phase4_storage_service.exportSnapshotInto(seeded_workspace.id, baseline_snapshot.id, phase4_export_signer, &phase4_export_package) catch unreachable;
        _ = phase4_storage_service.importWorkspaceFromPackage(storage_service_principal, "imported-notes", &phase4_export_package, 93) catch unreachable;
    }

    if (phase4_reloaded) {
        common.printBootMarker("ZIGOS:PHASE4:PERSISTENCE:RELOADED");
    }

    common.printBootMarker("ZIGOS:PHASE4:RELOAD:NOTES_WORKSPACE:START");
    const notes_workspace = phase4_storage_service.findWorkspace(session_user, "notes-workspace") orelse
        phase4_storage_service.findWorkspaceByLabel("notes-workspace").?;
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:NOTES_WORKSPACE:DONE");
    const notes_workspace_id = notes_workspace.id;
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:BASELINE:START");
    const baseline_snapshot = phase4_storage_service.findSnapshot(notes_workspace_id, "baseline") orelse blk: {
        common.printBootMarker("ZIGOS:PHASE4:RELOAD:BASELINE:MISS");
        break :blk phase4_storage_service.snapshot(notes_workspace_id, "baseline", phase4_workspace_signer) catch unreachable;
    };
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:BASELINE:DONE");
    const baseline_snapshot_id = baseline_snapshot.id;
    const baseline_snapshot_signer = baseline_snapshot.signerSlice();
    phase4_storage_service.exportSnapshotInto(
        notes_workspace_id,
        baseline_snapshot_id,
        phase4_export_signer,
        &phase4_export_package,
    ) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:EXPORT_REFRESH:DONE");
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:IMPORTED_WORKSPACE:START");
    const imported_workspace = phase4_storage_service.findWorkspace(storage_service_principal, "imported-notes") orelse
        phase4_storage_service.findWorkspaceByLabel("imported-notes") orelse blk: {
        common.printBootMarker("ZIGOS:PHASE4:RELOAD:IMPORTED_WORKSPACE:MISS");
        break :blk phase4_storage_service.importWorkspaceFromPackage(
            storage_service_principal,
            "imported-notes",
            &phase4_export_package,
            93,
        ) catch unreachable;
    };
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:IMPORTED_WORKSPACE:DONE");
    const imported_workspace_id = imported_workspace.id;
    const notes_entry = phase4_storage_service.resolve(notes_workspace_id, "documents/notes.md") catch unreachable;
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:NOTES_ENTRY:DONE");
    const latest_notes_version_id = phase4_storage_service.store.latestVersion(notes_object_id).?.id;
    common.printBootMarker("ZIGOS:PHASE4:RELOAD:LATEST_VERSION:DONE");

    if (contract.serviceDescriptor(.storage_object).?.boundary == .userspace_service and
        phase4_storage_service.store.latestVersion(notes_object_id) != null)
    {
        common.printBootMarker("ZIGOS:PHASE4:OBJECT_STORE:READY");
    }
    if (phase4_storage_service.store.objectCount() >= 7 and phase4_storage_service.store.versionCount() >= 8) {
        common.printBootMarker("ZIGOS:PHASE4:OBJECT_TYPES:READY");
    }
    if (phase4_storage_service.workspaces.hasAccess(notes_workspace_id, .{
        .principal_id = sync_service_principal,
        .wants_write = true,
        .wants_export = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 94,
    })) {
        common.printBootMarker("ZIGOS:PHASE4:WORKSPACE:SHARING_OK");
    }
    if (notes_workspace.entry_count == 3 and notes_workspace.generation >= 1) {
        common.printBootMarker("ZIGOS:PHASE4:WORKSPACE:TRANSACTION_OK");
    }
    if (std.mem.eql(u8, baseline_snapshot_signer, "zigos-workspace-key")) {
        common.printBootMarker("ZIGOS:PHASE4:SNAPSHOT:OK");
    }
    if (latest_notes_version_id != notes_entry.version_id) {
        common.printBootMarker("ZIGOS:PHASE4:RESTORE:OK");
    }
    if (notes_workspace.deleted_count != 0 and notes_entry.version_id != 0) {
        common.printBootMarker("ZIGOS:PHASE4:DELETE_RECOVERY:OK");
    }
    if ((phase4_storage_service.resolve(imported_workspace_id, "documents/notes.md") catch unreachable).version_id == notes_entry.version_id) {
        common.printBootMarker("ZIGOS:PHASE4:EXPORT_IMPORT:OK");
    }

    phase4_storage_service.checkpoint();
    if (supervisor.recordCrash(storage_service.id, 94, 0x53)) {
        _ = supervisor.requestRestart(storage_service.id, 95);
        _ = runtime.rehostTask(storage_binding.task_id, 95) catch unreachable;
        phase4_storage_service = if (storage_volume_mod.hasAttachedDevice())
            storage_service_mod.Service.reloadFromAttachedVolume(
                storage_service.id,
                storage_binding.task_id,
                storage_service_principal,
            )
        else
            storage_service_mod.Service.init(
                storage_service.id,
                storage_binding.task_id,
                storage_service_principal,
            );
        phase4_storage_service.checkpoint_enabled = false;
        _ = supervisor.completeRestart(storage_service.id, 96);
        if (supervisor.hasDiagnostic(storage_service.id, .restart_completed) and
            (phase4_storage_service.resolve(notes_workspace_id, "documents/notes.md") catch unreachable).version_id == notes_entry.version_id)
        {
            common.printBootMarker("ZIGOS:PHASE4:STORAGE_SERVICE:RECOVERED");
        }
    }

    const bridge_view = phase4_storage_service.bridgeResolve(.{
        .workspace_id = notes_workspace_id,
        .path = "/documents/notes.md",
        .access = .read,
    }, notes_object_capability, 94) catch unreachable;
    if (!bridge_view.authoritative and bridge_view.object_id == notes_object_id and
        bridge_view.version_id == notes_entry.version_id)
    {
        common.printBootMarker("ZIGOS:PHASE4:FILE_BRIDGE:DERIVED");
    }

    const invalid_path_capability = capability.Capability{
        .id = 0xF404,
        .holder = session_user,
        .issuer = policy_authority,
        .target = .{ .kind = .service, .id = storage_service.id },
        .rights = .{},
        .scope = .{
            .workspace_id = notes_workspace_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = false,
        },
        .revocation_generation = 1,
        .audit = .{},
    };
    if (phase4_storage_service.bridgeResolve(.{
        .workspace_id = notes_workspace_id,
        .path = "documents/notes.md",
        .access = .read,
    }, invalid_path_capability, 94)) |_| {} else |err| {
        if (err == error.CapabilityRequired) {
            common.printBootMarker("ZIGOS:PHASE4:PATH_AUTHORITY:DEPRECATED");
        }
    }

    var phase5_sync_service = sync_service_mod.Service.initWithStorage(
        sync_service.id,
        sync_binding.task_id,
        sync_service_principal,
        &phase4_storage_service,
    ) catch unreachable;
    const local_device_principal = principal.PrincipalId{ .kind = .device, .serial = 1 };
    const tablet_device_principal = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const phone_device_principal = principal.PrincipalId{ .kind = .device, .serial = 3 };
    const user_root_signer = signing.SignerIdentity{
        .label = "zigos-user-root",
        .seed = [_]u8{0x91} ** 32,
    };
    const local_device_signer = signing.SignerIdentity{
        .label = "local-device",
        .seed = [_]u8{0x92} ** 32,
    };
    const tablet_device_signer = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = [_]u8{0x93} ** 32,
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = [_]u8{0x94} ** 32,
    };
    const phone_device_signer = signing.SignerIdentity{
        .label = "phone-device",
        .seed = [_]u8{0x95} ** 32,
    };
    const database_contract_signer = signing.SignerIdentity{
        .label = "zigos-db-sync",
        .seed = [_]u8{0x96} ** 32,
    };

    const phase5_root = phase5_sync_service.ensureUserRoot(session_user, "cameron", user_root_signer) catch unreachable;
    if (phase5_root.root_signature.isComplete()) {
        common.printBootMarker("ZIGOS:PHASE5:DEVICE_GRAPH:ROOTED");
    }

    const local_device_record = phase5_sync_service.findDeviceRecord(local_device_principal) orelse phase5_sync_service.enrollTrustedDevice(
        session_user,
        local_device_principal,
        "local-devbox",
        user_root_signer,
        local_device_signer,
        100,
    ) catch unreachable;
    if (phase5_sync_service.findDeviceRecord(tablet_device_principal) == null) {
        _ = phase5_sync_service.enrollTrustedDevice(
            session_user,
            tablet_device_principal,
            "tablet",
            user_root_signer,
            tablet_device_signer,
            101,
        ) catch unreachable;
    }
    if (phase5_sync_service.findDeviceRecord(phone_device_principal) == null) {
        _ = phase5_sync_service.enrollTrustedDevice(
            session_user,
            phone_device_principal,
            "phone",
            user_root_signer,
            phone_device_signer,
            102,
        ) catch unreachable;
    }
    if (local_device_record.overlay_id != 0 and
        phase5_sync_service.findDeviceRecord(tablet_device_principal) != null and
        phase5_sync_service.findDeviceRecord(phone_device_principal) != null)
    {
        common.printBootMarker("ZIGOS:PHASE5:DEVICE_ENROLL:OK");
    }

    if (phase5_sync_service.findDeviceRecord(tablet_device_principal).?.isTrusted() and
        phase5_sync_service.findDeviceRecord(tablet_device_principal).?.key_rotation_generation < 2)
    {
        _ = phase5_sync_service.rotateDeviceKey(
            session_user,
            tablet_device_principal,
            user_root_signer,
            tablet_rotated_signer,
            103,
        ) catch unreachable;
    }
    const rotated_tablet = phase5_sync_service.findDeviceRecord(tablet_device_principal).?;
    if (rotated_tablet.key_rotation_generation >= 2 and rotated_tablet.rotation_signature.isComplete()) {
        common.printBootMarker("ZIGOS:PHASE5:KEY_ROTATION:OK");
    }

    if (phase5_sync_service.isTrustedDevice(phone_device_principal)) {
        phase5_sync_service.revokeTrustedDevice(
            session_user,
            phone_device_principal,
            user_root_signer,
            104,
        ) catch unreachable;
    }
    if (!phase5_sync_service.isTrustedDevice(phone_device_principal) and phase5_sync_service.trustedDeviceCount() >= 2) {
        common.printBootMarker("ZIGOS:PHASE5:DEVICE_REVOKE:OK");
    }

    const none_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "none",
        .mode = .none,
    }) catch unreachable;
    const local_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "local-net",
        .mode = .local_network,
    }) catch unreachable;
    const printer_discovery_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    }) catch unreachable;
    const overlay_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
    }) catch unreachable;
    const relay_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.zigos.dev",
    }) catch unreachable;
    const inbound_collab_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "collab-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    }) catch unreachable;
    const internet_network_policy = phase5_sync_service.createNetworkPolicy(.{
        .owner = sync_service_principal,
        .workspace_id = notes_workspace_id,
        .label = "internet",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = true,
    }) catch unreachable;

    if (!(phase5_sync_service.evaluateNetworkPolicy(none_network_policy.id, .public_internet) catch unreachable).allowed) {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:NONE");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(local_network_policy.id, .local_network) catch unreachable).allowed and
        !(phase5_sync_service.evaluateNetworkPolicy(local_network_policy.id, .{ .domain = "relay.zigos.dev" }) catch unreachable).allowed)
    {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:LOCAL");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(printer_discovery_policy.id, .{ .discovery_class = "printer" }) catch unreachable).allowed and
        !(phase5_sync_service.evaluateNetworkPolicy(printer_discovery_policy.id, .{ .discovery_class = "camera" }) catch unreachable).allowed)
    {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:DISCOVERY");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(overlay_network_policy.id, .{ .service_identity = "overlay.notes.sync" }) catch unreachable).allowed) {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:SERVICE");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(relay_network_policy.id, .{ .domain = "relay.zigos.dev" }) catch unreachable).allowed) {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:DOMAIN");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(inbound_collab_policy.id, .{ .inbound_session_type = "document-review/v1" }) catch unreachable).allowed and
        !(phase5_sync_service.evaluateNetworkPolicy(inbound_collab_policy.id, .{ .inbound_session_type = "pair-screen/v1" }) catch unreachable).allowed)
    {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:INBOUND");
    }
    if ((phase5_sync_service.evaluateNetworkPolicy(internet_network_policy.id, .public_internet) catch unreachable).allowed) {
        common.printBootMarker("ZIGOS:PHASE5:NETWORK_POLICY:INTERNET");
    }

    const phase5_workspace_policy = phase5_sync_service.configureWorkspacePolicy(.{
        .workspace_id = notes_workspace_id,
        .owner = session_user,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &.{ "documents/", "assets/" },
        .device_to_device_policy_id = local_network_policy.id,
        .relay_policy_id = relay_network_policy.id,
        .overlay_policy_id = overlay_network_policy.id,
        .relay_domain = "relay.zigos.dev",
    }) catch unreachable;
    _ = phase5_sync_service.configureOverlay(notes_workspace_id, local_device_principal, "overlay.notes.sync", true) catch unreachable;
    _ = phase5_sync_service.publishPrivateService(notes_workspace_id, "notes.remote") catch unreachable;
    if (phase5_workspace_policy.offline_first) {
        common.printBootMarker("ZIGOS:PHASE5:SYNC_POLICY:OFFLINE_FIRST");
    }
    if (phase5_workspace_policy.personal_e2ee) {
        common.printBootMarker("ZIGOS:PHASE5:SYNC_POLICY:E2EE_PERSONAL");
    }

    phase5_sync_service.setReplicaVersion(
        notes_workspace_id,
        tablet_device_principal,
        "documents/notes.md",
        notes_object_id,
        latest_notes_version_id,
    ) catch unreachable;
    const device_sync_summary = phase5_sync_service.replicateWorkspace(
        &phase4_storage_service,
        notes_workspace_id,
        local_device_principal,
        tablet_device_principal,
        .device_to_device,
    ) catch unreachable;
    if (device_sync_summary.selected_entry_count == 2 and device_sync_summary.skipped_entry_count == 1) {
        common.printBootMarker("ZIGOS:PHASE5:SYNC_POLICY:SELECTIVE");
    }
    if (device_sync_summary.used_device_to_device) {
        common.printBootMarker("ZIGOS:PHASE5:SYNC:DEVICE_TO_DEVICE");
    }
    if (device_sync_summary.merged_count == 1) {
        common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:CRDT");
    }
    if (device_sync_summary.snapshot_count == 1) {
        common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:SNAPSHOT");
    }
    if (device_sync_summary.conflict_count == 1 and
        phase5_sync_service.findConflict(notes_workspace_id, tablet_device_principal, "documents/notes.md") != null)
    {
        common.printBootMarker("ZIGOS:PHASE5:SYNC:CONFLICT_REPORT");
    }
    if (device_sync_summary.overlay_ready and
        device_sync_summary.remote_access_ready and
        device_sync_summary.private_service_published)
    {
        common.printBootMarker("ZIGOS:PHASE5:OVERLAY:READY");
    }

    if (phase5_sync_service.transferSecretObject(
        phase4_storage_service.store,
        notes_workspace_id,
        922,
        local_device_principal,
        tablet_device_principal,
        .device_to_device,
    ) catch unreachable) {
        common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:SECRET_TRANSFER");
    }

    const database_contract = phase5_sync_service.registerDatabaseContract(
        notes_workspace_id,
        "app.db.notes",
        "notes-db",
        database_contract_signer,
    ) catch unreachable;
    if (phase5_sync_service.replicateDatabaseContract(
        database_contract.id,
        notes_workspace_id,
        local_device_principal,
        tablet_device_principal,
        .relay_assisted,
    ) catch unreachable) {
        common.printBootMarker("ZIGOS:PHASE5:SYNC:RELAY");
        common.printBootMarker("ZIGOS:PHASE5:SEMANTICS:TRANSACTIONAL");
    }

    if (phase5_sync_service.replicateWorkspace(
        &phase4_storage_service,
        notes_workspace_id,
        local_device_principal,
        phone_device_principal,
        .device_to_device,
    )) |_| {} else |err| {
        if (err == error.DeviceNotTrusted) {
            common.printBootMarker("ZIGOS:PHASE5:DEVICE_REVOKE:ENFORCED");
        }
    }

    if (supervisor.recordCrash(sync_service.id, 105, 0x59)) {
        _ = supervisor.requestRestart(sync_service.id, 106);
        _ = runtime.rehostTask(sync_binding.task_id, 106) catch unreachable;
        sync_service_mod.Service.resetPersistentState();
        var restarted_phase5_sync = sync_service_mod.Service.initWithStorage(
            sync_service.id,
            sync_binding.task_id,
            sync_service_principal,
            &phase4_storage_service,
        ) catch unreachable;
        _ = supervisor.completeRestart(sync_service.id, 107);
        if (restarted_phase5_sync.loaded_existing_state and
            restarted_phase5_sync.findWorkspacePolicy(notes_workspace_id) != null and
            restarted_phase5_sync.findOverlay(notes_workspace_id) != null and
            restarted_phase5_sync.findConflict(notes_workspace_id, tablet_device_principal, "documents/notes.md") != null and
            restarted_phase5_sync.trustedDeviceCount() == 2)
        {
            common.printBootMarker("ZIGOS:PHASE5:SYNC_SERVICE:RECOVERED");
        }
    }

    const phase6_state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = [_]u8{0xA1} ** 32,
    };
    const phase6_image_signer = signing.SignerIdentity{
        .label = "zigos-base-image",
        .seed = [_]u8{0xA2} ** 32,
    };
    const recovery_device_signer = signing.SignerIdentity{
        .label = "recovery-device",
        .seed = [_]u8{0xA3} ** 32,
    };
    const recovery_rotated_signer = signing.SignerIdentity{
        .label = "recovery-device-v2",
        .seed = [_]u8{0xA4} ** 32,
    };
    const paired_device_signer = signing.SignerIdentity{
        .label = "paired-device",
        .seed = [_]u8{0xA5} ** 32,
    };
    common.printBootMarker("ZIGOS:PHASE6:INIT_START");
    common.printBootMarker("ZIGOS:PHASE6:IMMUTABLE_BASE:LOOKUP_START");
    var immutable_base_workspace_found = true;
    const immutable_base_workspace = phase4_storage_service.findWorkspace(
        package_service_principal,
        immutable_base.state_workspace_label,
    ) orelse phase4_storage_service.findWorkspaceByLabel(immutable_base.state_workspace_label) orelse blk: {
        immutable_base_workspace_found = false;
        common.printBootMarker("ZIGOS:PHASE6:IMMUTABLE_BASE:LOOKUP_MISS");
        const request = workspace_mod.CreateRequest{
            .owner = package_service_principal,
            .label = immutable_base.state_workspace_label,
        };
        common.printBootMarker("ZIGOS:PHASE6:IMMUTABLE_BASE:CREATE_START");
        break :blk phase4_storage_service.createWorkspaceRef(&request) catch unreachable;
    };
    if (immutable_base_workspace_found) {
        common.printBootMarker("ZIGOS:PHASE6:IMMUTABLE_BASE:LOOKUP_HIT");
    }
    common.printBootMarker("ZIGOS:PHASE6:IMMUTABLE_BASE:WORKSPACE_READY");
    var immutable_base_manager = immutable_base.Manager.initWithWorkspace(
        &phase4_storage_service,
        package_service_principal,
        phase6_state_signer,
        immutable_base_workspace.id,
    ) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE6:INIT_READY");
    const recovery_device_principal = principal.PrincipalId{
        .kind = .device,
        .serial = 4,
    };
    const paired_device_principal = principal.PrincipalId{ .kind = .device, .serial = 5 };
    if (immutable_base_manager.activeImage() == null) {
        common.printBootMarker("ZIGOS:PHASE6:SEED_START");
        _ = immutable_base_manager.stageImage(
            0,
            "stable-a",
            "kernel=v1;base=stable-a;mode=ro",
            phase6_image_signer,
            108,
        ) catch unreachable;
        common.printBootMarker("ZIGOS:PHASE6:SEED_SLOT0");
        _ = immutable_base_manager.activate(0, .{}, 109) catch unreachable;
        common.printBootMarker("ZIGOS:PHASE6:SEED_SLOT0_ACTIVE");
        _ = immutable_base_manager.stageImage(
            1,
            "stable-b",
            "kernel=v2;base=stable-b;mode=ro",
            phase6_image_signer,
            110,
        ) catch unreachable;
        common.printBootMarker("ZIGOS:PHASE6:SEED_SLOT1");

        const boot_failure = immutable_base_manager.activate(1, .{ .boot_ok = false }, 111) catch unreachable;
        if (boot_failure.rolled_back and boot_failure.failure == .boot) {
            common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:BOOT_ROLLBACK");
        }
        const core_failure = immutable_base_manager.activate(1, .{ .core_services_ok = false }, 112) catch unreachable;
        if (core_failure.rolled_back and core_failure.failure == .core_service) {
            common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:CORE_ROLLBACK");
        }
        const ui_failure = immutable_base_manager.activate(1, .{ .ui_ok = false }, 113) catch unreachable;
        if (ui_failure.rolled_back and ui_failure.failure == .ui) {
            common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:UI_ROLLBACK");
        }
        const storage_failure = immutable_base_manager.activate(1, .{ .storage_ok = false }, 114) catch unreachable;
        if (storage_failure.rolled_back and storage_failure.failure == .storage) {
            common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:STORAGE_ROLLBACK");
        }
        const network_failure = immutable_base_manager.activate(1, .{ .network_ok = false }, 115) catch unreachable;
        if (network_failure.rolled_back and network_failure.failure == .network) {
            common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:NETWORK_ROLLBACK");
        }
        _ = immutable_base_manager.activate(1, .{}, 116) catch unreachable;
    }

    if (immutable_base_manager.rollback_generation >= 1) {
        common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:BOOT_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 2) {
        common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:CORE_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 3) {
        common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:UI_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 4) {
        common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:STORAGE_ROLLBACK");
    }
    if (immutable_base_manager.rollback_generation >= 5) {
        common.printBootMarker("ZIGOS:PHASE6:HEALTHCHECK:NETWORK_ROLLBACK");
    }

    const active_base_image = immutable_base_manager.activeImage().?;
    if (immutable_base_manager.verifyActiveImage() and active_base_image.read_only) {
        common.printBootMarker("ZIGOS:PHASE6:IMMUTABLE_BASE:ACTIVE");
    }
    if (immutable_base_manager.rollback_generation >= 5) {
        common.printBootMarker("ZIGOS:PHASE6:ACTIVATION:ROLLBACK_OK");
    }

    var measured = measured_boot.Recorder.init();
    measured.begin(immutable_base_manager.activation_generation);
    measured.add(.kernel, "kernel-zigos-native", "phase6-native-kernel") catch unreachable;
    measured.add(.base_image, active_base_image.labelSlice(), &active_base_image.measurement) catch unreachable;
    var policy_measure: [96]u8 = undefined;
    const policy_measure_text = std.fmt.bufPrint(
        &policy_measure,
        "offline={d}:e2ee={d}:overlay={d}",
        .{
            @intFromBool(phase5_workspace_policy.offline_first),
            @intFromBool(phase5_workspace_policy.personal_e2ee),
            phase5_workspace_policy.overlay_policy_id orelse 0,
        },
    ) catch unreachable;
    measured.add(.policy, "workspace-policy", policy_measure_text) catch unreachable;
    const critical_services = [_]*supervisor_mod.ServiceRecord{
        supervisor.find(policy_service.id).?,
        supervisor.find(storage_service.id).?,
        supervisor.find(compositor_service.id).?,
        supervisor.find(network_service.id).?,
    };
    for (critical_services) |service_record| {
        var service_measure: [96]u8 = undefined;
        const service_measure_text = std.fmt.bufPrint(
            &service_measure,
            "{s}:{d}:{d}",
            .{
                contract.serviceName(service_record.class),
                @intFromEnum(service_record.state),
                service_record.restart_count,
            },
        ) catch unreachable;
        measured.add(.critical_service, contract.serviceName(service_record.class), service_measure_text) catch unreachable;
    }
    var driver_measure: [192]u8 = undefined;
    const driver_measure_text = std.fmt.bufPrint(
        &driver_measure,
        "{s}:{d}:{s}|{s}:{d}:{s}|{s}:{d}:{s}",
        .{
            driver_directory.findByClass(.network_adapter).?.signerSlice(),
            driver_directory.findByClass(.network_adapter).?.restart_generation,
            device_inventory.sourceName(device_inventory.recordForClass(.network_adapter).source),
            driver_directory.findByClass(.storage_controller).?.signerSlice(),
            driver_directory.findByClass(.storage_controller).?.restart_generation,
            device_inventory.sourceName(device_inventory.recordForClass(.storage_controller).source),
            driver_directory.findByClass(.graphics_adapter).?.signerSlice(),
            driver_directory.findByClass(.graphics_adapter).?.restart_generation,
            device_inventory.sourceName(device_inventory.recordForClass(.graphics_adapter).source),
        },
    ) catch unreachable;
    measured.add(.driver_set, "core-driver-set", driver_measure_text) catch unreachable;
    const measured_boot_record = measured.finalize();
    if (measured_boot_record.countKind(.kernel) == 1 and
        measured_boot_record.countKind(.base_image) == 1 and
        measured_boot_record.countKind(.critical_service) == 4 and
        measured_boot_record.countKind(.policy) == 1 and
        measured_boot_record.countKind(.driver_set) == 1 and
        !std.mem.allEqual(u8, &measured_boot_record.root_digest, 0))
    {
        common.printBootMarker("ZIGOS:PHASE6:MEASURED_BOOT:RECORDED");
    }

    if (phase5_sync_service.findDeviceRecord(recovery_device_principal) == null) {
        _ = phase5_sync_service.enrollTrustedDevice(
            session_user,
            recovery_device_principal,
            "recovery-device",
            user_root_signer,
            recovery_device_signer,
            117,
        ) catch unreachable;
    }

    var recovery = recovery_environment.Environment.init(session_service);
    if (recovery.verifyAndReinstallImage(
        &immutable_base_manager,
        "kernel=v2;base=reinstalled;mode=ro",
        phase6_image_signer,
        118,
    ) catch unreachable) {
        common.printBootMarker("ZIGOS:PHASE6:RECOVERY:VERIFY_REINSTALL");
    }

    const recovery_snapshot = phase4_storage_service.findSnapshot(notes_workspace_id, "phase6-recovery") orelse
        phase4_storage_service.snapshot(notes_workspace_id, "phase6-recovery", phase4_workspace_signer) catch unreachable;
    const recovery_snapshot_id = recovery_snapshot.id;
    phase4_storage_service.exportSnapshotInto(
        notes_workspace_id,
        recovery_snapshot_id,
        phase4_export_signer,
        &phase4_export_package,
    ) catch unreachable;

    common.printBootMarker("ZIGOS:PHASE6:RECOVERY:NOTES_V3_START");
    const notes_v3_request = object_store_mod.PutRequest{
        .object_type = .document,
        .payload = "# Notes\n- phase6 recovery drift\n",
        .metadata = object_store_mod.signMetadata(
            phase4_storage_signer,
            "notes",
            "text/markdown",
            .document,
            "# Notes\n- phase6 recovery drift\n",
            119,
        ) catch unreachable,
        .preferred_object_id = null,
        .parent_version_id = latest_notes_version_id,
    };
    _ = phase4_storage_service.putVersionRef(&notes_v3_request) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE6:RECOVERY:NOTES_V3_PUT");
    const notes_v3 = latestInsertedVersion(phase4_storage_service.store).?;
    notes_object_id = notes_v3.object_id;
    const notes_v3_version_id = notes_v3.id;
    common.printBootMarker("ZIGOS:PHASE6:RECOVERY:NOTES_V3_LATEST");
    phase4_storage_service.beginTransaction(notes_workspace_id) catch unreachable;
    phase4_storage_service.stagePut(
        notes_workspace_id,
        "documents/notes.md",
        notes_object_id,
        notes_v3_version_id,
        .document,
    ) catch unreachable;
    _ = phase4_storage_service.commit(notes_workspace_id, 120) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE6:RECOVERY:NOTES_V3_COMMIT");
    const restored_from_snapshot = recovery.restoreWorkspaceSnapshot(
        &phase4_storage_service,
        notes_workspace_id,
        recovery_snapshot_id,
        121,
    ) catch |err| switch (err) {
        error.SnapshotNotFound => recovery.restoreWorkspaceExport(
            &phase4_storage_service,
            notes_workspace_id,
            &phase4_export_package,
            121,
        ) catch unreachable,
        else => unreachable,
    };
    common.printBootMarker("ZIGOS:PHASE6:RECOVERY:RESTORE_APPLIED");
    if (restored_from_snapshot) {
        const restored_notes = phase4_storage_service.resolve(notes_workspace_id, "documents/notes.md") catch unreachable;
        if (restored_notes.version_id != notes_v3_version_id) {
            common.printBootMarker("ZIGOS:PHASE6:RECOVERY:RESTORE_SNAPSHOT");
        }
    }

    if (phase5_sync_service.findWorkspacePolicy(notes_workspace_id) == null) {
        _ = phase5_sync_service.configureWorkspacePolicy(.{
            .workspace_id = notes_workspace_id,
            .owner = session_user,
            .offline_first = true,
            .personal_e2ee = true,
            .selective_prefixes = &.{ "documents/", "assets/" },
            .device_to_device_policy_id = local_network_policy.id,
            .relay_policy_id = relay_network_policy.id,
            .overlay_policy_id = overlay_network_policy.id,
            .relay_domain = "relay.zigos.dev",
        }) catch unreachable;
    }
    if (recovery.repairSyncMetadata(
        &phase5_sync_service,
        &phase4_storage_service,
        notes_workspace_id,
        tablet_device_principal,
    ) catch unreachable and phase5_sync_service.findConflict(notes_workspace_id, tablet_device_principal, "documents/notes.md") == null) {
        common.printBootMarker("ZIGOS:PHASE6:RECOVERY:REPAIR_SYNC");
    }

    const recovery_device_record = phase5_sync_service.findDeviceRecord(recovery_device_principal).?;
    if (recovery_device_record.isTrusted() and recovery_device_record.key_rotation_generation < 2) {
        _ = recovery.rotateDeviceKeys(
            &phase5_sync_service,
            session_user,
            recovery_device_principal,
            user_root_signer,
            recovery_rotated_signer,
            122,
        ) catch unreachable;
    }
    if (phase5_sync_service.findDeviceRecord(recovery_device_principal).?.key_rotation_generation >= 2) {
        common.printBootMarker("ZIGOS:PHASE6:RECOVERY:ROTATE_KEYS");
    }
    if (phase5_sync_service.isTrustedDevice(recovery_device_principal)) {
        _ = recovery.revokeDeviceTrust(
            &phase5_sync_service,
            session_user,
            recovery_device_principal,
            user_root_signer,
            123,
        ) catch unreachable;
    }
    if (!phase5_sync_service.isTrustedDevice(recovery_device_principal)) {
        common.printBootMarker("ZIGOS:PHASE6:RECOVERY:REVOKE_TRUST");
    }

    var ux = native_ux.Controller.init();
    const phase6_notes_task = ux.startTask(&runtime, .{
        .owner = session_user,
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 6_000,
            .memory_bytes = 512 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 32 * 1024,
            .background_allowed = false,
        },
        .ui_surface_id = 2,
        .local_only = true,
        .initial_component = .{
            .label = "notes-task",
            .entry = "app.notes",
        },
    }) catch unreachable;
    if (phase6_notes_task.component_class == .app_component) {
        common.printBootMarker("ZIGOS:PHASE6:UX:START_TASK");
    }

    const opened_workspace = ux.openWorkspace(
        &phase4_storage_service,
        notes_workspace_id,
        "documents/notes.md",
        session_user,
    ) catch unreachable;
    if (opened_workspace.version_id != 0) {
        common.printBootMarker("ZIGOS:PHASE6:UX:OPEN_WORKSPACE");
    }

    ux.pairDevice(
        &phase5_sync_service,
        session_user,
        paired_device_principal,
        "paired-device",
        user_root_signer,
        paired_device_signer,
        124,
    ) catch unreachable;
    if (phase5_sync_service.isTrustedDevice(paired_device_principal)) {
        common.printBootMarker("ZIGOS:PHASE6:UX:PAIR_DEVICE");
    }

    if (ux.reviewPermissionRequest(
        phase6_notes_task.id,
        session_user,
        .object_access,
        true,
    ) catch unreachable) {
        common.printBootMarker("ZIGOS:PHASE6:UX:REVIEW_PERMISSION");
    }
    ux.recoverSystem(phase6_notes_task.id, session_user, "recovery-environment") catch unreachable;
    if (ux.flow_count == 5) {
        common.printBootMarker("ZIGOS:PHASE6:UX:RECOVER_SYSTEM");
    }

    runtime_service.checkpoint(125);
    phase4_storage_service.checkpoint_enabled = true;
    phase4_storage_service.checkpoint();
    common.printBootMarker("ZIGOS:TASK:SESSION_READY");
    common.printBootMarker("ZIGOS:NATIVE:READY");

    console.print("Zigos native session manager online\n");
    console.print("Native ABI: capability-ipc-v");
    printNumber(abi.ABI_VERSION);
    console.print("\n");
    console.print("Native-only platform ready\n");
}

test "boot wires bootstrap services storage sync recovery and phase3 contracts" {
    resetStateForTest();
    defer resetStateForTest();

    boot();

    try std.testing.expect(initialized);
    try std.testing.expectEqual(@as(usize, 13), serviceCount());
    try std.testing.expectEqual(@as(usize, 10), service_directory.bindingCount());
    try std.testing.expectEqual(@as(usize, 20), taskCount());
    try std.testing.expectEqual(@as(usize, 18), taskCountInState(.active));
    try std.testing.expectEqual(@as(usize, 1), taskCountInState(.suspended));
    try std.testing.expectEqual(@as(usize, 1), taskCountInState(.terminated));

    const runtime_service_record = supervisor.findByClass(.task_runtime).?;
    const compatibility_service = supervisor.findByClass(.compatibility_portal).?;
    const network_service = supervisor.findByClass(.network_stack).?;
    const storage_service = supervisor.findByClass(.storage_object).?;
    const sync_service = supervisor.findByClass(.sync_replication).?;
    const network_activation = driver_runtime.findByClass(.network_adapter).?;
    const storage_activation = driver_runtime.findByClass(.storage_controller).?;
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, runtime_service_record.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, compatibility_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, network_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, storage_service.state);
    try std.testing.expectEqual(supervisor_mod.ServiceState.healthy, sync_service.state);
    try std.testing.expect(runtime_service.has_checkpoint);
    try std.testing.expectEqual(@as(u32, 0), runtime_service.restart_generation);
    try std.testing.expect(network_activation.mode == .control_only or network_activation.mode == .published_data_plane);
    try std.testing.expect(storage_activation.mode == .control_only or storage_activation.mode == .published_data_plane);
    try std.testing.expectEqual(@as(u16, 1), network_service.restart_count);
    try std.testing.expectEqual(@as(u16, 1), storage_service.restart_count);
    try std.testing.expectEqual(@as(u16, 1), sync_service.restart_count);

    try std.testing.expectEqual(@as(u32, 2), driver_directory.findByClass(.network_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.storage_controller).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.graphics_adapter).?.restart_generation);
    try std.testing.expectEqual(@as(u32, 1), driver_directory.findByClass(.audio_print_io).?.restart_generation);

    const phase3_classes = [_]contract.ServiceClass{
        .package_install_update,
        .indexing_search,
        .media_print_helpers,
    };
    for (phase3_classes) |class| {
        const descriptor = service_contract.contractForClass(class).?;
        const connection = try service_directory.connect(descriptor.interface);
        try std.testing.expectEqual(supervisor.findByClass(class).?.id, connection.service_id);
    }
    const compatibility_connection = try service_directory.connect(compatibility_portal_interface);
    try std.testing.expectEqual(compatibility_service.id, compatibility_connection.service_id);

    const notes_task = findTaskByLabel("notes").?;
    const sync_task = findTaskByLabel("sync").?;
    const capture_task = findTaskByLabel("capture").?;
    const compatibility_task = findTaskByLabel("compatibility-portal").?;
    const storage_service_task = findTaskByLabel("workspace-storage").?;
    const sync_service_task = findTaskByLabel("sync-service").?;
    const session_task = findTaskByLabel("session-manager").?;
    const review_task = findTaskByLabel("permission-review").?;
    try std.testing.expectEqual(@as(usize, 2), notes_task.execution_component_count);
    try std.testing.expectEqual(@as(usize, 2), notes_task.capability_count);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, sync_task.state);
    try std.testing.expectEqual(@as(usize, 4), capture_task.capability_count);
    try std.testing.expectEqual(task_runtime.TaskState.active, compatibility_task.state);
    try std.testing.expect(runtime.processSeparated(notes_task.id, compatibility_task.id));
    try std.testing.expectEqual(@as(u32, 2), storage_service_task.process_generation);
    try std.testing.expectEqual(@as(u32, 2), sync_service_task.process_generation);
    try std.testing.expect(session_task.runsAsUserspaceProcess());
    try std.testing.expect(review_task.runsAsUserspaceProcess());
    try std.testing.expect(notes_task.runsAsUserspaceProcess());
    try std.testing.expect(storage_service_task.runsAsUserspaceProcess());
    try std.testing.expect(compatibility_task.runsAsUserspaceProcess());
    try std.testing.expectEqualStrings("zigos.system.session-manager", session_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("app.notes", notes_task.launchBundleIdSlice());
    try std.testing.expectEqualStrings("zigos.system.storage-object", storage_service_task.launchBundleIdSlice());

    const session_user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const storage_service_principal = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const tablet_device_principal = principal.PrincipalId{ .kind = .device, .serial = 2 };
    const notes_workspace = phase4_storage_service.findWorkspace(session_user, "notes-workspace").?;
    const imported_workspace = phase4_storage_service.findWorkspace(storage_service_principal, "imported-notes").?;
    const notes_entry = try phase4_storage_service.resolve(notes_workspace.id, "documents/notes.md");
    const imported_entry = try phase4_storage_service.resolve(imported_workspace.id, "documents/notes.md");
    try std.testing.expectEqual(notes_entry.version_id, imported_entry.version_id);
    try std.testing.expect(phase4_storage_service.findSnapshot(notes_workspace.id, "baseline") != null);

    sync_service_mod.Service.resetPersistentState();
    var restarted_sync = try sync_service_mod.Service.initWithStorage(sync_service.id, 0, sync_service.owner, &phase4_storage_service);
    try std.testing.expect(restarted_sync.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 3), restarted_sync.trustedDeviceCount());
    try std.testing.expect(restarted_sync.findWorkspacePolicy(notes_workspace.id) != null);
    try std.testing.expect(restarted_sync.findOverlay(notes_workspace.id) != null);
    try std.testing.expect(restarted_sync.findConflict(notes_workspace.id, tablet_device_principal, "documents/notes.md") == null);

    const state_signer = signing.SignerIdentity{
        .label = "zigos-base-state",
        .seed = [_]u8{0xA1} ** 32,
    };
    const package_service = supervisor.findByClass(.package_install_update).?;
    var immutable_base_manager = try immutable_base.Manager.init(&phase4_storage_service, package_service.owner, state_signer);
    try std.testing.expect(immutable_base_manager.loaded_existing_state);
    try std.testing.expectEqual(@as(u64, 8), immutable_base_manager.activation_generation);
    try std.testing.expectEqual(@as(u64, 5), immutable_base_manager.rollback_generation);
    try std.testing.expectEqualStrings("recovery-reinstall", immutable_base_manager.activeImage().?.labelSlice());
    try std.testing.expectEqualStrings("stable-b", immutable_base_manager.slots[immutable_base_manager.inactiveSlotIndex()].labelSlice());
}

test "boot is idempotent once initialized" {
    resetStateForTest();
    defer resetStateForTest();

    boot();
    const services_after_first_boot = serviceCount();
    const tasks_after_first_boot = taskCount();
    const bindings_after_first_boot = service_directory.bindingCount();
    const diagnostics_after_first_boot = supervisor.diagnostic_count;

    boot();

    try std.testing.expectEqual(services_after_first_boot, serviceCount());
    try std.testing.expectEqual(tasks_after_first_boot, taskCount());
    try std.testing.expectEqual(bindings_after_first_boot, service_directory.bindingCount());
    try std.testing.expectEqual(diagnostics_after_first_boot, supervisor.diagnostic_count);
}

fn printNumber(value: u64) void {
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch return;
    console.print(text);
}

fn hasGrantForKind(grants: []const policy_mediation.UserGrant, kind: manifest.PermissionKind) bool {
    for (grants) |grant| {
        if (grant.kind == kind and grant.allow) {
            return true;
        }
    }
    return false;
}
