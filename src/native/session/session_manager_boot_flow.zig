const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const endpoint_mod = @import("../kernel_api/endpoint.zig");
const manifest = @import("../policy/manifest.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const native_service_registry = @import("../kernel_api/service_registry.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const principal = @import("../core/principal.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const session_lifecycle_phases = @import("session_lifecycle_phases.zig");
const session_phase1_transport = @import("session_phase1_transport.zig");
const session_phase2_permissions = @import("session_phase2_permissions.zig");
const session_phase3_bootstrap_flow = @import("session_phase3_bootstrap_flow.zig");
const session_support = @import("session_manager_support.zig");
const shared_memory_mod = @import("../kernel_api/shared_memory.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service_mod = @import("../task/task_runtime_service.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const workspace_mod = @import("../storage/workspace.zig");

const BootstrapState = session_support.BootstrapState;
const NotesPhaseState = session_support.NotesPhaseState;
const Phase3Bindings = session_support.Phase3Bindings;
const Environment = session_support.Environment;

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
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

fn environment() Environment {
    return .{
        .capability_table = &capability_table,
        .runtime = &runtime,
        .service_directory = &service_directory,
        .userspace_catalog = &userspace_catalog,
        .supervisor = &supervisor,
        .driver_directory = &driver_directory,
        .driver_runtime = &driver_runtime,
    };
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

pub const testing = struct {
    pub fn resetState() void {
        resetStateForTest();
    }

    pub fn isInitialized() bool {
        return initialized;
    }

    pub fn countTasks() usize {
        var count: usize = 0;
        for (runtime.tasks) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn countTasksInState(state: task_runtime.TaskState) usize {
        var count: usize = 0;
        for (runtime.tasks) |slot| {
            if (slot.in_use and slot.task.state == state) count += 1;
        }
        return count;
    }

    pub fn countServices() usize {
        var count: usize = 0;
        for (supervisor.services) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn findTask(label: []const u8) ?*task_runtime.TaskRecord {
        var match: ?*task_runtime.TaskRecord = null;
        for (&runtime.tasks) |*slot| {
            if (!slot.in_use or slot.task.execution_component_count == 0) continue;
            if (std.mem.eql(u8, slot.task.execution_components[0].labelSlice(), label)) {
                match = &slot.task;
            }
        }
        return match;
    }

    pub fn runtimePtr() *task_runtime.Runtime {
        return &runtime;
    }

    pub fn runtimeServicePtr() *task_runtime_service_mod.Service {
        return &runtime_service;
    }

    pub fn serviceDirectoryPtr() *native_service_registry.Registry {
        return &service_directory;
    }

    pub fn driverDirectoryPtr() *driver_service.Directory {
        return &driver_directory;
    }

    pub fn driverRuntimePtr() *driver_runtime_mod.Runtime {
        return &driver_runtime;
    }

    pub fn supervisorPtr() *supervisor_mod.Supervisor {
        return &supervisor;
    }

    pub fn storageServicePtr() *storage_service_mod.Service {
        return &phase4_storage_service;
    }

    pub fn compatibilityPortalInterface() manifest.InterfaceDecl {
        return session_support.compatibility_portal_interface;
    }
};

pub fn kernelPort() ?*component_port.KernelPort {
    if (!kernel_port_ready) return null;
    return &kernel_port_instance;
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

    const env = environment();
    const state = initializeBootstrapState();
    var mediator = initPolicyMediator(state.ids.policy_authority, state.services);
    const kernel_port = prepareKernelInterface(state.ids.policy_authority, state.session_task.id);
    var review_service = initReviewService(state.services.review_service_record.id, state.review_service_task.id);
    var review_port = review_component_port.Port.init(&review_service);
    var policy_port = policy_component_port.Port.init(&mediator);
    common.printBootMarker(boot_markers.phase2_review_port_ready);
    common.printBootMarker(boot_markers.phase2_policy_port_ready);

    runPhase1TransportChecks(&env, &state, kernel_port);
    const notes_phase = runPhase2PermissionFlows(&env, &state, kernel_port, &review_port, &policy_port);
    const phase3 = runPhase3ServiceBootstrap(&env, &state, kernel_port);
    runSessionLifecycle(&state, &phase3, notes_phase.object_capability);
    printReadyBanner();
}

fn initializeBootstrapState() BootstrapState {
    common.printBootMarker(boot_markers.native_bootstrap);
    common.printBootMarker(boot_markers.tcb_defined);

    const ids = session_bootstrap.principals();
    session_bootstrap.initializeUserspace(&userspace_catalog, &runtime);
    const services = session_bootstrap.registerCoreServices(&supervisor, &runtime_service, ids);

    const session_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "zigos.system.session-manager",
        .{
            .owner = ids.session_user,
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
    common.printBootMarker(boot_markers.policy_ready);

    const review_service_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "zigos.system.permission-review",
        .{
            .owner = ids.review_service,
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
    common.printBootMarker(boot_markers.phase2_ui_service_ready);
    common.printBootMarker(boot_markers.phase2_ui_service_task_ready);

    const session_capability = mintSessionCapability(ids, services, session_task.id);
    recordSessionTaskBootstrap(session_task.id, session_capability.id);

    return .{
        .ids = ids,
        .services = services,
        .session_task = session_task,
        .review_service_task = review_service_task,
        .session_capability = session_capability,
        .policy_capability = mintPolicyCapability(ids.policy_authority, services.policy_service.id, session_task.id),
    };
}

fn mintSessionCapability(
    ids: session_bootstrap.Principals,
    services: session_bootstrap.CoreServices,
    session_task_id: u64,
) capability.Capability {
    return capability_table.mint(.{
        .holder = ids.session_service,
        .issuer = ids.policy_authority,
        .target = .{ .kind = .service, .id = services.session.id },
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
            .source_task_id = session_task_id,
            .broker_service_id = services.policy_service.id,
        },
    }) catch unreachable;
}

fn recordSessionTaskBootstrap(session_task_id: u64, session_capability_id: u64) void {
    runtime.grantCapability(session_task_id, session_capability_id) catch unreachable;
    runtime.audit(session_task_id, .{
        .kind = .created,
        .tick = 0,
    }) catch unreachable;
    runtime.audit(session_task_id, .{
        .kind = .capability_granted,
        .capability_id = session_capability_id,
        .tick = 0,
    }) catch unreachable;
}

fn mintPolicyCapability(
    policy_authority: principal.PrincipalId,
    policy_service_id: u64,
    session_task_id: u64,
) capability.Capability {
    return capability_table.mint(.{
        .holder = policy_authority,
        .issuer = policy_authority,
        .target = .{ .kind = .policy, .id = policy_service_id },
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
            .source_task_id = session_task_id,
            .broker_service_id = policy_service_id,
        },
    }) catch unreachable;
}

fn initPolicyMediator(
    policy_authority: principal.PrincipalId,
    services: session_bootstrap.CoreServices,
) policy_mediation.PolicyMediator {
    return policy_mediation.PolicyMediator.init(
        policy_authority,
        &capability_table,
        runtime_service.runtimePtr(),
        .{
            .network_service_id = services.network_service.id,
            .compositor_service_id = services.compositor_service.id,
            .policy_service_id = services.policy_service.id,
            .service_registry_id = services.service_registry.id,
        },
    );
}

fn prepareKernelInterface(policy_authority: principal.PrincipalId, session_task_id: u64) *component_port.KernelPort {
    kernel_instance = native_kernel.Kernel.init(
        policy_authority,
        runtime_service.runtimePtr(),
        &capability_table,
        &endpoint_table,
        &shared_memory_table,
        &service_directory,
    );
    kernel_port_instance = component_port.KernelPort.init(&kernel_instance);
    kernel_port_ready = true;
    executeUserspaceProbe(session_task_id);
    common.printBootMarker(boot_markers.phase1_native_kernel_ready);
    common.printBootMarker(boot_markers.phase1_no_root);
    common.printBootMarker(boot_markers.phase1_component_abi_ready);
    return &kernel_port_instance;
}

fn initReviewService(review_service_id: u64, review_task_id: u64) permission_review_service.Service {
    return permission_review_service.Service.init(
        review_service_id,
        review_task_id,
        &runtime,
        &bootstrap_review_inputs,
    );
}

fn runPhase1TransportChecks(
    env: *const Environment,
    state: *const BootstrapState,
    kernel_port: *component_port.KernelPort,
) void {
    session_phase1_transport.run(env, state, kernel_port);
}

fn runPhase2PermissionFlows(
    env: *const Environment,
    state: *const BootstrapState,
    kernel_port: *component_port.KernelPort,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) NotesPhaseState {
    return session_phase2_permissions.run(env, state, kernel_port, review_port, policy_port);
}

fn runPhase3ServiceBootstrap(
    env: *const Environment,
    state: *const BootstrapState,
    kernel_port: *component_port.KernelPort,
) Phase3Bindings {
    return session_phase3_bootstrap_flow.run(env, state, kernel_port);
}

fn runSessionLifecycle(
    state: *const BootstrapState,
    phase3: *const Phase3Bindings,
    notes_object_capability: capability.Capability,
) void {
    var lifecycle_context = session_lifecycle_phases.Context{
        .runtime = &runtime,
        .runtime_service = &runtime_service,
        .supervisor = &supervisor,
        .driver_directory = &driver_directory,
        .storage_service_instance = &phase4_storage_service,
        .export_package = &phase4_export_package,
        .policy_authority = state.ids.policy_authority,
        .session_service = state.ids.session_service,
        .session_user = state.ids.session_user,
        .storage_service_id = state.services.storage_service.id,
        .storage_task_id = phase3.bindingFor(.storage_object).task_id,
        .storage_service_principal = state.ids.storage_service,
        .sync_service_id = state.services.sync_service.id,
        .sync_task_id = phase3.bindingFor(.sync_replication).task_id,
        .sync_service_principal = state.ids.sync_service,
        .policy_service_id = state.services.policy_service.id,
        .network_service_id = state.services.network_service.id,
        .compositor_service_id = state.services.compositor_service.id,
        .package_service_id = state.services.package_service.id,
        .package_service_principal = state.ids.package_service,
        .notes_object_capability = notes_object_capability,
    };
    session_lifecycle_phases.run(&lifecycle_context);
}

fn printReadyBanner() void {
    console.print("Zigos native session manager online\n");
    console.print("Native ABI: capability-ipc-v");
    printNumber(abi.ABI_VERSION);
    console.print("\n");
    console.print("Native-only platform ready\n");
}

fn printNumber(value: u64) void {
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch return;
    console.print(text);
}
