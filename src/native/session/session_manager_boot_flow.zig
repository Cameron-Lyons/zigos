const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_packages = @import("bootstrap_packages.zig");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const endpoint_mod = @import("../kernel_api/endpoint.zig");
const manifest = @import("../policy/manifest.zig");
const bootstrap_review_profile = @import("../policy/bootstrap_review_profile.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const native_service_registry = @import("../kernel_api/service_registry.zig");
const native_ux = @import("../platform/native_ux.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const principal = @import("../core/principal.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const package_service = @import("../services/package_service.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const session_scenario_world = @import("session_scenario_world.zig");
const session_transport_checks = @import("session_transport_checks.zig");
const session_permission_flows = @import("session_permission_flows.zig");
const session_service_bootstrap = @import("session_service_bootstrap.zig");
const session_support = @import("session_manager_support.zig");
const shared_memory_mod = @import("../kernel_api/shared_memory.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service_mod = @import("../task/task_runtime_service.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const workspace_mod = @import("../storage/workspace.zig");

const BootstrapState = session_support.BootstrapState;
const NotesReviewState = session_support.NotesReviewState;
const ServiceBindings = session_support.ServiceBindings;
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

pub const SessionManager = struct {
    constructed: bool = false,
    initialized: bool = false,
    capability_table: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoint_table: endpoint_mod.Table = endpoint_mod.Table.init(),
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    runtime_checkpoint_store: task_runtime_service_mod.CheckpointStore = .{},
    runtime_service: task_runtime_service_mod.Service = undefined,
    userspace_executor: userspace_executor.Executor = .{},
    userspace_scheduler: userspace_scheduler.Scheduler = undefined,
    service_directory: native_service_registry.Registry = native_service_registry.Registry.init(),
    shared_memory_table: shared_memory_mod.Table = shared_memory_mod.Table.init(),
    userspace_catalog: userspace_loader.Catalog = userspace_loader.Catalog.init(),
    package_service_instance: package_service.Service = package_service.Service.init(),
    review_compositor_session: compositor_session.Session = compositor_session.Session.init(),
    review_ux_controller: native_ux.Controller = native_ux.Controller.init(),
    kernel_instance: native_kernel.Kernel = undefined,
    kernel_port_instance: component_port.KernelPort = undefined,
    kernel_port_ready: bool = false,
    driver_directory: driver_service.Directory = driver_service.Directory.init(),
    driver_runtime: driver_runtime_mod.Runtime = driver_runtime_mod.Runtime.init(),
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    diagnostic_ledger: event_ledger.Ledger = event_ledger.Ledger.init(),
    background_dispatcher: background_dispatch.Controller = background_dispatch.Controller.init(),
    storage_checkpoint_store: storage_service_mod.CheckpointStore = .{},
    storage_service_instance: storage_service_mod.Service = emptyStorageService(),
    export_package_buffer: workspace_mod.ExportPackage = workspace_mod.emptyExportPackage(),
    sync_resident_state: sync_service_mod.ResidentState = .{},

    pub fn init() SessionManager {
        return .{};
    }

    fn ensureConstructed(self: *SessionManager) void {
        if (self.constructed) return;
        self.runtime_service.initWithStoreInPlace(
            &self.runtime,
            &self.runtime_checkpoint_store,
        );
        self.userspace_scheduler = userspace_scheduler.Scheduler.init(&self.userspace_executor);
        self.constructed = true;
    }

    pub fn reset(self: *SessionManager) void {
        self.* = SessionManager.init();
        self.ensureConstructed();
        self.userspace_scheduler.reset();
        self.storage_checkpoint_store.resetPersistent();
        self.sync_resident_state.resetPersistent();
    }

    pub fn isInitialized(self: *const SessionManager) bool {
        return self.initialized;
    }

    pub fn countTasks(self: *const SessionManager) usize {
        var count: usize = 0;
        for (self.runtime.tasks) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn countTasksInState(self: *const SessionManager, state: task_runtime.TaskState) usize {
        var count: usize = 0;
        for (self.runtime.tasks) |slot| {
            if (slot.in_use and slot.task.state == state) count += 1;
        }
        return count;
    }

    pub fn countServices(self: *const SessionManager) usize {
        var count: usize = 0;
        for (self.supervisor.services) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn findTask(self: *SessionManager, label: []const u8) ?*task_runtime.TaskRecord {
        var match: ?*task_runtime.TaskRecord = null;
        for (&self.runtime.tasks) |*slot| {
            if (!slot.in_use or slot.task.execution_component_count == 0) continue;
            if (std.mem.eql(u8, slot.task.execution_components[0].labelSlice(), label)) {
                match = &slot.task;
            }
        }
        return match;
    }

    pub fn runtimePtr(self: *SessionManager) *task_runtime.Runtime {
        return &self.runtime;
    }

    pub fn runtimeServicePtr(self: *SessionManager) *task_runtime_service_mod.Service {
        self.ensureConstructed();
        return &self.runtime_service;
    }

    pub fn serviceDirectoryPtr(self: *SessionManager) *native_service_registry.Registry {
        return &self.service_directory;
    }

    pub fn driverDirectoryPtr(self: *SessionManager) *driver_service.Directory {
        return &self.driver_directory;
    }

    pub fn driverRuntimePtr(self: *SessionManager) *driver_runtime_mod.Runtime {
        return &self.driver_runtime;
    }

    pub fn supervisorPtr(self: *SessionManager) *supervisor_mod.Supervisor {
        return &self.supervisor;
    }

    pub fn storageServicePtr(self: *SessionManager) *storage_service_mod.Service {
        return &self.storage_service_instance;
    }

    pub fn packageServicePtr(self: *SessionManager) *package_service.Service {
        return &self.package_service_instance;
    }

    pub fn reviewUxControllerPtr(self: *SessionManager) *native_ux.Controller {
        return &self.review_ux_controller;
    }

    pub fn compositorSessionPtr(self: *SessionManager) *compositor_session.Session {
        return &self.review_compositor_session;
    }

    pub fn backgroundDispatchPtr(self: *SessionManager) *background_dispatch.Controller {
        return &self.background_dispatcher;
    }

    pub fn updateLedgerPtr(self: *SessionManager) *event_ledger.Ledger {
        return &self.diagnostic_ledger;
    }

    pub fn compatibilityPortalInterface(self: *const SessionManager) manifest.InterfaceDecl {
        _ = self;
        return session_support.compatibility_portal_interface;
    }

    pub fn kernelPort(self: *SessionManager) ?*component_port.KernelPort {
        if (!self.kernel_port_ready) return null;
        return &self.kernel_port_instance;
    }

    fn executeUserspaceProbe(self: *SessionManager, task_id: u64) void {
        _ = self.userspace_scheduler.executeTask(task_id, 0);
    }

    pub fn runUserspaceScheduler(self: *SessionManager, now_ticks: u64) bool {
        return self.userspace_scheduler.runNext(now_ticks);
    }

    pub fn boot(self: *SessionManager) void {
        self.ensureConstructed();
        if (self.initialized) return;
        self.initialized = true;
        self.kernel_port_ready = false;

        const env = environment(self);
        const state = initializeBootstrapState(self);
        const kernel_port = prepareKernelInterface(self, state.ids.policy_authority, state.session_task.id);
        var service_bindings: ServiceBindings = undefined;
        session_service_bootstrap.bootServices(&env, &state, kernel_port, &service_bindings);

        self.storage_service_instance = storage_service_mod.Service.initWithStore(
            state.services.storage_service.id,
            service_bindings.bindingFor(.storage_object).task_id,
            state.ids.storage_service,
            &self.storage_checkpoint_store,
        );
        self.storage_service_instance.checkpoint_enabled = false;

        self.runtime_service.checkpoint(60);
        common.printBootMarker(boot_markers.task_session_ready);
        common.printBootMarker(boot_markers.native_ready);
        printReadyBanner();
    }

    pub fn bootScenarioWorld(self: *SessionManager) void {
        self.ensureConstructed();
        if (self.initialized) return;
        self.initialized = true;
        self.kernel_port_ready = false;

        const env = environment(self);
        const state = initializeBootstrapState(self);
        bootstrap_packages.seed(&self.package_service_instance);
        var mediator = initPolicyMediator(self, state.ids.policy_authority, state.services);
        const kernel_port = prepareKernelInterface(self, state.ids.policy_authority, state.session_task.id);
        var review_service = initReviewService(self, state.services.review_service_record.id, state.review_service_task.id);
        var review_port = review_component_port.Port.init(&review_service);
        var policy_port = policy_component_port.Port.init(&mediator);
        common.printBootMarker(boot_markers.permission_review_port_ready);
        common.printBootMarker(boot_markers.permission_policy_port_ready);

        runTransportChecks(&env, &state, kernel_port);
        const notes_review = runPermissionFlows(&env, &state, kernel_port, &review_port, &policy_port);
        var service_bindings: ServiceBindings = undefined;
        runServiceBootstrap(&env, &state, kernel_port, &service_bindings);
        runSessionLifecycle(self, &state, &service_bindings, notes_review.object_capability);
        printReadyBanner();
    }
};

fn environment(self: *SessionManager) Environment {
    return .{
        .capability_table = &self.capability_table,
        .runtime = &self.runtime,
        .service_directory = &self.service_directory,
        .userspace_catalog = &self.userspace_catalog,
        .userspace_scheduler = &self.userspace_scheduler,
        .package_service = &self.package_service_instance,
        .supervisor = &self.supervisor,
        .driver_directory = &self.driver_directory,
        .driver_runtime = &self.driver_runtime,
        .diagnostic_ledger = &self.diagnostic_ledger,
        .background_dispatcher = &self.background_dispatcher,
    };
}

fn emptyStorageService() storage_service_mod.Service {
    return .{
        .service_id = 0,
        .task_id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .checkpoint_store = undefined,
        .store = undefined,
        .workspaces = undefined,
    };
}

fn initializeBootstrapState(self: *SessionManager) BootstrapState {
    common.printBootMarker(boot_markers.native_bootstrap);
    common.printBootMarker(boot_markers.tcb_defined);

    const ids = session_bootstrap.principals();
    session_bootstrap.initializeUserspace(
        &self.userspace_catalog,
        &self.runtime,
        &self.capability_table,
        &self.userspace_scheduler,
    );
    const services = session_bootstrap.registerCoreServices(&self.supervisor, &self.runtime_service, ids);

    const session_task = userspace_launch.launchRegisteredDirect(
        &self.userspace_catalog,
        &self.runtime,
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
        &self.userspace_scheduler,
    ) catch unreachable;
    common.printBootMarker(boot_markers.policy_ready);

    const review_service_task = userspace_launch.launchRegisteredDirect(
        &self.userspace_catalog,
        &self.runtime,
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
        &self.userspace_scheduler,
    ) catch unreachable;
    common.printBootMarker(boot_markers.permission_ui_service_ready);
    common.printBootMarker(boot_markers.permission_ui_service_task_ready);

    const session_capability = mintSessionCapability(self, ids, services, session_task.id);
    recordSessionTaskBootstrap(self, session_task.id, session_capability.id);

    return .{
        .ids = ids,
        .services = services,
        .session_task = session_task,
        .review_service_task = review_service_task,
        .session_capability = session_capability,
        .policy_capability = mintPolicyCapability(self, ids.policy_authority, services.policy_service.id, session_task.id),
    };
}

fn mintSessionCapability(
    self: *SessionManager,
    ids: session_bootstrap.Principals,
    services: session_bootstrap.CoreServices,
    session_task_id: u64,
) capability.Capability {
    return self.capability_table.mint(.{
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

fn recordSessionTaskBootstrap(self: *SessionManager, session_task_id: u64, session_capability_id: u64) void {
    self.runtime.grantCapability(session_task_id, session_capability_id) catch unreachable;
    self.runtime.audit(session_task_id, .{
        .kind = .created,
        .tick = 0,
    }) catch unreachable;
    self.runtime.audit(session_task_id, .{
        .kind = .capability_granted,
        .capability_id = session_capability_id,
        .tick = 0,
    }) catch unreachable;
}

fn mintPolicyCapability(
    self: *SessionManager,
    policy_authority: principal.PrincipalId,
    policy_service_id: u64,
    session_task_id: u64,
) capability.Capability {
    return self.capability_table.mint(.{
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
    self: *SessionManager,
    policy_authority: principal.PrincipalId,
    services: session_bootstrap.CoreServices,
) policy_mediation.PolicyMediator {
    return policy_mediation.PolicyMediator.init(
        policy_authority,
        &self.capability_table,
        self.runtime_service.runtimePtr(),
        .{
            .network_service_id = services.network_service.id,
            .compositor_service_id = services.compositor_service.id,
            .policy_service_id = services.policy_service.id,
            .service_registry_id = services.service_registry.id,
        },
    );
}

fn prepareKernelInterface(
    self: *SessionManager,
    policy_authority: principal.PrincipalId,
    session_task_id: u64,
) *component_port.KernelPort {
    self.kernel_instance = native_kernel.Kernel.init(
        policy_authority,
        self.runtime_service.runtimePtr(),
        &self.capability_table,
        &self.endpoint_table,
        &self.shared_memory_table,
        &self.service_directory,
    );
    self.kernel_port_instance = component_port.KernelPort.init(&self.kernel_instance);
    self.driver_runtime.bindKernelPort(&self.kernel_port_instance);
    self.kernel_port_ready = true;
    self.executeUserspaceProbe(session_task_id);
    common.printBootMarker(boot_markers.transport_native_kernel_ready);
    common.printBootMarker(boot_markers.transport_no_root);
    common.printBootMarker(boot_markers.transport_component_abi_ready);
    return &self.kernel_port_instance;
}

fn initReviewService(
    self: *SessionManager,
    review_service_id: u64,
    review_task_id: u64,
) permission_review_service.Service {
    return permission_review_service.Service.initProfiled(
        review_service_id,
        review_task_id,
        &self.runtime,
        &[_][]const u8{},
        bootstrap_review_profile.rules[0..],
        &self.review_compositor_session,
        &self.review_ux_controller,
    );
}

fn runTransportChecks(
    env: *const Environment,
    state: *const BootstrapState,
    kernel_port: *component_port.KernelPort,
) void {
    session_transport_checks.run(env, state, kernel_port);
}

fn runPermissionFlows(
    env: *const Environment,
    state: *const BootstrapState,
    kernel_port: *component_port.KernelPort,
    review_port: *review_component_port.Port,
    policy_port: *policy_component_port.Port,
) NotesReviewState {
    return session_permission_flows.run(env, state, kernel_port, review_port, policy_port);
}

fn runServiceBootstrap(
    env: *const Environment,
    state: *const BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: *ServiceBindings,
) void {
    session_service_bootstrap.run(env, state, kernel_port, service_bindings);
}

fn runSessionLifecycle(
    self: *SessionManager,
    state: *const BootstrapState,
    service_bindings: *const ServiceBindings,
    notes_object_capability: capability.Capability,
) void {
    var lifecycle_context = session_scenario_world.Context{
        .runtime = &self.runtime,
        .runtime_service = &self.runtime_service,
        .supervisor = &self.supervisor,
        .compositor = &self.review_compositor_session,
        .driver_directory = &self.driver_directory,
        .storage_service_instance = &self.storage_service_instance,
        .storage_checkpoint_store = &self.storage_checkpoint_store,
        .export_package = &self.export_package_buffer,
        .policy_authority = state.ids.policy_authority,
        .session_service = state.ids.session_service,
        .session_user = state.ids.session_user,
        .storage_service_id = state.services.storage_service.id,
        .storage_task_id = service_bindings.bindingFor(.storage_object).task_id,
        .storage_service_principal = state.ids.storage_service,
        .sync_service_id = state.services.sync_service.id,
        .sync_task_id = service_bindings.bindingFor(.sync_replication).task_id,
        .sync_service_principal = state.ids.sync_service,
        .sync_resident_state = &self.sync_resident_state,
        .policy_service_id = state.services.policy_service.id,
        .network_service_id = state.services.network_service.id,
        .compositor_service_id = state.services.compositor_service.id,
        .package_service_id = state.services.package_service.id,
        .package_service_principal = state.ids.package_service,
        .update_ledger = &self.diagnostic_ledger,
        .notes_object_capability = notes_object_capability,
    };
    session_scenario_world.run(&lifecycle_context);
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
