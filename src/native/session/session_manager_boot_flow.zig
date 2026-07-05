const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const booted_evidence = @import("booted_evidence.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const native_service_registry = @import("../services/service_registry.zig");
const native_util = @import("../core/util.zig");
const native_ux = @import("../platform/native_ux.zig");
const principal = @import("../core/principal.zig");
const package_service = @import("../services/package_service.zig");
const runtime_negative_proofs = @import("runtime_negative_proofs.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const session_contexts = @import("session_manager_contexts.zig");
const service_catalog = @import("service_catalog.zig");
const service_graph_builder = @import("service_graph_builder.zig");
const session_support = @import("session_manager_support.zig");
const native_store_mount = @import("native_store_mount.zig");
const storage_durability_qemu = @import("../storage/storage_durability_qemu.zig");
const storage_service_mod = @import("../storage/storage_service.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const session_service_bootstrap = @import("session_service_bootstrap.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service_mod = @import("../task/task_runtime_service.zig");
const trust_boot = @import("trust_boot.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const workspace_mod = @import("../storage/workspace.zig");

pub const BootstrapState = session_support.BootstrapState;
pub const ServiceBindings = session_support.ServiceBindings;
pub const Environment = session_support.Environment;
const BootstrapError = error{ MissingBootstrapLaunch, MissingBootstrapGrant, MissingUserspaceImage } || session_bootstrap.Error || userspace_launch.Error || capability.Error || task_runtime.Error;

pub const ServiceGraph = service_graph_builder.ServiceGraph;

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
        pub fn printChar(_: u8) void {}
    };
const stack_watermark = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/stack_watermark.zig")
else
    struct {
        pub fn reportPeak() void {}
    };

pub const SessionManager = struct {
    initialized: bool = false,
    kernel_context: session_contexts.KernelContext = session_contexts.KernelContext.init(),
    runtime_context: session_contexts.RuntimeContext = session_contexts.RuntimeContext.init(),
    service_graph_builder: service_graph_builder.Builder = service_graph_builder.Builder.init(),
    native_store: native_store_mount.NativeStoreMount = native_store_mount.NativeStoreMount.init(),
    recovery_context: session_contexts.RecoveryContext = session_contexts.RecoveryContext.init(),

    pub fn init() SessionManager {
        return .{};
    }

    fn ensureConstructed(self: *SessionManager) void {
        self.runtime_context.ensureConstructed();
    }

    pub fn reset(self: *SessionManager) void {
        self.* = SessionManager.init();
        bootstrap_driver_port.reset();
        session_service_bootstrap.resetBootedDataPlanes();
        self.ensureConstructed();
        self.runtime_context.resetScheduler();
        self.native_store.resetPersistent();
    }

    pub fn isInitialized(self: *const SessionManager) bool {
        return self.initialized;
    }

    pub fn countTasks(self: *const SessionManager) usize {
        return self.runtime_context.countTasks();
    }

    pub fn countTasksInState(self: *const SessionManager, state: task_runtime.TaskState) usize {
        return self.runtime_context.countTasksInState(state);
    }

    pub fn countServices(self: *const SessionManager) usize {
        return self.service_graph_builder.supervisor.serviceCount();
    }

    pub fn findTask(self: *SessionManager, label: []const u8) ?*task_runtime.TaskRecord {
        return self.runtime_context.findTask(label);
    }

    pub fn runtimePtr(self: *SessionManager) *task_runtime.Runtime {
        return &self.runtime_context.runtime;
    }

    pub fn runtimeServicePtr(self: *SessionManager) *task_runtime_service_mod.Service {
        self.ensureConstructed();
        return &self.runtime_context.runtime_service;
    }

    pub fn capabilityTablePtr(self: *SessionManager) *capability.CapabilityTable {
        return &self.kernel_context.capability_table;
    }

    pub fn userspaceCatalogPtr(self: *SessionManager) *userspace_loader.Catalog {
        return &self.runtime_context.userspace_catalog;
    }

    pub fn userspaceSchedulerPtr(self: *SessionManager) *userspace_scheduler.Scheduler {
        self.ensureConstructed();
        return &self.runtime_context.userspace_scheduler;
    }

    pub fn serviceDirectoryPtr(self: *SessionManager) *native_service_registry.Service {
        return &self.service_graph_builder.service_directory;
    }

    pub fn driverDirectoryPtr(self: *SessionManager) *driver_service.Directory {
        return &self.service_graph_builder.driver_directory;
    }

    pub fn driverRuntimePtr(self: *SessionManager) *driver_runtime_mod.Runtime {
        return &self.service_graph_builder.driver_runtime;
    }

    pub fn supervisorPtr(self: *SessionManager) *supervisor_mod.Supervisor {
        return &self.service_graph_builder.supervisor;
    }

    pub fn storageServicePtr(self: *SessionManager) *storage_service_mod.Service {
        return &self.native_store.storage_service_instance;
    }

    pub fn storageCheckpointStorePtr(self: *SessionManager) *storage_service_mod.CheckpointStore {
        return &self.native_store.storage_checkpoint_store;
    }

    pub fn exportPackagePtr(self: *SessionManager) *workspace_mod.ExportPackage {
        return &self.native_store.export_package_buffer;
    }

    pub fn syncResidentStatePtr(self: *SessionManager) *sync_service_mod.ResidentState {
        return &self.native_store.sync_resident_state;
    }

    pub fn packageServicePtr(self: *SessionManager) *package_service.Service {
        return &self.service_graph_builder.package_service_instance;
    }

    pub fn reviewUxControllerPtr(self: *SessionManager) *native_ux.Controller {
        return &self.recovery_context.review_ux_controller;
    }

    pub fn compositorSessionPtr(self: *SessionManager) *compositor_session.Session {
        return &self.recovery_context.review_compositor_session;
    }

    pub fn backgroundDispatchPtr(self: *SessionManager) *background_dispatch.Controller {
        return &self.service_graph_builder.background_dispatcher;
    }

    pub fn updateLedgerPtr(self: *SessionManager) *event_ledger.Ledger {
        return &self.recovery_context.diagnostic_ledger;
    }

    pub fn kernelPort(self: *SessionManager) ?*component_port.KernelPort {
        return self.kernel_context.port();
    }

    fn executeUserspaceProbe(self: *SessionManager, task_id: u64) void {
        self.runtime_context.executeUserspaceProbe(task_id);
    }

    pub fn runUserspaceScheduler(self: *SessionManager, now_ticks: u64) bool {
        return self.runtime_context.runScheduler(now_ticks);
    }

    pub fn boot(self: *SessionManager) void {
        if (smokeFaultModeIs("storage_durability")) {
            self.bootStorageDurabilityProof();
            return;
        }
        const graph = self.buildProductionServiceGraph() orelse return;
        var trust = self.trustBoot();
        if (!trust.recordProductionMeasuredBoot(&graph)) {
            self.failBoot();
            return;
        }
        if (!runtime_negative_proofs.runAndPrint()) {
            self.failBoot();
            return;
        }
        if (!runtime_negative_proofs.runFreestandingAndPrint(
            &self.runtime_context.userspace_catalog,
            &self.runtime_context.runtime,
            &self.runtime_context.userspace_scheduler,
        )) {
            self.failBoot();
            return;
        }
        if (builtin.target.os.tag == .freestanding and !booted_evidence.runProduction(self, &graph)) {
            self.failBoot();
            return;
        }
        stack_watermark.reportPeak();
        userspace_executor.reportTrapStackPeak();
        common.printBootMarker(boot_markers.task_session_ready);
        common.printBootMarker(boot_markers.native_ready);
        printReadyBanner();
    }

    fn bootStorageDurabilityProof(self: *SessionManager) void {
        var graph = self.beginServiceGraph() orelse return;
        if (!session_service_bootstrap.bootServices(
            &graph.env,
            &graph.state,
            graph.kernel_port,
            &graph.service_bindings,
        )) {
            self.failBoot();
            return;
        }
        self.bindProductionStorageService(&graph);
        if (!storage_durability_qemu.run(&self.native_store.storage_service_instance)) {
            self.failBoot();
            return;
        }
    }

    pub fn beginServiceGraph(self: *SessionManager) ?ServiceGraph {
        self.ensureConstructed();
        if (self.initialized) return null;
        self.initialized = true;
        self.kernel_context.resetPort();

        const env = self.service_graph_builder.environment(
            &self.runtime_context,
            &self.kernel_context,
            &self.recovery_context,
        );
        const state = initializeBootstrapState(self) catch {
            self.failBoot();
            return null;
        };
        self.service_graph_builder.package_service_instance.bind(
            state.services.package_service.id,
            state.ids.package_service,
        );
        const kernel_port = prepareKernelInterface(self, state.ids.policy_authority, state.session_task.id);
        return .{
            .env = env,
            .state = state,
            .kernel_port = kernel_port,
            .service_bindings = ServiceBindings.init(),
        };
    }

    pub fn buildProductionServiceGraph(self: *SessionManager) ?ServiceGraph {
        var graph = self.beginServiceGraph() orelse return null;
        if (!self.service_graph_builder.bootProduction(&graph)) {
            self.failBoot();
            return null;
        }
        self.bindProductionStorageService(&graph);
        self.runtime_context.runtime_service.checkpoint(60);
        var trust = self.trustBoot();
        if (!trust.proveProductionAbImageRollback(&graph)) {
            self.failBoot();
            return null;
        }
        if (!trust.proveProductionPostActivationHealthChecks(&graph)) {
            self.failBoot();
            return null;
        }
        if (!trust.verifyProductionArtifactManifest(&graph)) {
            self.failBoot();
            return null;
        }
        return graph;
    }

    pub fn bindProductionStorageService(self: *SessionManager, graph: *const ServiceGraph) void {
        self.native_store.bindProduction(
            graph.state.services.storage_service.id,
            graph.service_bindings.bindingFor(.storage_object).task_id,
            graph.state.ids.storage_service,
            &self.kernel_context.capability_table,
        );
    }

    pub fn failBoot(self: *SessionManager) void {
        self.initialized = false;
        self.kernel_context.resetPort();
        clearRootKernelPort();
    }

    fn recordBootFailure(self: *SessionManager, service_id: u64, tick: u64, err: anyerror) void {
        _ = self.service_graph_builder.supervisor.recordCrash(service_id, tick, bootFailureCode(err));
    }

    fn trustBoot(self: *SessionManager) trust_boot.TrustBoot {
        return trust_boot.TrustBoot.init(
            &self.runtime_context,
            &self.kernel_context,
            &self.recovery_context.review_compositor_session,
            &self.service_graph_builder,
            &self.native_store,
        );
    }
};

fn initializeBootstrapState(self: *SessionManager) BootstrapError!BootstrapState {
    common.printBootMarker(boot_markers.native_bootstrap);
    common.printBootMarker(boot_markers.tcb_defined);

    const ids = session_bootstrap.principals();
    try session_bootstrap.initializeUserspace(
        &self.runtime_context.userspace_catalog,
        &self.runtime_context.runtime,
        &self.kernel_context.capability_table,
        &self.runtime_context.userspace_scheduler,
    );
    const services = try session_bootstrap.registerCoreServices(&self.service_graph_builder.supervisor, &self.runtime_context.runtime_service, ids);

    const session_task = launchNativeBootstrapService(self, ids, services, .session_manager) catch |err| {
        self.recordBootFailure(services.session.id, 0, err);
        return err;
    };
    common.printBootMarker(boot_markers.policy_ready);

    const review_service_task = launchNativeBootstrapService(self, ids, services, .permission_review_ui) catch |err| {
        self.recordBootFailure(services.review_service_record.id, 0, err);
        return err;
    };
    common.printBootMarker(boot_markers.permission_ui_service_ready);
    common.printBootMarker(boot_markers.permission_ui_service_task_ready);

    const session_capability = mintNativeBootstrapGrant(self, ids, services, session_task.id, .session_manager, .session_service_authority) catch |err| {
        self.recordBootFailure(services.session.id, 0, err);
        return err;
    };
    const policy_capability = mintNativeBootstrapGrant(self, ids, services, session_task.id, .session_manager, .policy_mint_authority) catch |err| {
        self.recordBootFailure(services.policy_service.id, 0, err);
        return err;
    };
    recordSessionTaskBootstrap(self, session_task.id, session_capability.id, policy_capability.id) catch |err| {
        self.recordBootFailure(services.session.id, 0, err);
        return err;
    };

    return .{
        .ids = ids,
        .services = services,
        .session_task = session_task,
        .review_service_task = review_service_task,
        .session_capability = session_capability,
        .policy_capability = policy_capability,
    };
}

fn launchNativeBootstrapService(
    self: *SessionManager,
    ids: session_bootstrap.Principals,
    services: session_bootstrap.CoreServices,
    class: service_catalog.ServiceClass,
) BootstrapError!*task_runtime.TaskRecord {
    const launch = service_catalog.bootstrapLaunchForClass(class) orelse return error.MissingBootstrapLaunch;
    if (launch.mode != .native_direct) return error.MissingBootstrapLaunch;
    const bundle_id = service_catalog.bundleIdForServiceClass(class) orelse return error.MissingUserspaceImage;
    return userspace_launch.launchRegisteredDirect(
        &self.runtime_context.userspace_catalog,
        &self.runtime_context.runtime,
        bundle_id,
        .{
            .owner = session_bootstrap.ownerForServiceClass(ids, class) orelse return error.MissingBootstrapLaunch,
            .budget = launch.budget,
            .ui_surface_id = launch.ui_surface_id,
            .local_only = true,
        },
        &self.runtime_context.userspace_scheduler,
    ) catch |err| {
        const record = session_bootstrap.serviceRecordForClass(services, class) orelse return error.MissingBootstrapLaunch;
        self.recordBootFailure(record.id, launch.tick, err);
        return err;
    };
}

fn mintNativeBootstrapGrant(
    self: *SessionManager,
    ids: session_bootstrap.Principals,
    services: session_bootstrap.CoreServices,
    session_task_id: u64,
    class: service_catalog.ServiceClass,
    grant: service_catalog.BootstrapGrantKind,
) BootstrapError!capability.Capability {
    if (!catalogDeclaresGrant(class, grant)) return error.MissingBootstrapGrant;
    const target: capability.CapabilityTarget = switch (grant) {
        .session_service_authority => .{ .kind = .service, .id = services.session.id },
        .policy_mint_authority => .{ .kind = .policy, .id = services.policy_service.id },
        .service_task_authority => return error.MissingBootstrapGrant,
    };
    const broker_service_id = switch (grant) {
        .session_service_authority => services.policy_service.id,
        .policy_mint_authority => services.policy_service.id,
        .service_task_authority => unreachable,
    };
    return try self.kernel_context.capability_table.mintBootRoot(.{
        .holder = ids.session_service,
        .issuer = ids.policy_authority,
        .target = target,
        .rights = service_catalog.rightsForBootstrapGrant(grant),
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
            .broker_service_id = broker_service_id,
        },
    });
}

fn catalogDeclaresGrant(class: service_catalog.ServiceClass, grant: service_catalog.BootstrapGrantKind) bool {
    const launch = service_catalog.bootstrapLaunchForClass(class) orelse return false;
    for (launch.grants) |declared| {
        if (declared == grant) return true;
    }
    return false;
}

fn recordSessionTaskBootstrap(
    self: *SessionManager,
    session_task_id: u64,
    session_capability_id: u64,
    policy_capability_id: u64,
) task_runtime.Error!void {
    try self.runtime_context.runtime.grantCapability(session_task_id, session_capability_id);
    try self.runtime_context.runtime.grantCapability(session_task_id, policy_capability_id);
    try self.runtime_context.runtime.audit(session_task_id, .{
        .kind = .created,
        .tick = 0,
    });
    try self.runtime_context.runtime.audit(session_task_id, .{
        .kind = .capability_granted,
        .capability_id = session_capability_id,
        .tick = 0,
    });
    try self.runtime_context.runtime.audit(session_task_id, .{
        .kind = .capability_granted,
        .capability_id = policy_capability_id,
        .tick = 0,
    });
}

fn prepareKernelInterface(
    self: *SessionManager,
    policy_authority: principal.PrincipalId,
    session_task_id: u64,
) *component_port.KernelPort {
    const kernel_port = self.kernel_context.prepare(
        policy_authority,
        &self.runtime_context.runtime_service,
        &self.service_graph_builder.driver_runtime,
    );
    publishRootKernelPort(kernel_port);
    self.executeUserspaceProbe(session_task_id);
    common.printBootMarker(boot_markers.transport_native_kernel_ready);
    common.printBootMarker(boot_markers.transport_no_root);
    common.printBootMarker(boot_markers.transport_component_abi_ready);
    return kernel_port;
}

fn publishRootKernelPort(port: anytype) void {
    if (builtin.target.os.tag != .freestanding) return;
    const root = @import("root");
    if (@hasDecl(root, "publishKernelPort")) {
        root.publishKernelPort(port);
    }
}

fn clearRootKernelPort() void {
    if (builtin.target.os.tag != .freestanding) return;
    const root = @import("root");
    if (@hasDecl(root, "clearKernelPort")) {
        root.clearKernelPort();
    }
}

pub fn printReadyBanner() void {
    console.print("Zigos native session manager online\n");
    console.print("Native ABI: capability-ipc-v");
    printNumber(abi.ABI_VERSION);
    console.print("\n");
    console.print("Native-only platform ready\n");
}

fn printNumber(value: u64) void {
    const DECIMAL_U64_BUFFER_BYTES: usize = 20;
    var buffer: [DECIMAL_U64_BUFFER_BYTES]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch return;
    console.print(text);
}

fn bootFailureCode(err: anyerror) u32 {
    return @truncate(native_util.fnv1a64(@errorName(err)));
}

fn smokeFaultModeIs(comptime mode_name: []const u8) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    const config = @import("../../kernel/config.zig");
    return std.mem.eql(u8, @tagName(config.smokeFaultMode()), mode_name);
}
