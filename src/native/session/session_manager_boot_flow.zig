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
const compositor_session = @import("../platform/compositor_session.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const measured_boot = @import("../platform/measured_boot.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const native_service_registry = @import("../services/service_registry.zig");
const native_ux = @import("../platform/native_ux.zig");
const principal = @import("../core/principal.zig");
const package_service = @import("../services/package_service.zig");
const runtime_negative_proofs = @import("runtime_negative_proofs.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const service_catalog = @import("service_catalog.zig");
const session_service_bootstrap = @import("session_service_bootstrap.zig");
const session_support = @import("session_manager_support.zig");
const signing = @import("../core/signing.zig");
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

pub const BootstrapState = session_support.BootstrapState;
pub const ServiceBindings = session_support.ServiceBindings;
pub const Environment = session_support.Environment;
const BootstrapError = error{ MissingBootstrapLaunch, MissingBootstrapGrant, MissingUserspaceImage } || session_bootstrap.Error || userspace_launch.Error || capability.Error || task_runtime.Error;

pub const ServiceGraph = struct {
    env: Environment,
    state: BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: ServiceBindings,
};

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
    service_directory: native_service_registry.Service = native_service_registry.Service.init(),
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
    service_bindings: ServiceBindings = ServiceBindings.init(),

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
            if (std.mem.eql(u8, slot.task.executionComponents()[0].labelSlice(), label)) {
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

    pub fn serviceDirectoryPtr(self: *SessionManager) *native_service_registry.Service {
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
        const graph = self.buildProductionServiceGraph() orelse return;
        recordProductionMeasuredBoot(self, &graph);
        if (!runtime_negative_proofs.runAndPrint()) {
            self.failBoot();
            return;
        }
        if (!runtime_negative_proofs.runFreestandingAndPrint(
            &self.userspace_catalog,
            &self.runtime,
            &self.userspace_scheduler,
        )) {
            self.failBoot();
            return;
        }
        common.printBootMarker(boot_markers.task_session_ready);
        common.printBootMarker(boot_markers.native_ready);
        printReadyBanner();
    }

    pub fn beginServiceGraph(self: *SessionManager) ?ServiceGraph {
        self.ensureConstructed();
        if (self.initialized) return null;
        self.initialized = true;
        self.kernel_port_ready = false;

        const env = environment(self);
        const state = initializeBootstrapState(self) catch {
            self.failBoot();
            return null;
        };
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
        if (!verifyProductionArtifactManifest(self)) {
            self.failBoot();
            return null;
        }
        const env_snapshot = graph.env;
        const state_snapshot = graph.state;
        self.service_bindings = ServiceBindings.init();
        if (!session_service_bootstrap.bootServices(&env_snapshot, &state_snapshot, graph.kernel_port, &self.service_bindings)) {
            self.failBoot();
            return null;
        }
        graph.env = env_snapshot;
        graph.state = state_snapshot;
        graph.service_bindings = self.service_bindings;
        self.bindProductionStorageService(&graph);
        self.runtime_service.checkpoint(60);
        return graph;
    }

    pub fn bindProductionStorageService(self: *SessionManager, graph: *const ServiceGraph) void {
        self.storage_service_instance = storage_service_mod.Service.reloadFromAttachedVolume(
            graph.state.services.storage_service.id,
            graph.service_bindings.bindingFor(.storage_object).task_id,
            graph.state.ids.storage_service,
            &self.storage_checkpoint_store,
        );
        self.storage_service_instance.bindCapabilityTable(&self.capability_table);
        self.storage_service_instance.checkpoint_enabled = false;
    }

    pub fn failBoot(self: *SessionManager) void {
        self.initialized = false;
        self.kernel_port_ready = false;
    }
};

fn verifyProductionArtifactManifest(manager: *SessionManager) bool {
    const manifest_signer = signing.SignerIdentity{
        .label = "zigos-artifact-manifest",
        .seed = [_]u8{0xB7} ** 32,
    };
    const artifact_manifest = buildProductionArtifactManifest(manager) catch return false;
    const signed_manifest = measured_boot.signArtifactManifest(artifact_manifest, manifest_signer) catch return false;
    if (!measured_boot.verifySignedArtifactManifest(&signed_manifest)) return false;
    common.printBootMarker(boot_markers.platform_artifact_manifest_verified);
    return true;
}

fn buildProductionArtifactManifest(manager: *SessionManager) !measured_boot.ArtifactManifest {
    var manifest_record = measured_boot.ArtifactManifest.init(1);
    try manifest_record.add(.kernel, "bootloader+kernel-zigos-native", "src/boot/boot64.S:zig-out/bin/kernel-zigos-native.elf");
    try manifest_record.add(.base_image, "production-native-base", "native-store:production-service-graph");
    try manifest_record.add(.policy, "production-policy-set", "zero-root:capability-ipc:local-first");

    const critical_service_classes = [_]service_catalog.ServiceClass{
        .policy_mediation,
        .storage_object,
        .compositor_ui_session,
        .network_stack,
    };
    for (critical_service_classes) |class| {
        const bundle_id = service_catalog.bundleIdForServiceClass(class) orelse return error.MissingBootstrapLaunch;
        const image = manager.userspace_catalog.findByBundleId(bundle_id) orelse return error.MissingUserspaceImage;
        try manifest_record.addUserspaceServiceImage(image);
    }

    try manifest_record.add(
        .driver_set,
        "production-driver-set",
        "network=userspace-control-only;storage=userspace-brokered-ata;graphics=control-only;audio=control-only",
    );
    return manifest_record;
}

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
        .capability_table = null,
        .checkpoint_store = undefined,
        .store = undefined,
        .workspaces = undefined,
    };
}

fn initializeBootstrapState(self: *SessionManager) BootstrapError!BootstrapState {
    common.printBootMarker(boot_markers.native_bootstrap);
    common.printBootMarker(boot_markers.tcb_defined);

    const ids = session_bootstrap.principals();
    try session_bootstrap.initializeUserspace(
        &self.userspace_catalog,
        &self.runtime,
        &self.capability_table,
        &self.userspace_scheduler,
    );
    const services = try session_bootstrap.registerCoreServices(&self.supervisor, &self.runtime_service, ids);

    const session_task = launchNativeBootstrapService(self, ids, services, .session_manager) catch |err| {
        _ = self.supervisor.recordCrash(services.session.id, 0, bootFailureCode(err));
        return err;
    };
    common.printBootMarker(boot_markers.policy_ready);

    const review_service_task = launchNativeBootstrapService(self, ids, services, .permission_review_ui) catch |err| {
        _ = self.supervisor.recordCrash(services.review_service_record.id, 0, bootFailureCode(err));
        return err;
    };
    common.printBootMarker(boot_markers.permission_ui_service_ready);
    common.printBootMarker(boot_markers.permission_ui_service_task_ready);

    const session_capability = mintNativeBootstrapGrant(self, ids, services, session_task.id, .session_manager, .session_service_authority) catch |err| {
        _ = self.supervisor.recordCrash(services.session.id, 0, bootFailureCode(err));
        return err;
    };
    const policy_capability = mintNativeBootstrapGrant(self, ids, services, session_task.id, .session_manager, .policy_mint_authority) catch |err| {
        _ = self.supervisor.recordCrash(services.policy_service.id, 0, bootFailureCode(err));
        return err;
    };
    recordSessionTaskBootstrap(self, session_task.id, session_capability.id, policy_capability.id) catch |err| {
        _ = self.supervisor.recordCrash(services.session.id, 0, bootFailureCode(err));
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
        &self.userspace_catalog,
        &self.runtime,
        bundle_id,
        .{
            .owner = serviceOwner(ids, class),
            .budget = launch.budget,
            .ui_surface_id = launch.ui_surface_id,
            .local_only = true,
        },
        &self.userspace_scheduler,
    ) catch |err| {
        _ = self.supervisor.recordCrash(serviceRecord(services, class).id, launch.tick, bootFailureCode(err));
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
    return try self.capability_table.mintBootRoot(.{
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

fn serviceOwner(ids: session_bootstrap.Principals, class: service_catalog.ServiceClass) principal.PrincipalId {
    return switch (class) {
        .task_runtime => ids.task_runtime_service,
        .session_manager => ids.session_service,
        .policy_mediation => ids.policy_authority,
        .permission_review_ui => ids.review_service,
        .service_registry => ids.policy_authority,
        .compatibility_portal => ids.compatibility_service,
        .network_stack => ids.network_service,
        .storage_object => ids.storage_service,
        .package_install_update => ids.package_service,
        .compositor_ui_session => ids.compositor_service,
        .indexing_search => ids.indexing_service,
        .sync_replication => ids.sync_service,
        .media_print_helpers => ids.media_service,
    };
}

fn serviceRecord(services: session_bootstrap.CoreServices, class: service_catalog.ServiceClass) *supervisor_mod.ServiceRecord {
    return switch (class) {
        .task_runtime => services.runtime_service_record,
        .session_manager => services.session,
        .policy_mediation => services.policy_service,
        .permission_review_ui => services.review_service_record,
        .service_registry => services.service_registry,
        .compatibility_portal => services.compatibility_service,
        .network_stack => services.network_service,
        .storage_object => services.storage_service,
        .package_install_update => services.package_service,
        .compositor_ui_session => services.compositor_service,
        .indexing_search => services.indexing_service,
        .sync_replication => services.sync_service,
        .media_print_helpers => services.media_service,
    };
}

fn recordSessionTaskBootstrap(
    self: *SessionManager,
    session_task_id: u64,
    session_capability_id: u64,
    policy_capability_id: u64,
) task_runtime.Error!void {
    try self.runtime.grantCapability(session_task_id, session_capability_id);
    try self.runtime.grantCapability(session_task_id, policy_capability_id);
    try self.runtime.audit(session_task_id, .{
        .kind = .created,
        .tick = 0,
    });
    try self.runtime.audit(session_task_id, .{
        .kind = .capability_granted,
        .capability_id = session_capability_id,
        .tick = 0,
    });
    try self.runtime.audit(session_task_id, .{
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
    self.kernel_instance = native_kernel.Kernel.init(
        policy_authority,
        self.runtime_service.runtimePtr(),
        &self.capability_table,
        &self.endpoint_table,
        &self.shared_memory_table,
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

pub fn printReadyBanner() void {
    console.print("Zigos native session manager online\n");
    console.print("Native ABI: capability-ipc-v");
    printNumber(abi.ABI_VERSION);
    console.print("\n");
    console.print("Native-only platform ready\n");
}

fn recordProductionMeasuredBoot(manager: *SessionManager, graph: *const ServiceGraph) void {
    var measured = measured_boot.Recorder.init();
    measured.begin(1);
    measured.add(.kernel, "bootloader+kernel-zigos-native", "src/boot/boot64.S:zig-out/bin/kernel-zigos-native.elf") catch unreachable;
    measured.add(.base_image, "production-native-base", "native-store:production-service-graph") catch unreachable;
    measured.add(.policy, "production-policy-set", "zero-root:capability-ipc:local-first") catch unreachable;

    const critical_services = [_]*supervisor_mod.ServiceRecord{
        graph.state.services.policy_service,
        graph.state.services.storage_service,
        graph.state.services.compositor_service,
        graph.state.services.network_service,
    };
    for (critical_services) |service_record| {
        const image = criticalServiceImage(manager, service_record) orelse unreachable;
        measured.addCriticalServiceImage(service_record, image) catch unreachable;
    }
    measured.addDriverSet("production-driver-set", &manager.driver_directory) catch unreachable;

    const boot = measured.finalize();
    printMeasurementSummary(&boot);
    supportMeasuredBootShape(&boot);
    recordMeasurementComparison(manager, &boot);
}

fn criticalServiceImage(
    manager: *SessionManager,
    service_record: *const supervisor_mod.ServiceRecord,
) ?*const userspace_loader.ImageRecord {
    const bundle_id = service_catalog.bundleIdForServiceClass(service_record.class) orelse return null;
    return manager.userspace_catalog.findByBundleId(bundle_id);
}

fn supportMeasuredBootShape(boot: *const measured_boot.BootRecord) void {
    if (boot.countKind(.kernel) == 1 and
        boot.countKind(.base_image) == 1 and
        boot.countKind(.critical_service) == 4 and
        boot.countKind(.policy) == 1 and
        boot.countKind(.driver_set) == 1 and
        !std.mem.allEqual(u8, &boot.root_digest, 0))
    {
        common.printBootMarker(boot_markers.platform_measured_boot_recorded);
    }
}

fn recordMeasurementComparison(manager: *SessionManager, boot: *const measured_boot.BootRecord) void {
    const measurement_signer = signing.SignerIdentity{
        .label = "zigos-measured-boot-state",
        .seed = [_]u8{0xA6} ** 32,
    };
    var journal = measured_boot.MeasurementJournal.init(
        &manager.storage_service_instance,
        session_bootstrap.principals().package_service,
        measurement_signer,
    ) catch unreachable;
    const comparison = journal.record(boot.*, 130) catch unreachable;
    manager.storage_service_instance.checkpoint();
    if (comparison.previous == null) {
        common.printBootMarker(boot_markers.platform_measured_boot_first);
        return;
    }
    if (comparison.same_root_digest) {
        common.printBootMarker(boot_markers.platform_measured_boot_same_root);
    }
    if (comparison.same_record_shape) {
        common.printBootMarker(boot_markers.platform_measured_boot_same_shape);
    }
}

fn printMeasurementSummary(boot: *const measured_boot.BootRecord) void {
    console.print("ZIGOS:PLATFORM:MEASURED_BOOT:ROOT ");
    printHexDigest(&boot.root_digest);
    console.print("\n");
    for (boot.records[0..boot.record_count]) |record| {
        console.print("ZIGOS:PLATFORM:MEASURED_BOOT:RECORD ");
        console.print(@tagName(record.kind));
        console.print(" ");
        console.print(record.labelSlice());
        console.print(" ");
        printHexDigest(&record.digest);
        console.print("\n");
    }
}

fn printHexDigest(digest: *const [32]u8) void {
    const hex = "0123456789abcdef";
    for (digest.*) |byte| {
        console.printChar(hex[byte >> 4]);
        console.printChar(hex[byte & 0x0f]);
    }
}

fn printNumber(value: u64) void {
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch return;
    console.print(text);
}

fn bootFailureCode(err: anyerror) u32 {
    var hash: u64 = 14695981039346656037;
    for (@errorName(err)) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return @truncate(hash);
}
