const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../kernel/boot/markers.zig");
const abi = @import("../core/abi.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const bootstrap_driver_port = @import("../drivers/bootstrap_driver_port.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const manifest = @import("../policy/manifest.zig");
const compositor_display = @import("../platform/compositor_display.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const input_router_mod = @import("../platform/input_router.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const native_service_registry = @import("../services/service_registry.zig");
const native_util = @import("../core/util.zig");
const native_ux = @import("../platform/native_ux.zig");
const principal = @import("../core/principal.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const package_service = @import("../services/package_service.zig");
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
const userspace_flags = @import("../task/userspace_flags.zig");
const trust_boot = @import("trust_boot.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_launch = @import("../task/userspace_launch.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const workspace_mod = @import("../storage/workspace.zig");

pub const BootstrapState = session_support.BootstrapState;
pub const ServiceBindings = session_support.ServiceBindings;
pub const Environment = session_support.Environment;
pub const HEAP_BACKED_CAPABILITY_TABLE_ON_FREESTANDING = session_contexts.HEAP_BACKED_CAPABILITY_TABLE_ON_FREESTANDING;
pub const HEAP_BACKED_ENDPOINT_TABLE_ON_FREESTANDING = session_contexts.HEAP_BACKED_ENDPOINT_TABLE_ON_FREESTANDING;
pub const ENDPOINT_TABLE_HANDLE_SIZE_CEILING_BYTES = session_contexts.ENDPOINT_TABLE_HANDLE_SIZE_CEILING_BYTES;
pub const kernel_context_layout = session_contexts.kernel_context_layout;
pub const HEAP_BACKED_USERSPACE_CATALOG_ON_FREESTANDING = session_contexts.HEAP_BACKED_USERSPACE_CATALOG_ON_FREESTANDING;
pub const BOOTSTRAP_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const UI_AUTHORITY_TASK_INDEX_RELOOKUPS: u8 = 0;
pub const HEAP_BACKED_USERSPACE_SCHEDULER_ON_FREESTANDING = session_contexts.HEAP_BACKED_USERSPACE_SCHEDULER_ON_FREESTANDING;
pub const HEAP_BACKED_TASK_RUNTIME_ON_FREESTANDING = session_contexts.HEAP_BACKED_TASK_RUNTIME_ON_FREESTANDING;
pub const HEAP_BACKED_PACKAGE_SERVICE_ON_FREESTANDING = service_graph_builder.HEAP_BACKED_PACKAGE_SERVICE_ON_FREESTANDING;
pub const HEAP_BACKED_BACKGROUND_DISPATCH_ON_FREESTANDING = service_graph_builder.HEAP_BACKED_BACKGROUND_DISPATCH_ON_FREESTANDING;
pub const BACKGROUND_DISPATCH_HANDLE_SIZE_CEILING_BYTES = service_graph_builder.BACKGROUND_DISPATCH_HANDLE_SIZE_CEILING_BYTES;
pub const background_dispatch_layout = service_graph_builder.background_dispatch_layout;
pub const HEAP_BACKED_REVIEW_UX_CONTROLLER_ON_FREESTANDING = session_contexts.HEAP_BACKED_REVIEW_UX_CONTROLLER_ON_FREESTANDING;
pub const REVIEW_UX_CONTROLLER_HANDLE_SIZE_CEILING_BYTES = session_contexts.REVIEW_UX_CONTROLLER_HANDLE_SIZE_CEILING_BYTES;
pub const recovery_context_layout = session_contexts.recovery_context_layout;
const BootstrapError = error{ MissingBootstrapLaunch, MissingBootstrapGrant, MissingUserspaceImage } || session_bootstrap.Error || userspace_launch.Error || capability.Error || task_runtime.Error;
const NETWORK_RECEIVE_SERVICE_BUDGET: usize = 8;

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
const kernel_config = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/config.zig")
else
    struct {
        pub fn includesVerificationEvidence() bool {
            return true;
        }
    };
const include_verification_evidence = kernel_config.includesVerificationEvidence();

pub const SessionManager = struct {
    initialized: bool = false,
    kernel_context: session_contexts.KernelContext = session_contexts.KernelContext.init(),
    runtime_context: session_contexts.RuntimeContext = session_contexts.RuntimeContext.init(),
    service_graph_builder: service_graph_builder.Builder = service_graph_builder.Builder.init(),
    native_store: native_store_mount.NativeStoreMount = native_store_mount.NativeStoreMount.init(),
    recovery_context: session_contexts.RecoveryContext = session_contexts.RecoveryContext.init(),
    input_router: input_router_mod.Router = .{},
    compositor_broker_service_id: u64 = 0,
    input_authority_failures: usize = 0,
    surface_authority_failures: usize = 0,
    surface_authority_scanned_lifecycle_generation: u64 = 0,

    pub fn init() SessionManager {
        return .{};
    }

    fn ensureConstructed(self: *SessionManager) bool {
        self.runtime_context.ensureConstructed() catch return false;
        return true;
    }

    pub fn reset(self: *SessionManager) void {
        permission_review_service.clearSystemInputRouter();
        self.input_router.deinit();
        self.runtime_context.releaseUserspaceScheduler();
        self.runtime_context.runtime_checkpoint_store.reset();
        self.runtime_context.releaseTaskRuntime();
        self.runtime_context.releaseUserspaceCatalog();
        self.kernel_context.releaseEndpointTable();
        self.kernel_context.shared_memory_table.deinit();
        self.kernel_context.releaseCapabilityTable();
        self.recovery_context.review_compositor_session.deinit();
        self.recovery_context.releaseReviewUxController();
        self.recovery_context.diagnostic_ledger.deinit();
        self.service_graph_builder.releaseBackgroundDispatch();
        self.service_graph_builder.releasePackageService();
        self.native_store.resetPersistent();
        self.* = SessionManager.init();
        bootstrap_driver_port.reset();
        session_service_bootstrap.resetBootedDataPlanes();
        if (self.ensureConstructed()) self.runtime_context.resetScheduler();
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
        if (!self.ensureConstructed()) {
            native_util.impossibleByInvariant("task runtime access requires constructed session state");
        }
        return self.runtime_context.taskRuntime() orelse
            native_util.impossibleByInvariant("constructed session state retains its task runtime");
    }

    pub fn runtimeServicePtr(self: *SessionManager) *task_runtime_service_mod.Service {
        if (!self.ensureConstructed()) {
            native_util.impossibleByInvariant("runtime service access requires constructed session state");
        }
        return &self.runtime_context.runtime_service;
    }

    pub fn capabilityTablePtr(self: *SessionManager) *capability.CapabilityTable {
        return self.kernel_context.capabilityTable() orelse
            native_util.impossibleByInvariant("session capability access follows table allocation");
    }

    pub fn userspaceCatalogPtr(self: *SessionManager) *userspace_loader.Catalog {
        return self.runtime_context.userspaceCatalog() orelse
            native_util.impossibleByInvariant("session userspace catalog access follows allocation");
    }

    pub fn userspaceSchedulerPtr(self: *SessionManager) *userspace_scheduler.Scheduler {
        if (!self.ensureConstructed()) {
            native_util.impossibleByInvariant("userspace scheduler access requires constructed session state");
        }
        return self.runtime_context.userspaceScheduler() orelse
            native_util.impossibleByInvariant("constructed session state retains its userspace scheduler");
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
        return self.native_store.checkpointStorePtr() orelse
            native_util.impossibleByInvariant("booted storage service retains checkpoint state");
    }

    pub fn exportPackagePtr(self: *SessionManager) error{NoSpaceLeft}!*workspace_mod.ExportPackage {
        return self.native_store.exportPackagePtr();
    }

    pub fn syncResidentStatePtr(self: *SessionManager) error{NoSpaceLeft}!*sync_service_mod.ResidentState {
        return self.native_store.syncResidentStatePtr();
    }

    pub fn packageServicePtr(self: *SessionManager) *package_service.Service {
        return self.service_graph_builder.ensurePackageService() catch
            native_util.impossibleByInvariant("package service access requires allocated service-graph state");
    }

    pub fn reviewUxControllerPtr(self: *SessionManager) error{NoSpaceLeft}!*native_ux.Controller {
        return self.recovery_context.ensureReviewUxController();
    }

    pub fn compositorSessionPtr(self: *SessionManager) *compositor_session.Session {
        return &self.recovery_context.review_compositor_session;
    }

    pub fn inputRouterPtr(self: *SessionManager) *input_router_mod.Router {
        return &self.input_router;
    }

    pub fn backgroundDispatchPtr(self: *SessionManager) error{NoSpaceLeft}!*background_dispatch.Controller {
        return self.service_graph_builder.ensureBackgroundDispatch();
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
        const runtime = self.runtimePtr();
        _ = self.recovery_context.review_compositor_session.pruneSurfacePresentations(runtime);
        if (runtime.taskLifecycleGeneration() != self.surface_authority_scanned_lifecycle_generation) {
            _ = self.provisionSurfacePresentationCapabilities(now_ticks);
        }
        return self.runtime_context.runScheduler(now_ticks);
    }

    pub fn userspaceSchedulerHasReadyTasks(self: *const SessionManager) bool {
        return self.runtime_context.schedulerHasReadyTasks();
    }

    pub fn servicePendingNetworkWork(self: *SessionManager, now_ticks: u64) usize {
        const service = bootstrap_driver_port.servicePendingNetworkFrames(NETWORK_RECEIVE_SERVICE_BUDGET);
        if (service.frames_queued != 0) {
            const task_id = bootstrap_driver_port.activeNetworkTaskId();
            if (task_id != 0) {
                _ = self.userspaceSchedulerPtr().wakeTask(
                    task_id,
                    .external_event,
                    now_ticks,
                    now_ticks +% 1,
                );
            }
        }
        return service.frames_queued;
    }

    pub fn bindHardwareInput(self: *SessionManager, source: input_router_mod.HardwareReportSource) void {
        self.input_router.bindHardwareSource(source);
    }

    pub fn servicePendingInputWork(self: *SessionManager, now_ticks: u64) usize {
        const result = self.input_router.service(now_ticks, input_router_mod.DEFAULT_REPORT_BUDGET);
        while (self.input_router.pollWakeTarget()) |task_id| {
            if (self.ensureFocusedInputCapability(task_id, now_ticks) == null) {
                self.input_authority_failures += 1;
                _ = self.input_router.dropForTask(task_id);
                continue;
            }
            _ = self.userspaceSchedulerPtr().wakeTask(
                task_id,
                .external_event,
                now_ticks,
                now_ticks +% 1,
            );
        }
        return result.events_routed;
    }

    pub fn focusedInputCapabilityForTask(self: *SessionManager, task_id: u64, now_ticks: u64) ?u64 {
        const task = self.runtimePtr().find(task_id) orelse return null;
        return self.focusedInputCapabilityForResolvedTask(task, now_ticks);
    }

    fn focusedInputCapabilityForResolvedTask(self: *SessionManager, task: *const task_runtime.TaskRecord, now_ticks: u64) ?u64 {
        for (task.capabilityIds()) |capability_id| {
            const granted = self.capabilityTablePtr().requireUsable(capability_id, now_ticks) catch continue;
            if (granted.target.kind != .task or granted.target.id != task.id) continue;
            if (granted.scope.task_id != task.id or !granted.rights.has(.input_recv)) continue;
            return capability_id;
        }
        return null;
    }

    fn ensureFocusedInputCapability(self: *SessionManager, task_id: u64, now_ticks: u64) ?u64 {
        const task = self.runtimePtr().find(task_id) orelse return null;
        if (self.focusedInputCapabilityForResolvedTask(task, now_ticks)) |capability_id| return capability_id;
        if (self.compositor_broker_service_id == 0) return null;
        const granted = self.capabilityTablePtr().mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel_context.kernel_instance.policy_authority,
            .target = .{ .kind = .task, .id = task.id },
            .rights = .{ .task = .{ .input_recv = true } },
            .scope = .{
                .task_id = task.id,
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
                .source_task_id = self.input_router.compositor_task_id,
                .broker_service_id = self.compositor_broker_service_id,
                .user_visible_entitlement = true,
            },
        }) catch return null;
        task_runtime.grantCapabilityToTask(task, granted.id) catch {
            self.capabilityTablePtr().revokeGrant(granted.id) catch {};
            return null;
        };
        return granted.id;
    }

    pub fn surfacePresentationCapabilityForTask(self: *SessionManager, task_id: u64, now_ticks: u64) ?u64 {
        const task = self.runtimePtr().find(task_id) orelse return null;
        return self.surfacePresentationCapabilityForResolvedTask(task, now_ticks);
    }

    fn surfacePresentationCapabilityForResolvedTask(self: *SessionManager, task: *const task_runtime.TaskRecord, now_ticks: u64) ?u64 {
        for (task.capabilityIds()) |capability_id| {
            const granted = self.capabilityTablePtr().requireUsable(capability_id, now_ticks) catch continue;
            if (granted.target.kind != .task or granted.target.id != task.id) continue;
            if (granted.scope.task_id != task.id or !granted.rights.has(.surface_present)) continue;
            return capability_id;
        }
        return null;
    }

    fn ensureSurfacePresentationCapability(self: *SessionManager, task_id: u64, now_ticks: u64) ?u64 {
        const task = self.runtimePtr().find(task_id) orelse return null;
        return self.ensureSurfacePresentationCapabilityForResolvedTask(task, now_ticks);
    }

    fn ensureSurfacePresentationCapabilityForResolvedTask(self: *SessionManager, task: *task_runtime.TaskRecord, now_ticks: u64) ?u64 {
        if (self.surfacePresentationCapabilityForResolvedTask(task, now_ticks)) |capability_id| return capability_id;
        if (!self.taskOwnsUiSurface(task) or self.compositor_broker_service_id == 0) return null;
        const granted = self.capabilityTablePtr().mintBootRoot(.{
            .holder = task.owner,
            .issuer = self.kernel_context.kernel_instance.policy_authority,
            .target = .{ .kind = .task, .id = task.id },
            .rights = .{ .task = .{ .surface_present = true } },
            .scope = .{
                .task_id = task.id,
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
                .source_task_id = self.input_router.compositor_task_id,
                .broker_service_id = self.compositor_broker_service_id,
                .user_visible_entitlement = true,
            },
        }) catch return null;
        task_runtime.grantCapabilityToTask(task, granted.id) catch {
            self.capabilityTablePtr().revokeGrant(granted.id) catch {};
            return null;
        };
        return granted.id;
    }

    fn provisionSurfacePresentationCapabilities(self: *SessionManager, now_ticks: u64) bool {
        const runtime = self.runtimePtr();
        var complete = true;
        var slot_index: usize = 0;
        while (slot_index < runtime.taskSlotCapacity()) : (slot_index += 1) {
            const slot = runtime.taskSlotAt(slot_index);
            if (!slot.in_use or !self.taskOwnsUiSurface(&slot.task)) continue;
            if (self.ensureSurfacePresentationCapabilityForResolvedTask(&slot.task, now_ticks) != null) continue;
            self.surface_authority_failures += 1;
            complete = false;
        }
        if (complete) self.surface_authority_scanned_lifecycle_generation = runtime.taskLifecycleGeneration();
        return complete;
    }

    fn taskOwnsUiSurface(self: *SessionManager, task: *const task_runtime.TaskRecord) bool {
        if (task.state != .active or task.ui_surface_id == null or task.ui_surface_id.? == 0) return false;
        const image = self.userspaceCatalogPtr().findById(task.launch.image_id) orelse return false;
        return (image.contract_flags & userspace_flags.FLAG_OWNS_UI_SURFACE) != 0;
    }

    pub fn networkWorkPending(_: *const SessionManager) bool {
        return bootstrap_driver_port.networkWorkPending();
    }

    pub fn boot(self: *SessionManager) void {
        if (smokeFaultModeIs("storage_durability")) {
            self.bootStorageDurabilityProof();
            return;
        }
        const graph = self.buildProductionServiceGraph() orelse return;
        if (comptime !include_verification_evidence) {
            self.storageServicePtr().checkpoint_enabled = true;
        }
        var trust = self.trustBoot();
        if (!trust.recordProductionMeasuredBoot(&graph)) {
            self.failBoot();
            return;
        }
        if (!self.finishUserspaceSurfacePresentation(&graph)) {
            self.failBoot();
            return;
        }
        if (comptime include_verification_evidence) {
            const runtime_negative_proofs = @import("runtime_negative_proofs.zig");
            if (!runtime_negative_proofs.runAndPrint()) {
                self.failBoot();
                return;
            }
            if (!runtime_negative_proofs.runFreestandingAndPrint(
                self.userspaceCatalogPtr(),
                self.runtimePtr(),
                self.userspaceSchedulerPtr(),
            )) {
                self.failBoot();
                return;
            }
            if (builtin.target.os.tag == .freestanding) {
                const booted_evidence = @import("booted_evidence.zig");
                if (!booted_evidence.runProduction(self, &graph)) {
                    self.failBoot();
                    return;
                }
            }
        }
        stack_watermark.reportPeak();
        userspace_executor.reportTrapStackPeak();
        const checkpoint_clean = self.reportFinalCheckpointState();
        if (comptime !include_verification_evidence) {
            if (!checkpoint_clean) {
                self.failBoot();
                return;
            }
        }
        common.printBootMarker(boot_markers.task_session_ready);
        common.printBootMarker(boot_markers.native_ready);
        printReadyBanner();
    }

    fn reportFinalCheckpointState(self: *SessionManager) bool {
        const storage = self.storageServicePtr();
        const checkpoint_error: []const u8 = if (storage.checkpoint_store.last_checkpoint_error) |err| @errorName(err) else "none";

        var line_buffer: [128]u8 = undefined;
        const line = std.fmt.bufPrint(
            &line_buffer,
            "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled={} dirty={} generation={d} error={s}",
            .{
                storage.checkpoint_enabled,
                storage.pendingCheckpointMutations(),
                storage.checkpoint_store.last_checkpoint_generation,
                checkpoint_error,
            },
        ) catch return false;
        common.printBootMarker(line);
        return storage.checkpoint_enabled and
            !storage.pendingCheckpointMutations() and
            storage.checkpoint_store.last_checkpoint_error == null;
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
        if (!self.bindProductionStorageService(&graph)) {
            self.failBoot();
            return;
        }
        if (!storage_durability_qemu.run(&self.native_store.storage_service_instance)) {
            self.failBoot();
            return;
        }
    }

    pub fn beginServiceGraph(self: *SessionManager) ?ServiceGraph {
        if (!self.ensureConstructed()) return null;
        if (self.initialized) return null;
        self.initialized = true;
        self.kernel_context.resetPort();
        _ = self.kernel_context.ensureCapabilityTable() catch {
            self.failBoot();
            return null;
        };
        _ = self.kernel_context.ensureEndpointTable() catch {
            self.failBoot();
            return null;
        };
        _ = self.runtime_context.ensureUserspaceCatalog() catch {
            self.failBoot();
            return null;
        };
        _ = self.service_graph_builder.ensurePackageService() catch {
            self.failBoot();
            return null;
        };

        const env = self.service_graph_builder.environment(
            &self.runtime_context,
            &self.kernel_context,
            &self.recovery_context,
        );
        const state = initializeBootstrapState(self) catch {
            self.failBoot();
            return null;
        };
        self.packageServicePtr().bind(
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
        if (!self.service_graph_builder.bootProduction(&graph, include_verification_evidence)) {
            self.failBoot();
            return null;
        }
        if (!self.bindFocusedInputRouting(&graph)) {
            self.failBoot();
            return null;
        }
        if (!self.bindProductionStorageService(&graph)) {
            self.failBoot();
            return null;
        }
        self.runtime_context.runtime_service.checkpoint(60) catch {
            self.failBoot();
            return null;
        };
        var trust = self.trustBoot();
        if (comptime include_verification_evidence) {
            if (!trust.proveProductionAbImageRollback(&graph)) {
                self.failBoot();
                return null;
            }
            if (!trust.proveProductionPostActivationHealthChecks(&graph)) {
                self.failBoot();
                return null;
            }
        }
        if (!trust.verifyProductionArtifactManifest(&graph)) {
            self.failBoot();
            return null;
        }
        return graph;
    }

    pub fn bindFocusedInputRouting(self: *SessionManager, graph: *const ServiceGraph) bool {
        const compositor_task_id = graph.service_bindings.bindingFor(.compositor_ui_session).task_id;
        const compositor_task = self.runtimePtr().find(compositor_task_id) orelse return false;
        self.input_router.bindCompositor(
            &self.recovery_context.review_compositor_session,
            compositor_task_id,
        );
        self.compositor_broker_service_id = graph.state.services.compositor_service.id;
        self.kernel_context.kernel_instance.bindFocusedInputReceiver(.{
            .context = &self.input_router,
            .poll = pollFocusedInputForKernel,
        });
        self.kernel_context.kernel_instance.bindSurfacePresentationReceiver(.{
            .context = &self.recovery_context.review_compositor_session,
            .present = presentSurfaceForKernel,
        });
        if (!sessionHasTaskSurfaceWindow(&self.recovery_context.review_compositor_session, compositor_task)) {
            _ = self.recovery_context.review_compositor_session.openTaskView(compositor_task, "Zigos") catch return false;
        }
        if (!self.provisionSurfacePresentationCapabilities(0)) return false;
        permission_review_service.bindSystemInputRouter(&self.input_router);
        common.printBootMarker(boot_markers.compositor_input_router_ready);
        common.printBootMarker(boot_markers.userspace_input_abi_ready);
        return true;
    }

    fn finishUserspaceSurfacePresentation(self: *SessionManager, graph: *const ServiceGraph) bool {
        const compositor_task_id = graph.service_bindings.bindingFor(.compositor_ui_session).task_id;
        const runtime = self.runtimePtr();
        const compositor_task = runtime.find(compositor_task_id) orelse return false;
        if (builtin.target.os.tag == .freestanding) {
            _ = self.userspaceSchedulerPtr().wakeTask(compositor_task_id, .external_event, 0, 1);
            var attempts: usize = 0;
            const dispatch_budget = runtime.taskSlotCapacity() * 8;
            while (attempts < dispatch_budget and
                self.recovery_context.review_compositor_session.surfacePresentation(compositor_task.ui_surface_id.?) == null) : (attempts += 1)
            {
                if (!self.userspaceSchedulerPtr().hasReadyTasks()) break;
                _ = self.runUserspaceScheduler(@intCast(attempts + 1));
            }
            if (!self.proveUserspaceSurfacePresentation(compositor_task)) {
                self.printSurfacePresentationTelemetry(compositor_task.id);
                return false;
            }
        }
        common.printBootMarker(boot_markers.userspace_surface_presentation_ready);
        return true;
    }

    fn proveUserspaceSurfacePresentation(self: *SessionManager, compositor_task: *const task_runtime.TaskRecord) bool {
        const surface_id = compositor_task.ui_surface_id orelse return false;
        const surface = self.recovery_context.review_compositor_session.surfacePresentation(surface_id) orelse return false;
        if (surface.task_id != compositor_task.id or surface.presentation.revision == 0) return false;
        const model = abi.surfaceModelKind(surface.presentation.model_kind) orelse return false;
        if (model != .compositor) return false;
        const dispatch = self.userspaceSchedulerPtr().taskDispatchStats(compositor_task.id) orelse return false;
        if (dispatch.last_ui_state_revision != surface.presentation.revision) return false;
        const mailbox = self.runtime_context.userspace_executor.bootstrapMailboxSnapshot(
            self.userspaceCatalogPtr(),
            self.runtimePtr(),
            compositor_task.id,
        ) orelse return false;
        if (mailbox.surface_presentation_capability_id == 0 or
            mailbox.ui_surface_id != surface_id or
            mailbox.ui_state_revision != surface.presentation.revision or
            mailbox.ui_presented_revision != surface.presentation.revision or
            mailbox.ui_presentation_failures != 0 or
            mailbox.ui_last_presentation_status != @intFromEnum(abi.SyscallStatus.success)) return false;

        var storage: [compositor_display.MIN_WIDTH * compositor_display.MIN_HEIGHT]u8 = undefined;
        var framebuffer = compositor_display.Framebuffer.init(&storage, compositor_display.MIN_WIDTH, compositor_display.MIN_HEIGHT) catch return false;
        framebuffer.renderSession(&self.recovery_context.review_compositor_session) catch return false;
        var expected_buffer: [96]u8 = undefined;
        const expected = std.fmt.bufPrint(&expected_buffer, "surface_state model=compositor revision={d}", .{surface.presentation.revision}) catch return false;
        _ = framebuffer.requirePresentation(
            expected,
            self.recovery_context.review_compositor_session.visibleWindowCount(),
            self.recovery_context.review_compositor_session.active_window_id,
        ) catch return false;
        return true;
    }

    fn printSurfacePresentationTelemetry(self: *SessionManager, task_id: u64) void {
        const runtime = self.runtimePtr();
        const mailbox = self.runtime_context.userspace_executor.bootstrapMailboxSnapshot(
            self.userspaceCatalogPtr(),
            runtime,
            task_id,
        ) orelse {
            console.print("ZIGOS:USERSPACE:SURFACE_PRESENTATION:FAIL mailbox=missing\n");
            return;
        };
        const dispatch = self.userspaceSchedulerPtr().taskDispatchStats(task_id);
        const task = runtime.find(task_id);
        const authority = self.capabilityTablePtr().query(mailbox.authority_capability_id);
        var line_buffer: [512]u8 = undefined;
        const line = std.fmt.bufPrint(
            &line_buffer,
            "ZIGOS:USERSPACE:SURFACE_PRESENTATION:FAIL task={d} owner={d}:{d} authority={d} holder={d}:{d} target={d}:{d} rights={x} scope_task={d} capability={d} surface={d} stage={d} counter={d} service_ops={d} service_flags={d} state_revision={d} presented_revision={d} failures={d} status={d} dispatches={d} waits={d} queued={}\n",
            .{
                task_id,
                if (task) |record| @intFromEnum(record.owner.kind) else 0,
                if (task) |record| record.owner.serial else 0,
                mailbox.authority_capability_id,
                if (authority) |granted| @intFromEnum(granted.holder.kind) else 0,
                if (authority) |granted| granted.holder.serial else 0,
                if (authority) |granted| @intFromEnum(granted.target.kind) else 0,
                if (authority) |granted| granted.target.id else 0,
                if (authority) |granted| granted.rights.toBits() else 0,
                if (authority) |granted| granted.scope.task_id orelse 0 else 0,
                mailbox.surface_presentation_capability_id,
                mailbox.ui_surface_id,
                mailbox.stage,
                mailbox.last_counter,
                mailbox.service_operation_count,
                mailbox.service_status_flags,
                mailbox.ui_state_revision,
                mailbox.ui_presented_revision,
                mailbox.ui_presentation_failures,
                mailbox.ui_last_presentation_status,
                if (dispatch) |stats| stats.dispatch_count else 0,
                if (dispatch) |stats| stats.event_wait_count else 0,
                if (dispatch) |stats| stats.queued_ready else false,
            },
        ) catch return;
        console.print(line);
    }

    pub fn bindProductionStorageService(self: *SessionManager, graph: *const ServiceGraph) bool {
        self.native_store.bindProduction(
            graph.state.services.storage_service.id,
            graph.service_bindings.bindingFor(.storage_object).task_id,
            graph.state.ids.storage_service,
            self.capabilityTablePtr(),
        ) catch return false;
        return true;
    }

    pub fn failBoot(self: *SessionManager) void {
        self.initialized = false;
        self.kernel_context.kernel_instance.clearFocusedInputReceiver();
        self.kernel_context.kernel_instance.clearSurfacePresentationReceiver();
        self.input_router.clearCompositor();
        self.compositor_broker_service_id = 0;
        self.surface_authority_scanned_lifecycle_generation = 0;
        permission_review_service.clearSystemInputRouter();
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

fn pollFocusedInputForKernel(context: *anyopaque, task_id: u64) ?abi.InputEventDescriptor {
    const router: *input_router_mod.Router = @ptrCast(@alignCast(context));
    return router.pollAbiForTask(task_id);
}

fn sessionHasTaskSurfaceWindow(
    session: *const compositor_session.Session,
    task: *const task_runtime.TaskRecord,
) bool {
    const surface_id = task.ui_surface_id orelse return false;
    var order: usize = 0;
    while (order < session.window_count) : (order += 1) {
        const window = session.windowAtOrder(order) orelse continue;
        if (window.subject_task_id == task.id and window.ui_surface_id == surface_id) return true;
    }
    return false;
}

fn initializeBootstrapState(self: *SessionManager) BootstrapError!BootstrapState {
    common.printBootMarker(boot_markers.native_bootstrap);
    common.printBootMarker(boot_markers.tcb_defined);

    const ids = session_bootstrap.principals();
    try session_bootstrap.initializeUserspace(
        self.userspaceCatalogPtr(),
        self.runtimePtr(),
        self.capabilityTablePtr(),
        self.userspaceSchedulerPtr(),
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
    grantNativeServiceTaskAuthority(
        self,
        ids,
        services,
        session_task.id,
        review_service_task,
        .permission_review_ui,
    ) catch |err| {
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
    recordSessionTaskBootstrap(session_task, session_capability.id, policy_capability.id) catch |err| {
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
        self.userspaceCatalogPtr(),
        self.runtimePtr(),
        bundle_id,
        .{
            .owner = session_bootstrap.ownerForServiceClass(ids, class) orelse return error.MissingBootstrapLaunch,
            .budget = launch.budget,
            .ui_surface_id = launch.ui_surface_id,
            .local_only = true,
        },
        self.userspaceSchedulerPtr(),
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
    return try self.capabilityTablePtr().mintBootRoot(.{
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
            .renewable = false,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task_id,
            .broker_service_id = broker_service_id,
        },
    });
}

fn grantNativeServiceTaskAuthority(
    self: *SessionManager,
    ids: session_bootstrap.Principals,
    services: session_bootstrap.CoreServices,
    source_task_id: u64,
    task: *task_runtime.TaskRecord,
    class: service_catalog.ServiceClass,
) BootstrapError!void {
    if (!catalogDeclaresGrant(class, .service_task_authority)) return error.MissingBootstrapGrant;
    const service = session_bootstrap.serviceRecordForClass(services, class) orelse return error.MissingBootstrapGrant;
    const granted = try self.capabilityTablePtr().mintBootRoot(.{
        .holder = task.owner,
        .issuer = ids.policy_authority,
        .target = .{ .kind = .service, .id = service.id },
        .rights = service_catalog.rightsForBootstrapGrant(.service_task_authority),
        .scope = .{
            .task_id = task.id,
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
            .source_task_id = source_task_id,
            .broker_service_id = service.id,
        },
    });
    task_runtime.grantCapabilityToTask(task, granted.id) catch |err| {
        self.capabilityTablePtr().revokeGrant(granted.id) catch {};
        return err;
    };
}

fn catalogDeclaresGrant(class: service_catalog.ServiceClass, grant: service_catalog.BootstrapGrantKind) bool {
    const launch = service_catalog.bootstrapLaunchForClass(class) orelse return false;
    for (launch.grants) |declared| {
        if (declared == grant) return true;
    }
    return false;
}

fn recordSessionTaskBootstrap(
    session_task: *task_runtime.TaskRecord,
    session_capability_id: u64,
    policy_capability_id: u64,
) task_runtime.Error!void {
    try task_runtime.grantCapabilityToTask(session_task, session_capability_id);
    try task_runtime.grantCapabilityToTask(session_task, policy_capability_id);
    session_task.appendAudit(.{
        .kind = .created,
        .tick = 0,
    });
    session_task.appendAudit(.{
        .kind = .capability_granted,
        .capability_id = session_capability_id,
        .tick = 0,
    });
    session_task.appendAudit(.{
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

fn presentSurfaceForKernel(
    context: *anyopaque,
    task: *const task_runtime.TaskRecord,
    presentation: *const abi.SurfacePresentation,
) native_kernel.SurfacePresentStatus {
    const session: *compositor_session.Session = @ptrCast(@alignCast(context));
    return switch (session.presentSurface(task, presentation) catch |err| switch (err) {
        error.StalePresentation, error.PresentationConflict => return .stale,
        error.SurfaceTableFull, error.OutOfMemory => return .full,
        else => return .invalid_surface,
    }) {
        .accepted => .accepted,
        .duplicate => .duplicate,
    };
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
