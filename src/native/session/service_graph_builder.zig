const builtin = @import("builtin");
const std = @import("std");
const component_port = @import("../kernel_api/component_port.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_service_registry = @import("../services/service_registry.zig");
const native_util = @import("../core/util.zig");
const package_service = @import("../services/package_service.zig");
const session_contexts = @import("session_manager_contexts.zig");
const session_service_bootstrap = @import("session_service_bootstrap.zig");
const session_support = @import("session_manager_support.zig");
const supervisor_mod = @import("supervisor.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const root = @import("root");

pub const HEAP_BACKED_PACKAGE_SERVICE_ON_FREESTANDING = true;
const heap_backed_package_service = builtin.target.os.tag == .freestanding and HEAP_BACKED_PACKAGE_SERVICE_ON_FREESTANDING;
const PackageServiceBacking = if (heap_backed_package_service) ?*package_service.Service else package_service.Service;
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

pub const BootstrapState = session_support.BootstrapState;
pub const ServiceBindings = session_support.ServiceBindings;
pub const Environment = session_support.Environment;

pub const ServiceGraph = struct {
    env: Environment,
    state: BootstrapState,
    kernel_port: *component_port.KernelPort,
    service_bindings: ServiceBindings,
};

pub const Builder = struct {
    service_directory: native_service_registry.Service = native_service_registry.Service.init(),
    package_service_instance: PackageServiceBacking = if (heap_backed_package_service) null else package_service.Service.init(),
    driver_directory: driver_service.Directory = driver_service.Directory.init(),
    driver_runtime: driver_runtime_mod.Runtime = driver_runtime_mod.Runtime.init(),
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    background_dispatcher: background_dispatch.Controller = background_dispatch.Controller.init(),
    service_bindings: ServiceBindings = ServiceBindings.init(),

    comptime {
        if (heap_backed_package_service and @sizeOf(@This()) > 22 * 1024) {
            @compileError("heap-backed service graph builders exceed their compact resident layout");
        }
    }

    pub fn init() Builder {
        return .{};
    }

    pub fn packageService(self: *Builder) ?*package_service.Service {
        if (comptime heap_backed_package_service) return self.package_service_instance;
        return &self.package_service_instance;
    }

    pub fn ensurePackageService(self: *Builder) error{NoSpaceLeft}!*package_service.Service {
        if (self.packageService()) |service| return service;
        if (comptime heap_backed_package_service) {
            const allocation = kernel_memory.kmalloc(@sizeOf(package_service.Service)) orelse return error.NoSpaceLeft;
            const service: *package_service.Service = @ptrCast(@alignCast(allocation));
            service.initializeAllocated();
            self.package_service_instance = service;
            return service;
        }
        return &self.package_service_instance;
    }

    pub fn releasePackageService(self: *Builder) void {
        if (comptime heap_backed_package_service) {
            if (self.package_service_instance) |service| {
                service.deinit();
                @memset(std.mem.asBytes(service), 0);
                kernel_memory.kfree(@ptrCast(service));
                self.package_service_instance = null;
            }
        } else {
            self.package_service_instance.deinit();
            self.package_service_instance = package_service.Service.init();
        }
    }

    pub fn environment(
        self: *Builder,
        runtime_context: *session_contexts.RuntimeContext,
        kernel_context: *session_contexts.KernelContext,
        recovery_context: *session_contexts.RecoveryContext,
    ) Environment {
        const capability_table = kernel_context.capabilityTable() orelse
            native_util.impossibleByInvariant("service graph construction follows capability-table allocation");
        const userspace_catalog = runtime_context.userspaceCatalog() orelse
            native_util.impossibleByInvariant("service graph construction follows userspace-catalog allocation");
        const userspace_scheduler = runtime_context.userspaceScheduler() orelse
            native_util.impossibleByInvariant("service graph construction follows userspace-scheduler allocation");
        const task_runtime = runtime_context.taskRuntime() orelse
            native_util.impossibleByInvariant("service graph construction follows task-runtime allocation");
        const package_service_instance = self.packageService() orelse
            native_util.impossibleByInvariant("service graph construction follows package-service allocation");
        return .{
            .capability_table = capability_table,
            .runtime = task_runtime,
            .service_directory = &self.service_directory,
            .userspace_catalog = userspace_catalog,
            .userspace_scheduler = userspace_scheduler,
            .package_service = package_service_instance,
            .supervisor = &self.supervisor,
            .driver_directory = &self.driver_directory,
            .driver_runtime = &self.driver_runtime,
            .diagnostic_ledger = &recovery_context.diagnostic_ledger,
            .background_dispatcher = &self.background_dispatcher,
        };
    }

    pub fn bootProduction(
        self: *Builder,
        graph: *ServiceGraph,
        comptime include_verification_evidence: bool,
    ) bool {
        const env_snapshot = graph.env;
        const state_snapshot = graph.state;
        self.service_bindings = ServiceBindings.init();
        if (!session_service_bootstrap.bootServices(
            &env_snapshot,
            &state_snapshot,
            graph.kernel_port,
            &self.service_bindings,
        )) {
            return false;
        }
        if (comptime include_verification_evidence) {
            if (!session_service_bootstrap.connectClient(
                &env_snapshot,
                &state_snapshot,
                graph.kernel_port,
                &self.service_bindings,
            )) {
                return false;
            }
            if (!session_service_bootstrap.proveDriverCrashRestart(
                &env_snapshot,
                &state_snapshot,
                graph.kernel_port,
                &self.service_bindings,
            )) {
                return false;
            }
        }
        graph.env = env_snapshot;
        graph.state = state_snapshot;
        graph.service_bindings = self.service_bindings;
        return true;
    }
};
