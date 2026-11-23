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
const table_backing = @import("../core/table_backing.zig");

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
    package_service_instance: table_backing.Lazy(package_service.Service, package_service.Service.initializeAllocated) = .{},
    driver_directory: driver_service.Directory = driver_service.Directory.init(),
    driver_runtime: driver_runtime_mod.Runtime = driver_runtime_mod.Runtime.init(),
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    background_dispatcher: table_backing.Lazy(background_dispatch.Controller, background_dispatch.Controller.initializeAllocated) = .{},

    comptime {
        if (@sizeOf(@This()) > 22 * 1024) {
            @compileError("heap-backed service graph builders exceed their compact resident layout");
        }
    }

    pub fn init() Builder {
        return .{};
    }

    pub fn packageService(self: *Builder) ?*package_service.Service {
        return self.package_service_instance.get();
    }

    pub fn ensurePackageService(self: *Builder) error{NoSpaceLeft}!*package_service.Service {
        return self.package_service_instance.ensure();
    }

    pub fn releasePackageService(self: *Builder) void {
        if (self.package_service_instance.get()) |service| service.deinit();
        self.package_service_instance.release();
    }

    pub fn backgroundDispatch(self: *Builder) ?*background_dispatch.Controller {
        return self.background_dispatcher.get();
    }

    pub fn ensureBackgroundDispatch(self: *Builder) error{NoSpaceLeft}!*background_dispatch.Controller {
        return self.background_dispatcher.ensure();
    }

    pub fn releaseBackgroundDispatch(self: *Builder) void {
        self.background_dispatcher.release();
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
            .background_dispatcher = self.backgroundDispatch(),
        };
    }

    pub fn bootProduction(
        _: *Builder,
        graph: *ServiceGraph,
        comptime include_verification_evidence: bool,
    ) bool {
        const env_snapshot = graph.env;
        const state_snapshot = graph.state;
        var service_bindings = ServiceBindings.init();
        if (!session_service_bootstrap.bootServices(
            &env_snapshot,
            &state_snapshot,
            graph.kernel_port,
            &service_bindings,
        )) {
            return false;
        }
        if (comptime include_verification_evidence) {
            if (!session_service_bootstrap.connectClient(
                &env_snapshot,
                &state_snapshot,
                graph.kernel_port,
                &service_bindings,
            )) {
                return false;
            }
            if (!session_service_bootstrap.proveDriverCrashRestart(
                &env_snapshot,
                &state_snapshot,
                graph.kernel_port,
                &service_bindings,
            )) {
                return false;
            }
        }
        graph.env = env_snapshot;
        graph.state = state_snapshot;
        graph.service_bindings = service_bindings;
        return true;
    }
};
