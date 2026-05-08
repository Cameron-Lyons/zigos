const component_port = @import("../kernel_api/component_port.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const native_service_registry = @import("../services/service_registry.zig");
const package_service = @import("../services/package_service.zig");
const session_contexts = @import("session_manager_contexts.zig");
const session_service_bootstrap = @import("session_service_bootstrap.zig");
const session_support = @import("session_manager_support.zig");
const supervisor_mod = @import("supervisor.zig");
const background_dispatch = @import("../task/background_dispatch.zig");

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
    package_service_instance: package_service.Service = package_service.Service.init(),
    driver_directory: driver_service.Directory = driver_service.Directory.init(),
    driver_runtime: driver_runtime_mod.Runtime = driver_runtime_mod.Runtime.init(),
    supervisor: supervisor_mod.Supervisor = supervisor_mod.Supervisor.init(),
    background_dispatcher: background_dispatch.Controller = background_dispatch.Controller.init(),
    service_bindings: ServiceBindings = ServiceBindings.init(),

    pub fn init() Builder {
        return .{};
    }

    pub fn environment(
        self: *Builder,
        runtime_context: *session_contexts.RuntimeContext,
        kernel_context: *session_contexts.KernelContext,
        recovery_context: *session_contexts.RecoveryContext,
    ) Environment {
        return .{
            .capability_table = &kernel_context.capability_table,
            .runtime = &runtime_context.runtime,
            .service_directory = &self.service_directory,
            .userspace_catalog = &runtime_context.userspace_catalog,
            .userspace_scheduler = &runtime_context.userspace_scheduler,
            .package_service = &self.package_service_instance,
            .supervisor = &self.supervisor,
            .driver_directory = &self.driver_directory,
            .driver_runtime = &self.driver_runtime,
            .diagnostic_ledger = &recovery_context.diagnostic_ledger,
            .background_dispatcher = &self.background_dispatcher,
        };
    }

    pub fn bootProduction(self: *Builder, graph: *ServiceGraph) bool {
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
        graph.env = env_snapshot;
        graph.state = state_snapshot;
        graph.service_bindings = self.service_bindings;
        return session_service_bootstrap.proveDriverCrashRestart(
            &graph.env,
            &graph.state,
            &graph.service_bindings,
        );
    }
};
