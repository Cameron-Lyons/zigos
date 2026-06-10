const boot_flow = @import("session_manager_boot_flow.zig");
const demo_boot = @import("../demo/session_demo_boot.zig");
const background_dispatch = @import("../task/background_dispatch.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const driver_runtime = @import("../drivers/driver_runtime.zig");
const driver_service = @import("../drivers/driver_service.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const native_service_registry = @import("../services/service_registry.zig");
const package_service = @import("../services/package_service.zig");
const storage_service = @import("../storage/storage_service.zig");
const supervisor = @import("supervisor.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const native_ux = @import("../platform/native_ux.zig");
const component_port = @import("../kernel_api/component_port.zig");

pub const SessionManager = boot_flow.SessionManager;

var default_manager = SessionManager.init();

pub const testing = struct {
    pub fn resetState() void {
        default_manager.reset();
    }

    pub fn isInitialized() bool {
        return default_manager.isInitialized();
    }

    pub fn countTasks() usize {
        return default_manager.countTasks();
    }

    pub fn countTasksInState(state: task_runtime.TaskState) usize {
        return default_manager.countTasksInState(state);
    }

    pub fn countServices() usize {
        return default_manager.countServices();
    }

    pub fn findTask(label: []const u8) ?*task_runtime.TaskRecord {
        return default_manager.findTask(label);
    }

    pub fn runtimePtr() *task_runtime.Runtime {
        return default_manager.runtimePtr();
    }

    pub fn runtimeServicePtr() *task_runtime_service.Service {
        return default_manager.runtimeServicePtr();
    }

    pub fn userspaceSchedulerPtr() *userspace_scheduler.Scheduler {
        return default_manager.userspaceSchedulerPtr();
    }

    pub fn serviceDirectoryPtr() *native_service_registry.Service {
        return default_manager.serviceDirectoryPtr();
    }

    pub fn driverDirectoryPtr() *driver_service.Directory {
        return default_manager.driverDirectoryPtr();
    }

    pub fn driverRuntimePtr() *driver_runtime.Runtime {
        return default_manager.driverRuntimePtr();
    }

    pub fn supervisorPtr() *supervisor.Supervisor {
        return default_manager.supervisorPtr();
    }

    pub fn storageServicePtr() *storage_service.Service {
        return default_manager.storageServicePtr();
    }

    pub fn packageServicePtr() *package_service.Service {
        return default_manager.packageServicePtr();
    }

    pub fn reviewUxControllerPtr() *native_ux.Controller {
        return default_manager.reviewUxControllerPtr();
    }

    pub fn compositorSessionPtr() *compositor_session.Session {
        return default_manager.compositorSessionPtr();
    }

    pub fn backgroundDispatchPtr() *background_dispatch.Controller {
        return default_manager.backgroundDispatchPtr();
    }

    pub fn updateLedgerPtr() *event_ledger.Ledger {
        return default_manager.updateLedgerPtr();
    }
};

pub fn system() *SessionManager {
    return &default_manager;
}

pub fn boot() void {
    default_manager.boot();
}

pub fn bootScenarioWorld() void {
    demo_boot.bootScenarioWorld(&default_manager);
}

pub fn kernelPort() ?*component_port.KernelPort {
    return default_manager.kernelPort();
}

pub fn runUserspaceScheduler(now_ticks: u64) bool {
    return default_manager.runUserspaceScheduler(now_ticks);
}
