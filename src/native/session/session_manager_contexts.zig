const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const driver_runtime_mod = @import("../drivers/driver_runtime.zig");
const endpoint_mod = @import("../kernel_api/endpoint.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const native_ux = @import("../platform/native_ux.zig");
const principal = @import("../core/principal.zig");
const shared_memory_mod = @import("../kernel_api/shared_memory.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service_mod = @import("../task/task_runtime_service.zig");
const userspace_executor = @import("../task/userspace_executor.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");

pub const KernelContext = struct {
    capability_table: capability.CapabilityTable = capability.CapabilityTable.init(),
    endpoint_table: endpoint_mod.Table = endpoint_mod.Table.init(),
    shared_memory_table: shared_memory_mod.Table = shared_memory_mod.Table.init(),
    kernel_instance: native_kernel.Kernel = undefined,
    kernel_port_instance: component_port.KernelPort = undefined,
    kernel_port_ready: bool = false,

    pub fn init() KernelContext {
        return .{};
    }

    pub fn resetPort(self: *KernelContext) void {
        self.kernel_port_ready = false;
    }

    pub fn port(self: *KernelContext) ?*component_port.KernelPort {
        if (!self.kernel_port_ready) return null;
        return &self.kernel_port_instance;
    }

    pub fn prepare(
        self: *KernelContext,
        policy_authority: principal.PrincipalId,
        runtime_service: *task_runtime_service_mod.Service,
        driver_runtime: *driver_runtime_mod.Runtime,
    ) *component_port.KernelPort {
        self.kernel_instance = native_kernel.Kernel.init(
            policy_authority,
            runtime_service.runtimePtr(),
            &self.capability_table,
            &self.endpoint_table,
            &self.shared_memory_table,
        );
        self.kernel_port_instance = component_port.KernelPort.init(&self.kernel_instance);
        driver_runtime.bindKernelPort(&self.kernel_port_instance);
        self.kernel_port_ready = true;
        return &self.kernel_port_instance;
    }
};

pub const RuntimeContext = struct {
    runtime: task_runtime.Runtime = task_runtime.Runtime.init(),
    runtime_checkpoint_store: task_runtime_service_mod.CheckpointStore = .{},
    runtime_service: task_runtime_service_mod.Service = undefined,
    userspace_executor: userspace_executor.Executor = .{},
    userspace_scheduler: userspace_scheduler.Scheduler = undefined,
    userspace_catalog: userspace_loader.Catalog = userspace_loader.Catalog.init(),
    constructed: bool = false,

    pub fn init() RuntimeContext {
        return .{};
    }

    pub fn ensureConstructed(self: *RuntimeContext) void {
        if (self.constructed) return;
        self.runtime_service.initWithStoreInPlace(
            &self.runtime,
            &self.runtime_checkpoint_store,
        );
        self.userspace_scheduler = userspace_scheduler.Scheduler.init(&self.userspace_executor);
        self.constructed = true;
    }

    pub fn resetScheduler(self: *RuntimeContext) void {
        self.userspace_scheduler.reset();
    }

    pub fn countTasks(self: *const RuntimeContext) usize {
        return self.runtime.taskCount();
    }

    pub fn countTasksInState(self: *const RuntimeContext, state: task_runtime.TaskState) usize {
        var count: usize = 0;
        var slot_index: usize = 0;
        while (slot_index < self.runtime.taskSlotCapacity()) : (slot_index += 1) {
            const slot = self.runtime.taskSlotAtConst(slot_index);
            if (slot.in_use and slot.task.state == state) count += 1;
        }
        return count;
    }

    pub fn findTask(self: *RuntimeContext, label: []const u8) ?*task_runtime.TaskRecord {
        var best: ?*task_runtime.TaskRecord = null;
        var slot_index: usize = 0;
        while (slot_index < self.runtime.taskSlotCapacity()) : (slot_index += 1) {
            const slot = self.runtime.taskSlotAt(slot_index);
            if (!slot.in_use or slot.task.execution_component_count == 0) continue;
            if (std.mem.eql(u8, slot.task.executionComponents()[0].labelSlice(), label)) {
                if (best == null or preferTaskLookupMatch(&slot.task, best.?)) {
                    best = &slot.task;
                }
            }
        }
        return best;
    }

    pub fn executeUserspaceProbe(self: *RuntimeContext, task_id: u64) void {
        _ = self.userspace_scheduler.executeTask(task_id, 0);
    }

    pub fn runScheduler(self: *RuntimeContext, now_ticks: u64) bool {
        return self.userspace_scheduler.runNext(now_ticks);
    }
};

fn preferTaskLookupMatch(candidate: *const task_runtime.TaskRecord, current: *const task_runtime.TaskRecord) bool {
    if (candidate.state == .active and current.state != .active) return true;
    if (candidate.state != .active and current.state == .active) return false;
    if (candidate.process_generation != current.process_generation) return candidate.process_generation > current.process_generation;
    return candidate.id > current.id;
}

pub const RecoveryContext = struct {
    review_compositor_session: compositor_session.Session = compositor_session.Session.init(),
    review_ux_controller: native_ux.Controller = native_ux.Controller.init(),
    diagnostic_ledger: event_ledger.Ledger = event_ledger.Ledger.init(),

    pub fn init() RecoveryContext {
        return .{};
    }
};
