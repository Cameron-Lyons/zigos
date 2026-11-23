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
const table_backing = @import("../core/table_backing.zig");

pub const KernelContext = struct {
    capability_table: table_backing.Lazy(capability.CapabilityTable, capability.CapabilityTable.initializeAllocated) = .{},
    endpoint_table: table_backing.Lazy(endpoint_mod.Table, null) = .{},
    shared_memory_table: shared_memory_mod.Table = shared_memory_mod.Table.init(),
    kernel_instance: native_kernel.Kernel = undefined,
    kernel_port_instance: component_port.KernelPort = undefined,
    kernel_port_ready: bool = false,

    comptime {
        if (@sizeOf(@This()) > 12 * 1024) {
            @compileError("heap-backed kernel contexts exceed their compact resident layout");
        }
    }

    pub fn init() KernelContext {
        return .{};
    }

    pub fn resetPort(self: *KernelContext) void {
        if (self.kernel_port_ready) {
            self.kernel_instance.clearEndpointWakeSink();
            self.kernel_instance.deinit();
        }
        self.kernel_port_ready = false;
    }

    pub fn capabilityTable(self: *KernelContext) ?*capability.CapabilityTable {
        return self.capability_table.get();
    }

    pub fn ensureCapabilityTable(self: *KernelContext) error{NoSpaceLeft}!*capability.CapabilityTable {
        return self.capability_table.ensure();
    }

    pub fn releaseCapabilityTable(self: *KernelContext) void {
        self.capability_table.release();
    }

    pub fn endpointTable(self: *KernelContext) ?*endpoint_mod.Table {
        return self.endpoint_table.get();
    }

    pub fn ensureEndpointTable(self: *KernelContext) error{NoSpaceLeft}!*endpoint_mod.Table {
        return self.endpoint_table.ensure();
    }

    pub fn releaseEndpointTable(self: *KernelContext) void {
        if (self.endpoint_table.get()) |table| table.deinit();
        self.endpoint_table.release();
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
        const capability_table = self.capabilityTable() orelse unreachable;
        const endpoint_table = self.endpointTable() orelse unreachable;
        self.kernel_instance.initInPlace(
            policy_authority,
            runtime_service.runtimePtr(),
            capability_table,
            endpoint_table,
            &self.shared_memory_table,
        );
        self.kernel_port_instance = component_port.KernelPort.init(&self.kernel_instance);
        driver_runtime.bindKernelPort(&self.kernel_port_instance);
        self.kernel_port_ready = true;
        return &self.kernel_port_instance;
    }
};

pub const RuntimeContext = struct {
    runtime: table_backing.Lazy(task_runtime.Runtime, task_runtime.Runtime.initializeAllocated) = .{},
    runtime_checkpoint_store: task_runtime_service_mod.CheckpointStore = .{},
    runtime_service: task_runtime_service_mod.Service = undefined,
    userspace_executor: userspace_executor.Executor = .{},
    userspace_scheduler: table_backing.Lazy(userspace_scheduler.Scheduler, null) = .{},
    userspace_catalog: table_backing.Lazy(userspace_loader.Catalog, null) = .{},
    constructed: bool = false,

    comptime {
        if (@sizeOf(@This()) > 1024) {
            @compileError("heap-backed runtime contexts exceed their compact resident layout");
        }
    }

    pub fn init() RuntimeContext {
        return .{};
    }

    pub fn ensureConstructed(self: *RuntimeContext) error{NoSpaceLeft}!void {
        if (self.constructed) return;
        const runtime = try self.runtime.ensure();
        const scheduler = self.userspace_scheduler.ensure() catch |err| {
            self.releaseTaskRuntime();
            return err;
        };
        scheduler.initializeAllocated(&self.userspace_executor);
        self.runtime_service.initWithStoreInPlace(
            runtime,
            &self.runtime_checkpoint_store,
        );
        self.constructed = true;
    }

    pub fn taskRuntime(self: *RuntimeContext) ?*task_runtime.Runtime {
        return self.runtime.get();
    }

    pub fn taskRuntimeConst(self: *const RuntimeContext) ?*const task_runtime.Runtime {
        return self.runtime.get();
    }

    pub fn releaseTaskRuntime(self: *RuntimeContext) void {
        if (self.runtime.get()) |runtime| runtime.reset();
        self.runtime.release();
    }

    pub fn userspaceScheduler(self: *RuntimeContext) ?*userspace_scheduler.Scheduler {
        return self.userspace_scheduler.get();
    }

    pub fn userspaceSchedulerConst(self: *const RuntimeContext) ?*const userspace_scheduler.Scheduler {
        return self.userspace_scheduler.get();
    }

    pub fn releaseUserspaceScheduler(self: *RuntimeContext) void {
        if (!self.constructed) return;
        if (self.userspace_scheduler.get()) |scheduler| scheduler.deinit();
        self.userspace_scheduler.release();
        self.constructed = false;
    }

    pub fn userspaceCatalog(self: *RuntimeContext) ?*userspace_loader.Catalog {
        return self.userspace_catalog.get();
    }

    pub fn ensureUserspaceCatalog(self: *RuntimeContext) error{NoSpaceLeft}!*userspace_loader.Catalog {
        return self.userspace_catalog.ensure();
    }

    pub fn releaseUserspaceCatalog(self: *RuntimeContext) void {
        self.userspace_catalog.release();
    }

    pub fn resetScheduler(self: *RuntimeContext) void {
        const scheduler = self.userspaceScheduler() orelse return;
        scheduler.reset();
    }

    pub fn countTasks(self: *const RuntimeContext) usize {
        const runtime = self.taskRuntimeConst() orelse return 0;
        return runtime.taskCount();
    }

    pub fn countTasksInState(self: *const RuntimeContext, state: task_runtime.TaskState) usize {
        const runtime = self.taskRuntimeConst() orelse return 0;
        return runtime.countTasksInState(state);
    }

    pub fn findTask(self: *RuntimeContext, label: []const u8) ?*task_runtime.TaskRecord {
        const runtime = self.taskRuntime() orelse return null;
        return runtime.findByInitialComponentLabel(label);
    }

    pub fn executeUserspaceProbe(self: *RuntimeContext, task_id: u64) void {
        const scheduler = self.userspaceScheduler() orelse return;
        _ = scheduler.executeTask(task_id, 0);
    }
};

pub const RecoveryContext = struct {
    review_compositor_session: compositor_session.Session = compositor_session.Session.init(),
    review_ux_controller: table_backing.Lazy(native_ux.Controller, native_ux.Controller.initializeAllocated) = .{},
    diagnostic_ledger: event_ledger.Ledger = event_ledger.Ledger.init(),

    pub fn init() RecoveryContext {
        return .{};
    }

    pub fn reviewUxController(self: *RecoveryContext) ?*native_ux.Controller {
        return self.review_ux_controller.get();
    }

    pub fn ensureReviewUxController(self: *RecoveryContext) error{NoSpaceLeft}!*native_ux.Controller {
        return self.review_ux_controller.ensure();
    }

    pub fn releaseReviewUxController(self: *RecoveryContext) void {
        self.review_ux_controller.release();
    }
};
