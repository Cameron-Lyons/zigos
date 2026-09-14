const builtin = @import("builtin");
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

pub const HEAP_BACKED_CAPABILITY_TABLE_ON_FREESTANDING = true;
pub const HEAP_BACKED_ENDPOINT_TABLE_ON_FREESTANDING = true;
pub const HEAP_BACKED_USERSPACE_CATALOG_ON_FREESTANDING = true;
pub const HEAP_BACKED_USERSPACE_SCHEDULER_ON_FREESTANDING = true;
pub const HEAP_BACKED_TASK_RUNTIME_ON_FREESTANDING = true;
pub const HEAP_BACKED_REVIEW_UX_CONTROLLER_ON_FREESTANDING = true;
pub const ENDPOINT_TABLE_HANDLE_SIZE_CEILING_BYTES: usize = 8;
pub const REVIEW_UX_CONTROLLER_HANDLE_SIZE_CEILING_BYTES: usize = 8;
const heap_backed_capability_table = builtin.target.os.tag == .freestanding;
const heap_backed_endpoint_table = builtin.target.os.tag == .freestanding;
const heap_backed_userspace_catalog = builtin.target.os.tag == .freestanding;
const heap_backed_userspace_scheduler = builtin.target.os.tag == .freestanding;
const heap_backed_task_runtime = builtin.target.os.tag == .freestanding;
const heap_backed_review_ux_controller = builtin.target.os.tag == .freestanding;
const CapabilityTableBacking = if (heap_backed_capability_table) ?*capability.CapabilityTable else capability.CapabilityTable;
const EndpointTableBacking = if (heap_backed_endpoint_table) ?*endpoint_mod.Table else endpoint_mod.Table;
const UserspaceCatalogBacking = if (heap_backed_userspace_catalog) ?*userspace_loader.Catalog else userspace_loader.Catalog;
const UserspaceSchedulerBacking = if (heap_backed_userspace_scheduler) ?*userspace_scheduler.Scheduler else userspace_scheduler.Scheduler;
const TaskRuntimeBacking = if (heap_backed_task_runtime) ?*task_runtime.Runtime else task_runtime.Runtime;
const ReviewUxControllerBacking = if (heap_backed_review_ux_controller) ?*native_ux.Controller else native_ux.Controller;

pub const KernelContext = struct {
    capability_table: CapabilityTableBacking = if (heap_backed_capability_table) null else capability.CapabilityTable.init(),
    endpoint_table: EndpointTableBacking = if (heap_backed_endpoint_table) null else endpoint_mod.Table.init(),
    shared_memory_table: shared_memory_mod.Table = shared_memory_mod.Table.init(),
    kernel_instance: native_kernel.Kernel = undefined,
    kernel_port_instance: component_port.KernelPort = undefined,
    kernel_port_ready: bool = false,

    comptime {
        if ((heap_backed_capability_table or heap_backed_endpoint_table) and @sizeOf(@This()) > 12 * 1024) {
            @compileError("heap-backed kernel contexts exceed their compact resident layout");
        }
        if (heap_backed_endpoint_table and @sizeOf(EndpointTableBacking) > ENDPOINT_TABLE_HANDLE_SIZE_CEILING_BYTES) {
            @compileError("heap-backed endpoint table exceeds its handle size ceiling");
        }
    }

    pub fn init() KernelContext {
        return .{};
    }

    pub fn resetPort(self: *KernelContext) void {
        self.kernel_port_ready = false;
    }

    pub fn capabilityTable(self: *KernelContext) ?*capability.CapabilityTable {
        if (comptime heap_backed_capability_table) return self.capability_table;
        return &self.capability_table;
    }

    pub fn ensureCapabilityTable(self: *KernelContext) error{NoSpaceLeft}!*capability.CapabilityTable {
        if (self.capabilityTable()) |table| return table;
        if (comptime heap_backed_capability_table) {
            const table = table_backing.alloc(capability.CapabilityTable) orelse return error.NoSpaceLeft;
            table.initializeAllocated();
            self.capability_table = table;
            return table;
        }
        return &self.capability_table;
    }

    pub fn releaseCapabilityTable(self: *KernelContext) void {
        if (comptime heap_backed_capability_table) {
            if (self.capability_table) |table| {
                table_backing.free(capability.CapabilityTable, table);
                self.capability_table = null;
            }
        } else {
            self.capability_table = capability.CapabilityTable.init();
        }
    }

    pub fn endpointTable(self: *KernelContext) ?*endpoint_mod.Table {
        if (comptime heap_backed_endpoint_table) return self.endpoint_table;
        return &self.endpoint_table;
    }

    pub fn ensureEndpointTable(self: *KernelContext) error{NoSpaceLeft}!*endpoint_mod.Table {
        if (self.endpointTable()) |table| return table;
        if (comptime heap_backed_endpoint_table) {
            const table = table_backing.alloc(endpoint_mod.Table) orelse return error.NoSpaceLeft;
            table.initializeAllocated();
            self.endpoint_table = table;
            return table;
        }
        return &self.endpoint_table;
    }

    pub fn releaseEndpointTable(self: *KernelContext) void {
        if (comptime heap_backed_endpoint_table) {
            if (self.endpoint_table) |table| {
                table.deinit();
                table_backing.free(endpoint_mod.Table, table);
                self.endpoint_table = null;
            }
        } else {
            self.endpoint_table.deinit();
            self.endpoint_table = endpoint_mod.Table.init();
        }
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
        self.kernel_instance = native_kernel.Kernel.init(
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

pub const kernel_context_layout = .{
    .freestanding_endpoint_table_size_ceiling_bytes = endpoint_mod.FREESTANDING_TABLE_SIZE_CEILING_BYTES,
    .freestanding_endpoint_table_handle_size_bytes = @sizeOf(?*endpoint_mod.Table),
    .heap_backs_endpoint_table_on_freestanding = HEAP_BACKED_ENDPOINT_TABLE_ON_FREESTANDING,
};

pub const RuntimeContext = struct {
    runtime: TaskRuntimeBacking = if (heap_backed_task_runtime) null else task_runtime.Runtime.init(),
    runtime_checkpoint_store: task_runtime_service_mod.CheckpointStore = .{},
    runtime_service: task_runtime_service_mod.Service = undefined,
    userspace_executor: userspace_executor.Executor = .{},
    userspace_scheduler: UserspaceSchedulerBacking = if (heap_backed_userspace_scheduler) null else undefined,
    userspace_catalog: UserspaceCatalogBacking = if (heap_backed_userspace_catalog) null else userspace_loader.Catalog.init(),
    constructed: bool = false,

    comptime {
        if ((heap_backed_userspace_catalog or heap_backed_userspace_scheduler or heap_backed_task_runtime) and @sizeOf(@This()) > 1024) {
            @compileError("heap-backed runtime contexts exceed their compact resident layout");
        }
    }

    pub fn init() RuntimeContext {
        return .{};
    }

    pub fn ensureConstructed(self: *RuntimeContext) error{NoSpaceLeft}!void {
        if (self.constructed) return;
        const runtime = try self.ensureTaskRuntime();
        if (comptime heap_backed_userspace_scheduler) {
            const scheduler = table_backing.alloc(userspace_scheduler.Scheduler) orelse {
                self.releaseTaskRuntime();
                return error.NoSpaceLeft;
            };
            scheduler.initializeAllocated(&self.userspace_executor);
            self.userspace_scheduler = scheduler;
        } else {
            self.userspace_scheduler = userspace_scheduler.Scheduler.init(&self.userspace_executor);
        }
        self.runtime_service.initWithStoreInPlace(
            runtime,
            &self.runtime_checkpoint_store,
        );
        self.constructed = true;
    }

    pub fn taskRuntime(self: *RuntimeContext) ?*task_runtime.Runtime {
        if (comptime heap_backed_task_runtime) return self.runtime;
        return &self.runtime;
    }

    pub fn taskRuntimeConst(self: *const RuntimeContext) ?*const task_runtime.Runtime {
        if (comptime heap_backed_task_runtime) return self.runtime;
        return &self.runtime;
    }

    fn ensureTaskRuntime(self: *RuntimeContext) error{NoSpaceLeft}!*task_runtime.Runtime {
        if (self.taskRuntime()) |runtime| return runtime;
        if (comptime heap_backed_task_runtime) {
            const runtime = table_backing.alloc(task_runtime.Runtime) orelse return error.NoSpaceLeft;
            runtime.initializeAllocated();
            self.runtime = runtime;
            return runtime;
        }
        return &self.runtime;
    }

    pub fn releaseTaskRuntime(self: *RuntimeContext) void {
        if (comptime heap_backed_task_runtime) {
            if (self.runtime) |runtime| {
                runtime.reset();
                table_backing.free(task_runtime.Runtime, runtime);
                self.runtime = null;
            }
        } else {
            self.runtime.reset();
        }
    }

    pub fn userspaceScheduler(self: *RuntimeContext) ?*userspace_scheduler.Scheduler {
        if (comptime heap_backed_userspace_scheduler) return self.userspace_scheduler;
        return &self.userspace_scheduler;
    }

    pub fn userspaceSchedulerConst(self: *const RuntimeContext) ?*const userspace_scheduler.Scheduler {
        if (comptime heap_backed_userspace_scheduler) return self.userspace_scheduler;
        return &self.userspace_scheduler;
    }

    pub fn releaseUserspaceScheduler(self: *RuntimeContext) void {
        if (!self.constructed) return;
        if (comptime heap_backed_userspace_scheduler) {
            if (self.userspace_scheduler) |scheduler| {
                scheduler.deinit();
                table_backing.free(userspace_scheduler.Scheduler, scheduler);
                self.userspace_scheduler = null;
            }
        } else {
            self.userspace_scheduler.deinit();
        }
        self.constructed = false;
    }

    pub fn userspaceCatalog(self: *RuntimeContext) ?*userspace_loader.Catalog {
        if (comptime heap_backed_userspace_catalog) return self.userspace_catalog;
        return &self.userspace_catalog;
    }

    pub fn ensureUserspaceCatalog(self: *RuntimeContext) error{NoSpaceLeft}!*userspace_loader.Catalog {
        if (self.userspaceCatalog()) |catalog| return catalog;
        if (comptime heap_backed_userspace_catalog) {
            const catalog = table_backing.alloc(userspace_loader.Catalog) orelse return error.NoSpaceLeft;
            catalog.initializeAllocated();
            self.userspace_catalog = catalog;
            return catalog;
        }
        return &self.userspace_catalog;
    }

    pub fn releaseUserspaceCatalog(self: *RuntimeContext) void {
        if (comptime heap_backed_userspace_catalog) {
            if (self.userspace_catalog) |catalog| {
                table_backing.free(userspace_loader.Catalog, catalog);
                self.userspace_catalog = null;
            }
        } else {
            self.userspace_catalog = userspace_loader.Catalog.init();
        }
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

    pub fn runScheduler(self: *RuntimeContext, now_ticks: u64) bool {
        const scheduler = self.userspaceScheduler() orelse return false;
        return scheduler.runNext(now_ticks);
    }

    pub fn schedulerHasReadyTasks(self: *const RuntimeContext) bool {
        const scheduler = self.userspaceSchedulerConst() orelse return false;
        return scheduler.hasReadyTasks();
    }
};

pub const RecoveryContext = struct {
    review_compositor_session: compositor_session.Session = compositor_session.Session.init(),
    review_ux_controller: ReviewUxControllerBacking = if (heap_backed_review_ux_controller) null else native_ux.Controller.init(),
    diagnostic_ledger: event_ledger.Ledger = event_ledger.Ledger.init(),

    comptime {
        if (heap_backed_review_ux_controller and @sizeOf(ReviewUxControllerBacking) > REVIEW_UX_CONTROLLER_HANDLE_SIZE_CEILING_BYTES) {
            @compileError("heap-backed review UX controller exceeds its handle size ceiling");
        }
    }

    pub fn init() RecoveryContext {
        return .{};
    }

    pub fn reviewUxController(self: *RecoveryContext) ?*native_ux.Controller {
        if (comptime heap_backed_review_ux_controller) return self.review_ux_controller;
        return &self.review_ux_controller;
    }

    pub fn ensureReviewUxController(self: *RecoveryContext) error{NoSpaceLeft}!*native_ux.Controller {
        if (self.reviewUxController()) |controller| return controller;
        if (comptime heap_backed_review_ux_controller) {
            const controller = table_backing.alloc(native_ux.Controller) orelse return error.NoSpaceLeft;
            controller.initializeAllocated();
            self.review_ux_controller = controller;
            return controller;
        }
        return &self.review_ux_controller;
    }

    pub fn releaseReviewUxController(self: *RecoveryContext) void {
        if (comptime heap_backed_review_ux_controller) {
            if (self.review_ux_controller) |controller| {
                table_backing.free(native_ux.Controller, controller);
                self.review_ux_controller = null;
            }
        } else {
            self.review_ux_controller = native_ux.Controller.init();
        }
    }
};

pub const recovery_context_layout = .{
    .heap_backs_review_ux_controller_on_freestanding = HEAP_BACKED_REVIEW_UX_CONTROLLER_ON_FREESTANDING,
    .review_ux_controller_size_bytes = native_ux.CONTROLLER_SIZE_CEILING_BYTES,
    .freestanding_review_ux_controller_handle_size_bytes = if (HEAP_BACKED_REVIEW_UX_CONTROLLER_ON_FREESTANDING) @sizeOf(?*native_ux.Controller) else native_ux.CONTROLLER_SIZE_CEILING_BYTES,
};
