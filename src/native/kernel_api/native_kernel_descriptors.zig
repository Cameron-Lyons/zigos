const abi = @import("../core/abi.zig");
const capability = @import("capability.zig");
const device_broker = @import("device_broker.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub fn taskDescriptor(task: *const task_runtime.TaskRecord) abi.TaskDescriptor {
    return .{
        .task_id = task.id,
        .owner_serial = task.owner.serial,
        .owner_kind = @intFromEnum(task.owner.kind),
        .component_class = @intFromEnum(task.component_class),
        .state = @intFromEnum(task.state),
        .flags = taskFlags(task),
        .ui_surface_id = task.ui_surface_id orelse 0,
    };
}

pub fn taskFlags(task: *const task_runtime.TaskRecord) u16 {
    var flags: u16 = 0;
    if (task.local_only) flags |= abi.TASK_FLAG_LOCAL_ONLY;
    if (task.zero_ambient_authority) flags |= abi.TASK_FLAG_ZERO_AMBIENT_AUTHORITY;
    if (task.background_allowed) flags |= abi.TASK_FLAG_BACKGROUND_ALLOWED;
    if (task.runsAsUserspaceProcess()) flags |= abi.TASK_FLAG_USERSPACE_PROCESS;
    if (task.hasLoadedExecutable()) flags |= abi.TASK_FLAG_EXECUTABLE_IMAGE_MAPPED;
    flags |= @as(u16, @intFromEnum(task.resourceClass())) << abi.TASK_RESOURCE_CLASS_SHIFT;
    return flags;
}

pub fn serviceBindingFlags(task: *const task_runtime.TaskRecord) u16 {
    var flags: u16 = 0;
    if (task.runsAsUserspaceProcess()) flags |= abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER;
    if (task.launch.signed) flags |= abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE;
    return flags;
}

pub fn capabilityDescriptor(owned: capability.Capability) abi.CapabilityDescriptor {
    const flags = abi.ScopeFlags{
        .local_only = owned.scope.local_only,
        .broker_only = owned.scope.broker_only,
        .task_scoped = owned.scope.task_id != null,
        .workspace_scoped = owned.scope.workspace_id != null,
        .ephemeral = !owned.lease.renewable,
    };
    return .{
        .capability_id = owned.id,
        .target_id = owned.target.id,
        .rights = @bitCast(owned.rights),
        .revocation_generation = owned.revocation_generation,
        .expires_at_ticks = owned.lease.expires_at_ticks,
        .scope_task_id = owned.scope.task_id orelse 0,
        .scope_workspace_id = owned.scope.workspace_id orelse 0,
        .scope_flags = @bitCast(flags),
    };
}

pub fn deviceDescriptor(descriptor: device_broker.ControllerDescriptor) abi.DeviceDescriptor {
    return .{
        .device_id = descriptor.device_id,
        .base_port = descriptor.base_port,
        .io_port_count = descriptor.io_port_count,
        .ctrl_port = descriptor.ctrl_port,
        .irq_line = descriptor.irq_line,
        .mmio_window_count = descriptor.mmio_window_count,
        .flags = if (descriptor.is_master) abi.DEVICE_DESCRIPTOR_FLAG_ATA_MASTER else 0,
        .sector_count = descriptor.sector_count,
    };
}

pub fn mmioWindowDescriptor(window: device_broker.MmioWindow) abi.DeviceMmioWindowDescriptor {
    var flags: u16 = 0;
    if (window.writable) flags |= abi.MMIO_WINDOW_FLAG_WRITABLE;
    if (window.executable) flags |= abi.MMIO_WINDOW_FLAG_EXECUTABLE;
    return .{
        .base = window.base,
        .length = window.length,
        .flags = flags,
        ._reserved = [_]u8{0} ** 6,
    };
}
