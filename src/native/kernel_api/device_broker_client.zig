const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");

pub const Error = component_port.Error || error{
    KernelPortUnavailable,
    StaleGeneration,
    TrapConflict,
    TrapDenied,
    TrapFailed,
    TrapInternal,
    TrapNotFound,
    TrapUnavailable,
};

pub const Client = struct {
    kernel_port: *component_port.KernelPort,
    authority_capability_id: u64,
    task_id: u64,
    now_ticks: u64,
    process_generation: u32,
    next_correlation_id: u64 = 1,

    pub fn init(
        kernel_port: *component_port.KernelPort,
        authority_capability_id: u64,
        task_id: u64,
        now_ticks: u64,
    ) Client {
        return .{
            .kernel_port = kernel_port,
            .authority_capability_id = authority_capability_id,
            .task_id = task_id,
            .now_ticks = now_ticks,
            .process_generation = if (kernel_port.kernel.runtime.find(task_id)) |task| task.process_generation else 0,
        };
    }

    pub fn describe(self: *Client) Error!abi.DeviceDescriptor {
        try self.requireCurrentGeneration();
        return self.kernel_port.deviceDescribe(.{
            .header = component_port.makeHeader(.device_describe, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
        }, self.now_ticks);
    }

    pub fn mmioWindow(self: *Client, window_index: u8) Error!abi.DeviceMmioWindowDescriptor {
        try self.requireCurrentGeneration();
        return self.kernel_port.deviceMmioWindow(.{
            .header = component_port.makeHeader(.device_mmio_window, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
            .window_index = window_index,
        }, self.now_ticks);
    }

    pub fn readPort(self: *Client, port: u16, width: abi.DevicePortWidth) Error!u32 {
        try self.requireCurrentGeneration();
        return self.kernel_port.devicePortRead(.{
            .header = component_port.makeHeader(.device_port_read, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
            .port = port,
            .width = width,
        }, self.now_ticks);
    }

    pub fn writePort(self: *Client, port: u16, width: abi.DevicePortWidth, value: u32) Error!void {
        try self.requireCurrentGeneration();
        return self.kernel_port.devicePortWrite(.{
            .header = component_port.makeHeader(.device_port_write, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
            .port = port,
            .width = width,
            .value = value,
        }, self.now_ticks);
    }

    fn nextCorrelationId(self: *Client) u64 {
        defer self.next_correlation_id += 1;
        return self.next_correlation_id;
    }

    fn requireCurrentGeneration(self: *const Client) Error!void {
        const task = self.kernel_port.kernel.runtime.find(self.task_id) orelse return error.KernelPortUnavailable;
        if (task.process_generation != self.process_generation) return error.StaleGeneration;
    }
};
