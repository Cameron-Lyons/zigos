const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const device_broker = @import("device_broker.zig");

pub const Error = component_port.Error || error{
    BrokerRevoked,
    KernelPortUnavailable,
    StaleBrokerSession,
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
    device_id: u64 = 0,
    broker_generation: u64 = 0,
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
        const descriptor = try self.kernel_port.deviceDescribe(.{
            .header = component_port.makeHeader(.device_describe, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
        }, self.now_ticks);
        self.device_id = descriptor.device_id;
        self.broker_generation = device_broker.brokerGeneration(descriptor.device_id) orelse return error.BrokerRevoked;
        return descriptor;
    }

    pub fn mmioWindow(self: *Client, window_index: u8) Error!abi.DeviceMmioWindowDescriptor {
        try self.requireCurrentGeneration();
        return self.kernel_port.deviceMmioWindow(.{
            .header = component_port.makeHeader(.device_mmio_window, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
            .window_index = window_index,
        }, self.now_ticks);
    }

    fn nextCorrelationId(self: *Client) u64 {
        defer self.next_correlation_id += 1;
        return self.next_correlation_id;
    }

    fn requireCurrentGeneration(self: *const Client) Error!void {
        const task = self.kernel_port.kernel.runtime.find(self.task_id) orelse return error.KernelPortUnavailable;
        if (task.process_generation != self.process_generation) return error.StaleGeneration;
        if (self.device_id != 0) {
            const current_generation = device_broker.brokerGeneration(self.device_id) orelse return error.BrokerRevoked;
            if (current_generation != self.broker_generation) return error.StaleBrokerSession;
        }
    }
};
