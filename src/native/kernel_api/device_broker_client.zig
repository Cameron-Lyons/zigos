const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const native_util = @import("../core/util.zig");

pub const Error = component_port.Error || error{
    KernelPortUnavailable,
    TrapConflict,
    TrapDenied,
    TrapFailed,
    TrapInternal,
    TrapNotFound,
    TrapUnavailable,
};

const freestanding_trap = if (builtin.target.os.tag == .freestanding)
    struct {
        extern fn syscall3_asm(request_addr: usize, response_addr: usize, response_len: usize) callconv(.c) usize;

        fn call(
            request_addr: usize,
            response_addr: usize,
            response_len: usize,
        ) abi.SyscallStatus {
            return @enumFromInt(syscall3_asm(request_addr, response_addr, response_len));
        }
    }
else
    struct {
        fn call(_: usize, _: usize, _: usize) abi.SyscallStatus {
            native_util.impossibleByInvariant("host device broker client cannot issue freestanding syscall traps");
        }
    };

pub const Client = struct {
    kernel_port: *component_port.KernelPort,
    authority_capability_id: u64,
    task_id: u64,
    now_ticks: u64,
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
        };
    }

    pub fn describe(self: *Client) Error!abi.DeviceDescriptor {
        if (builtin.target.os.tag == .freestanding) {
            const request = component_port.DeviceDescribeRequest{
                .header = component_port.makeHeader(.device_describe, self.nextCorrelationId(), self.task_id),
                .device_capability_id = self.authority_capability_id,
            };
            var response = abi.DeviceDescriptor{
                .device_id = 0,
                .base_port = 0,
                .io_port_count = 0,
                .ctrl_port = 0,
                .irq_line = 0,
                .mmio_window_count = 0,
                .flags = 0,
                .sector_count = 0,
            };
            try trapCall(&request, &response);
            return response;
        }
        return self.kernel_port.deviceDescribe(.{
            .header = component_port.makeHeader(.device_describe, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
        }, self.now_ticks);
    }

    pub fn mmioWindow(self: *Client, window_index: u8) Error!abi.DeviceMmioWindowDescriptor {
        if (builtin.target.os.tag == .freestanding) {
            const request = component_port.DeviceMmioWindowRequest{
                .header = component_port.makeHeader(.device_mmio_window, self.nextCorrelationId(), self.task_id),
                .device_capability_id = self.authority_capability_id,
                .window_index = window_index,
            };
            var response = abi.DeviceMmioWindowDescriptor{
                .base = 0,
                .length = 0,
                .flags = 0,
                ._reserved = [_]u8{0} ** 6,
            };
            try trapCall(&request, &response);
            return response;
        }
        return self.kernel_port.deviceMmioWindow(.{
            .header = component_port.makeHeader(.device_mmio_window, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
            .window_index = window_index,
        }, self.now_ticks);
    }

    pub fn readPort(self: *Client, port: u16, width: abi.DevicePortWidth) Error!u32 {
        if (builtin.target.os.tag == .freestanding) {
            const request = component_port.DevicePortReadRequest{
                .header = component_port.makeHeader(.device_port_read, self.nextCorrelationId(), self.task_id),
                .device_capability_id = self.authority_capability_id,
                .port = port,
                .width = width,
            };
            var response = abi.DevicePortReadResponse{ .value = 0 };
            try trapCall(&request, &response);
            return response.value;
        }
        return self.kernel_port.devicePortRead(.{
            .header = component_port.makeHeader(.device_port_read, self.nextCorrelationId(), self.task_id),
            .device_capability_id = self.authority_capability_id,
            .port = port,
            .width = width,
        }, self.now_ticks);
    }

    pub fn writePort(self: *Client, port: u16, width: abi.DevicePortWidth, value: u32) Error!void {
        if (builtin.target.os.tag == .freestanding) {
            const request = component_port.DevicePortWriteRequest{
                .header = component_port.makeHeader(.device_port_write, self.nextCorrelationId(), self.task_id),
                .device_capability_id = self.authority_capability_id,
                .port = port,
                .width = width,
                .value = value,
            };
            return trapCallNoResponse(&request);
        }
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
};

fn trapCall(request: anytype, response: anytype) Error!void {
    const status = freestanding_trap.call(
        @intFromPtr(request),
        @intFromPtr(response),
        @sizeOf(@TypeOf(response.*)),
    );
    try mapTrapStatus(status);
}

fn trapCallNoResponse(request: anytype) Error!void {
    const status = freestanding_trap.call(@intFromPtr(request), 0, 0);
    try mapTrapStatus(status);
}

fn mapTrapStatus(status: abi.SyscallStatus) Error!void {
    switch (status) {
        .success => return,
        .unavailable => return error.TrapUnavailable,
        .denied => return error.TrapDenied,
        .not_found => return error.TrapNotFound,
        .conflict => return error.TrapConflict,
        .internal_error => return error.TrapInternal,
        .invalid_request_pointer,
        .invalid_response_buffer,
        .buffer_too_small,
        .unsupported_operation,
        .unsupported_abi_version,
        => return error.TrapFailed,
    }
}
