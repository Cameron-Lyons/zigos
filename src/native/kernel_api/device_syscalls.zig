const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    syscall_abi.declare(.device_describe, .device, component_port.DeviceDescribeRequest, abi.DeviceDescriptor, dispatchDeviceDescribe, .plain),
    syscall_abi.declare(.device_mmio_window, .device, component_port.DeviceMmioWindowRequest, abi.DeviceMmioWindowDescriptor, dispatchDeviceMmioWindow, .plain),
    syscall_abi.declare(.device_port_read, .device, component_port.DevicePortReadRequest, abi.DevicePortReadResponse, dispatchDevicePortRead, .plain),
    syscall_abi.declare(.device_port_write, .device, component_port.DevicePortWriteRequest, void, dispatchDevicePortWrite, .plain),
};

pub fn dispatchDeviceDescribe(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.DeviceDescribeRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.deviceDescribe(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

pub fn dispatchDeviceMmioWindow(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.DeviceMmioWindowRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = port.deviceMmioWindow(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, descriptor);
}

pub fn dispatchDevicePortRead(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.DevicePortReadRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const value = port.devicePortRead(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.writeResponse(memory, response_addr, response_len, abi.DevicePortReadResponse{
        .value = value,
    });
}

pub fn dispatchDevicePortWrite(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    _ = response_len;
    _ = response_addr;
    const request = dispatch.readRequest(component_port.DevicePortWriteRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    port.devicePortWrite(request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.success();
}
