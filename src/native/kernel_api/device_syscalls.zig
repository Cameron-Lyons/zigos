const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");

pub fn dispatchDeviceDescribe(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    const request = dispatch.readRequest(component_port.DeviceDescribeRequest, memory, request_addr) orelse return dispatch.invalidRequest();
    const descriptor = component_port.invokeGenerated(.device_describe, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const descriptor = component_port.invokeGenerated(.device_mmio_window, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    const value = component_port.invokeGenerated(.device_port_read, port, request, now_ticks) catch |err| return dispatch.mapError(err);
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
    component_port.invokeGenerated(.device_port_write, port, request, now_ticks) catch |err| return dispatch.mapError(err);
    return dispatch.success();
}
