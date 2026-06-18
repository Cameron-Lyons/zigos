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
    return dispatch.invokeAndWriteResponse(.device_describe, port, memory, now_ticks, request_addr, response_addr, response_len);
}

pub fn dispatchDeviceMmioWindow(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request_addr: usize,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.device_mmio_window, port, memory, now_ticks, request_addr, response_addr, response_len);
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
    return dispatch.invokeNoResponse(.device_port_write, port, memory, now_ticks, request_addr, response_addr, response_len);
}
