const component_port = @import("component_port.zig");
const dispatch = @import("syscall_dispatch.zig");

pub fn dispatchDeviceDescribe(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.device_describe, port, memory, now_ticks, request, response_addr, response_len);
}

pub fn dispatchDeviceMmioWindow(
    port: *component_port.KernelPort,
    memory: dispatch.UserMemoryContext,
    now_ticks: u64,
    request: []align(8) const u8,
    response_addr: usize,
    response_len: usize,
) dispatch.DispatchResult {
    return dispatch.invokeAndWriteResponse(.device_mmio_window, port, memory, now_ticks, request, response_addr, response_len);
}
